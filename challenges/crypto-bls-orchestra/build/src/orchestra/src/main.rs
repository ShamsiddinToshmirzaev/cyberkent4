// C15 "BLS Orchestra" — orchestra DAO setlist-approval service (Rust).
//
// Vulnerability (two flaws, both required):
//  (a) POST /legacy/import registers a key with NO proof-of-possession, enabling a
//      rogue-key cancellation attack that forges the legacy committee's aggregate.
//  (b) POST /approve tallies each participant's weight from a client-supplied
//      "attendance card" {pubkey, section} (deduped by (section,pubkey)) instead of
//      from the registry (which pins imported keys to provisional/weight 0). The
//      aggregate is reconstructed deduped BY PUBKEY, so multi-role cards don't
//      disturb the pairing — that asymmetry is the bug.
// Rogue-key alone captures only the sub-threshold legacy weight; the card bug alone
// can't produce a valid aggregate. Only together do they cross the threshold.
//
// POST /enroll is the SAFE modern path: it requires a real proof of possession, so
// a rogue (unknown-dlog) key can never be enrolled there.
mod bls;

use bls::*;
use ff::Field;
use group::Curve;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

#[derive(Clone)]
struct Member {
    committee: String,
    section: String,
    weight: u64,
}

struct Server {
    registry: Mutex<HashMap<String, Member>>, // canonical pubkey hex -> Member
    threshold: u64,
    base_weight: HashMap<String, u64>,        // section -> base weight
    sections: Vec<(String, u64)>,
    provisional: String,
    target_title: String,
    app_dst: Vec<u8>,
    pop_dst: Vec<u8>,
    flag: String,
}

fn err(msg: &str) -> (String, String) {
    ("400 Bad Request".into(), json!({"status": "error", "reason": msg}).to_string())
}

impl Server {
    fn info(&self) -> (String, String) {
        let reg = self.registry.lock().unwrap();
        let mut members: Vec<Value> = reg
            .iter()
            .map(|(pk, m)| json!({"pubkey": pk, "committee": m.committee, "section": m.section, "weight": m.weight}))
            .collect();
        members.sort_by(|a, b| a["pubkey"].as_str().cmp(&b["pubkey"].as_str()));
        let sections: Vec<Value> = self
            .sections
            .iter()
            .map(|(n, w)| json!({"name": n, "base_weight": w}))
            .collect();
        let body = json!({
            "id": "C15-bls-orchestra",
            "members": members,
            "threshold": self.threshold,
            "sections": sections,
            "provisional_section": self.provisional,
            "target_title": self.target_title,
            "app_dst": hex_encode(&self.app_dst),
            "pop_dst": hex_encode(&self.pop_dst),
            "app_prefix": String::from_utf8_lossy(APP_PREFIX),
            "note": "Legacy import needs no proof-of-possession; modern enroll does. Weight is tallied from attendance cards."
        });
        ("200 OK".into(), body.to_string())
    }

    fn legacy_import(&self, v: &Value) -> (String, String) {
        let pkh = match v["pubkey"].as_str() {
            Some(s) => s,
            None => return err("missing pubkey"),
        };
        let pk = match decode_g1(pkh) {
            Some(p) => p,
            None => return err("pubkey not a valid, non-identity, subgroup G1 point"),
        };
        let canon = encode_g1(&pk);
        let mut reg = self.registry.lock().unwrap();
        // dedup by pubkey; forced into provisional / weight 0 regardless of any submitted section
        reg.entry(canon.clone()).or_insert(Member {
            committee: "legacy".into(),
            section: self.provisional.clone(),
            weight: 0,
        });
        ("200 OK".into(), json!({"status": "imported", "pubkey": canon,
            "section": self.provisional, "weight": 0, "committee": "legacy"}).to_string())
    }

    fn enroll(&self, v: &Value) -> (String, String) {
        let pk = match v["pubkey"].as_str().and_then(decode_g1) {
            Some(p) => p,
            None => return err("pubkey not a valid, non-identity, subgroup G1 point"),
        };
        let pop = match v["pop"].as_str().and_then(decode_g2) {
            Some(p) => p,
            None => return err("pop not a valid, non-identity, subgroup G2 point"),
        };
        if !verify_pop(&pk, &self.pop_dst, &pop) {
            return ("403 Forbidden".into(),
                json!({"status": "rejected", "reason": "invalid proof of possession"}).to_string());
        }
        let section = v["section"].as_str().unwrap_or("season").to_string();
        let canon = encode_g1(&pk);
        let mut reg = self.registry.lock().unwrap();
        reg.entry(canon.clone()).or_insert(Member {
            committee: "modern".into(),
            section,
            weight: 0, // self-enrolled modern keys carry no governance weight
        });
        ("200 OK".into(), json!({"status": "enrolled", "pubkey": canon,
            "committee": "modern", "weight": 0}).to_string())
    }

    fn approve(&self, v: &Value) -> (String, String) {
        let title = match v["title"].as_str() {
            Some(s) => s,
            None => return err("missing title"),
        };
        let pubkeys = match v["pubkeys"].as_array() {
            Some(a) => a,
            None => return err("missing pubkeys"),
        };
        // reconstruct the aggregate public key over the claimed legacy participants,
        // deduped BY PUBKEY; every participant must be a registered legacy member.
        let mut pts = Vec::new();
        let mut authorized: HashSet<String> = HashSet::new();
        {
            let reg = self.registry.lock().unwrap();
            for pkv in pubkeys {
                let aff = match pkv.as_str().and_then(decode_g1) {
                    Some(p) => p,
                    None => return err("participant not a valid subgroup G1 point"),
                };
                let canon = encode_g1(&aff);
                match reg.get(&canon) {
                    Some(m) if m.committee == "legacy" => {}
                    _ => return err("participant is not a registered legacy member"),
                }
                if authorized.insert(canon) {
                    pts.push(aff);
                }
            }
        }
        if pts.is_empty() {
            return err("no participants");
        }
        let apk = sum_g1(&pts).to_affine();
        if bool::from(group::Group::is_identity(&bls12_381::G1Projective::from(apk))) {
            return err("aggregate public key is the identity");
        }
        let asig = match v["asig"].as_str().and_then(decode_g2) {
            Some(s) => s,
            None => return err("asig not a valid, non-identity, subgroup G2 point"),
        };
        let msg = approval_msg(title);
        if !verify_agg(&apk, &self.app_dst, &msg, &asig) {
            return ("200 OK".into(),
                json!({"status": "invalid_signature"}).to_string());
        }
        // tally weight from attendance cards: weight comes from the CARD's section,
        // deduped by (section, pubkey), counted only for authorized participants.
        let empty = vec![];
        let cards = v["cards"].as_array().unwrap_or(&empty);
        let mut seen: HashSet<String> = HashSet::new();
        let mut total: u64 = 0;
        for c in cards {
            let cpk = match c["pubkey"].as_str().and_then(decode_g1) {
                Some(p) => encode_g1(&p),
                None => continue,
            };
            if !authorized.contains(&cpk) {
                continue;
            }
            let sec = c["section"].as_str().unwrap_or("");
            let key = format!("{}|{}", sec, cpk);
            if seen.insert(key) {
                total += self.base_weight.get(sec).copied().unwrap_or(0);
            }
        }
        if total >= self.threshold && title == self.target_title {
            ("200 OK".into(), json!({"status": "approved", "tally": total,
                "threshold": self.threshold, "credential": "RING_THE_SETLIST",
                "flag": self.flag}).to_string())
        } else {
            ("200 OK".into(), json!({"status": "insufficient", "tally": total,
                "threshold": self.threshold}).to_string())
        }
    }

    fn route(&self, method: &str, path: &str, body: &[u8]) -> (String, String) {
        if method == "GET" && path == "/info" {
            return self.info();
        }
        let v: Value = match serde_json::from_slice(body) {
            Ok(x) => x,
            Err(_) if body.is_empty() => Value::Null,
            Err(_) => return err("invalid JSON body"),
        };
        match (method, path) {
            ("POST", "/legacy/import") => self.legacy_import(&v),
            ("POST", "/enroll") => self.enroll(&v),
            ("POST", "/approve") => self.approve(&v),
            _ => ("404 Not Found".into(), json!({"status": "error", "reason": "no such route"}).to_string()),
        }
    }
}

fn handle(mut stream: TcpStream, srv: Arc<Server>) {
    let peer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(peer);
    let mut request_line = String::new();
    if reader.read_line(&mut request_line).is_err() || request_line.is_empty() {
        return;
    }
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }
    let (method, path) = (parts[0].to_string(), parts[1].to_string());
    let mut content_length = 0usize;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).is_err() {
            return;
        }
        let t = line.trim_end();
        if t.is_empty() {
            break;
        }
        if let Some(v) = t.strip_prefix("Content-Length:").or_else(|| t.strip_prefix("content-length:")) {
            content_length = v.trim().parse().unwrap_or(0);
        }
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 && reader.read_exact(&mut body).is_err() {
        return;
    }
    let (code, resp) = srv.route(&method, &path, &body);
    let out = format!(
        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        code, resp.as_bytes().len(), resp
    );
    let _ = stream.write_all(out.as_bytes());
}

fn build_server(inst: &Value) -> Server {
    let seed = inst["seed"].as_u64().unwrap();
    let threshold = inst["threshold"].as_u64().unwrap();
    let target_title = inst["target_title"].as_str().unwrap().to_string();
    let provisional = inst["provisional_section"].as_str().unwrap().to_string();
    let app_dst = hex_decode(inst["app_dst"].as_str().unwrap()).unwrap();
    let pop_dst = hex_decode(inst["pop_dst"].as_str().unwrap()).unwrap();
    let flag = inst["flag"].as_str().unwrap().to_string();

    let mut sections = Vec::new();
    let mut base_weight = HashMap::new();
    for s in inst["sections"].as_array().unwrap() {
        let name = s["name"].as_str().unwrap().to_string();
        let w = s["base_weight"].as_u64().unwrap();
        sections.push((name.clone(), w));
        base_weight.insert(name, w);
    }
    base_weight.insert(provisional.clone(), 0);

    let mut registry: HashMap<String, Member> = HashMap::new();
    // honest founders: one legacy member per listed founder section; secret discarded.
    for (i, sidx) in inst["founder_sections"].as_array().unwrap().iter().enumerate() {
        let idx = sidx.as_u64().unwrap() as usize;
        let sk = scalar_from_seed(seed, i as u64);
        let pk = pk_of(&sk);
        let (sec, w) = sections[idx].clone();
        registry.insert(encode_g1(&pk), Member { committee: "legacy".into(), section: sec, weight: w });
    }
    Server {
        registry: Mutex::new(registry),
        threshold, base_weight, sections, provisional, target_title, app_dst, pop_dst, flag,
    }
}

fn run_server() {
    let path = std::env::var("INSTANCE").unwrap_or_else(|_| "instance/state/instance.json".into());
    let data = std::fs::read(&path).expect("read instance");
    let inst: Value = serde_json::from_slice(&data).expect("parse instance");
    let host = std::env::var("GATEWAY_BIND")
        .unwrap_or_else(|_| inst["net"]["gateway_host"].as_str().unwrap_or("127.0.0.1").to_string());
    let port = inst["net"]["gateway_port"].as_u64().unwrap_or(9150);
    let srv = Arc::new(build_server(&inst));
    let listener = TcpListener::bind((host.as_str(), port as u16)).expect("bind");
    eprintln!("gateway: listening {}:{} (threshold={}, target={:?})",
        host, port, srv.threshold, srv.target_title);
    for stream in listener.incoming() {
        if let Ok(s) = stream {
            let srv = srv.clone();
            thread::spawn(move || handle(s, srv));
        }
    }
}

// ---- forge subcommand (reference solver helper): compute the rogue key + forged
// aggregate signature. args: --honest h1,h2,... --app-dst <hex> --title <str> ----
fn run_forge() {
    let mut honest = String::new();
    let mut app_dst_hex = String::new();
    let mut title = String::new();
    let a: Vec<String> = std::env::args().collect();
    let mut i = 2;
    while i + 1 < a.len() {
        match a[i].as_str() {
            "--honest" => honest = a[i + 1].clone(),
            "--app-dst" => app_dst_hex = a[i + 1].clone(),
            "--title" => title = a[i + 1].clone(),
            _ => {}
        }
        i += 2;
    }
    let app_dst = hex_decode(&app_dst_hex).expect("app-dst hex");
    let honest_pts: Vec<_> = honest
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|h| decode_g1(h).expect("honest pubkey"))
        .collect();
    let mut seed_bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut seed_bytes).unwrap();
    let mut rng = StdRng::from_seed(seed_bytes);
    let x = bls12_381::Scalar::random(&mut rng);
    let sum = sum_g1(&honest_pts);
    let rogue = (g1_gen() * x - sum).to_affine();
    let msg = approval_msg(&title);
    let asig = (hash_to_g2(&app_dst, &msg) * x).to_affine();
    println!("{}", json!({
        "rogue_pubkey": encode_g1(&rogue),
        "asig": encode_g2(&asig)
    }));
}

fn run_selftest() {
    let mut rng = StdRng::seed_from_u64(1);
    let app = b"C15_APP_XMD:SHA-256_SSWU_RO_TEST_";
    let pop = b"C15_POP_XMD:SHA-256_SSWU_RO_TEST_";
    // aggregate + rogue-key
    let n = 4usize;
    let honest: Vec<_> = (0..n).map(|_| {
        let sk = bls12_381::Scalar::random(&mut rng);
        (sk, pk_of(&sk))
    }).collect();
    let title = "THE ROGUE SYMPHONY";
    let msg = approval_msg(title);
    // honest aggregate over the real message would need their sigs; we only prove rogue-key.
    let x = bls12_381::Scalar::random(&mut rng);
    let sum = sum_g1(&honest.iter().map(|(_, p)| *p).collect::<Vec<_>>());
    let rogue = (g1_gen() * x - sum).to_affine();
    let mut set: Vec<_> = honest.iter().map(|(_, p)| *p).collect();
    set.push(rogue);
    let apk = sum_g1(&set).to_affine();
    let asig = (hash_to_g2(app, &msg) * x).to_affine();
    let ok_rogue = verify_agg(&apk, app, &msg, &asig);
    let ok_neg = verify_agg(&sum_g1(&honest.iter().map(|(_, p)| *p).collect::<Vec<_>>()).to_affine(), app, &msg, &asig);
    // PoP round trip
    let sk = bls12_381::Scalar::random(&mut rng);
    let pk = pk_of(&sk);
    let pop_sig = (hash_to_g2(pop, &pk.to_compressed()) * sk).to_affine();
    let ok_pop = verify_pop(&pk, pop, &pop_sig);
    let ok_pop_neg = verify_pop(&pk, app, &pop_sig); // wrong DST must fail
    println!("rogue-key forgery verifies : {}", ok_rogue);
    println!("forgery fails vs honest apk: {}", !ok_neg);
    println!("PoP verifies               : {}", ok_pop);
    println!("PoP fails under wrong DST  : {}", !ok_pop_neg);
    if ok_rogue && !ok_neg && ok_pop && !ok_pop_neg {
        println!("SELFTEST OK");
    } else {
        println!("SELFTEST FAILED");
        std::process::exit(1);
    }
}

// genpop: emit a fresh {pubkey, pop} for testing the modern (PoP) enroll path.
// args: --pop-dst <hex>
fn run_genpop() {
    let mut pop_dst_hex = String::new();
    let a: Vec<String> = std::env::args().collect();
    let mut i = 2;
    while i + 1 < a.len() {
        if a[i] == "--pop-dst" {
            pop_dst_hex = a[i + 1].clone();
        }
        i += 2;
    }
    let pop_dst = hex_decode(&pop_dst_hex).expect("pop-dst hex");
    let mut seed_bytes = [0u8; 32];
    std::fs::File::open("/dev/urandom").unwrap().read_exact(&mut seed_bytes).unwrap();
    let mut rng = StdRng::from_seed(seed_bytes);
    let sk = bls12_381::Scalar::random(&mut rng);
    let pk = pk_of(&sk);
    let pop = (hash_to_g2(&pop_dst, &pk.to_compressed()) * sk).to_affine();
    println!("{}", json!({"pubkey": encode_g1(&pk), "pop": encode_g2(&pop)}));
}

fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("selftest") => run_selftest(),
        Some("forge") => run_forge(),
        Some("genpop") => run_genpop(),
        _ => run_server(),
    }
}
