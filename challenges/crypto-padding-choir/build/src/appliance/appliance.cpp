// C02 "Padding Choir" — RSA unwrap appliance (the crypto worker).
//
// Internal service, bound to localhost, spoken to ONLY by the gateway. It:
//   1. raw-RSA-decrypts an imported session ciphertext (blinded, constant-time-ish);
//   2. checks PKCS#1 v1.5 type-2 structure;
//   3. on a conforming block ONLY, performs heavy canonicalisation work + a
//      lenient (first-wins) DER import.
//
// The extra work in step 3 is the sole secret-dependent timing difference; it is
// the classic Bleichenbacher oracle (`m` starts with 00 02), surfaced as latency
// rather than as a distinct error. All non-import outcomes look identical to the
// player (the gateway maps every one to "403 AUTH FAILED").
//
// Config comes from the environment (the gateway/launcher sets it):
//   APPLIANCE_KEY      path to the RSA private key PEM
//   APPLIANCE_PORT     TCP port to listen on (127.0.0.1)
//   DER_WORK_FACTOR    canonicalisation repetitions (tunes the timing gap)
//   WORKER_COUNT       size of the bounded worker pool (models queue capacity)
//   ISSUER_TAG         hex of the per-instance genuineness secret
//   ALLOWLIST          comma-separated importable roles, e.g. "guest,subscriber"
//
// Wire (gateway<->appliance): request  = [u32 len][ciphertext]
//                             response = [u8 code][u32 plen][payload]
//   code 0 = non-conforming padding (fast path)
//   code 2 = conforming padding, but import rejected (DER/issuer/role) — slow path
//   code 3 = imported OK (role in allowlist, issuer matches); payload returned
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "der.hpp"

static EVP_PKEY* g_pkey = nullptr;
static int g_k = 0;
static int g_work = 1000;
static std::vector<uint8_t> g_issuer;
static std::vector<std::string> g_allow;

// Counting semaphore: bounds the number of *concurrent crypto operations* to
// WORKER_COUNT. Connections are always read promptly (thread-per-connection), so
// nothing starves, but under load requests queue for a processing slot — that is
// the bounded-capacity contention the timing model wants (C++17, no <semaphore>).
class Sem {
    std::mutex m;
    std::condition_variable cv;
    int count;
public:
    explicit Sem(int c) : count(c) {}
    void acquire() { std::unique_lock<std::mutex> lk(m); cv.wait(lk, [&] { return count > 0; }); --count; }
    void release() { std::lock_guard<std::mutex> lk(m); ++count; cv.notify_one(); }
};
static Sem* g_sem = nullptr;

static bool readn(int fd, uint8_t* b, size_t n) {
    size_t g = 0;
    while (g < n) { ssize_t r = read(fd, b + g, n - g); if (r <= 0) return false; g += (size_t)r; }
    return true;
}
static bool writen(int fd, const uint8_t* b, size_t n) {
    size_t p = 0;
    while (p < n) { ssize_t r = write(fd, b + p, n - p); if (r <= 0) return false; p += (size_t)r; }
    return true;
}

static bool rsa_raw_decrypt(const uint8_t* in, size_t inlen, uint8_t* em /* g_k */) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(g_pkey, nullptr);
    if (!ctx) return false;
    bool ok = false;
    std::vector<uint8_t> tmp(g_k);
    size_t outlen = g_k;
    if (EVP_PKEY_decrypt_init(ctx) > 0 &&
        EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) > 0 &&
        EVP_PKEY_decrypt(ctx, tmp.data(), &outlen, in, inlen) > 0 &&
        (int)outlen <= g_k) {
        memset(em, 0, g_k);
        memcpy(em + (g_k - outlen), tmp.data(), outlen);   // left-pad to modulus size
        ok = true;
    }
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static uint8_t process(const uint8_t* ct, size_t ctlen, std::vector<uint8_t>& payload) {
    if ((int)ctlen != g_k) return 0;
    std::vector<uint8_t> em(g_k);
    if (!rsa_raw_decrypt(ct, ctlen, em.data())) return 0;

    // Bleichenbacher oracle condition — the only secret-dependent branch.
    if (em[0] != 0x00 || em[1] != 0x02) return 0;               // FAST PATH

    // SLOW PATH: genuine work for every conforming block.
    volatile uint64_t sink = der::canonicalize_work(em.data() + 2, g_k - 2, g_work);
    (void)sink;

    int sep = -1;
    for (int i = 2; i < g_k; i++) { if (em[i] == 0x00) { sep = i; break; } }
    if (sep < 10) return 2;                                     // need >= 8 pad bytes
    const uint8_t* m = em.data() + sep + 1;
    size_t mlen = (size_t)(g_k - sep - 1);

    der::Session s;
    if (!der::unwrap_first_wins(m, mlen, s)) return 2;
    if (!s.have_issuer || s.issuer.size() != g_issuer.size() ||
        memcmp(s.issuer.data(), g_issuer.data(), g_issuer.size()) != 0) return 2;
    bool allowed = false;
    for (auto& r : g_allow) if (r == s.role) allowed = true;
    if (!allowed) return 2;                                     // e.g. lone "archivist"

    payload.assign(m, m + mlen);                               // forward to policy
    return 3;
}

static void handle_conn(int fd) {
    for (;;) {
        uint8_t lb[4];
        if (!readn(fd, lb, 4)) break;
        uint32_t len = (uint32_t(lb[0]) << 24) | (lb[1] << 16) | (lb[2] << 8) | lb[3];
        if (len == 0 || len > 65536) break;
        std::vector<uint8_t> ct(len);
        if (!readn(fd, ct.data(), len)) break;
        std::vector<uint8_t> payload;
        g_sem->acquire();                       // bounded crypto concurrency
        uint8_t code = process(ct.data(), len, payload);
        g_sem->release();
        uint32_t pl = (uint32_t)payload.size();
        std::vector<uint8_t> resp;
        resp.reserve(5 + pl);
        resp.push_back(code);
        resp.push_back(pl >> 24); resp.push_back(pl >> 16);
        resp.push_back(pl >> 8);  resp.push_back(pl);
        resp.insert(resp.end(), payload.begin(), payload.end());
        if (!writen(fd, resp.data(), resp.size())) break;
    }
    close(fd);
}

static std::vector<uint8_t> from_hex(const std::string& h) {
    std::vector<uint8_t> o;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        o.push_back((uint8_t)strtol(h.substr(i, 2).c_str(), nullptr, 16));
    return o;
}

int main() {
    const char* key = getenv("APPLIANCE_KEY");
    const char* port_s = getenv("APPLIANCE_PORT");
    const char* work_s = getenv("DER_WORK_FACTOR");
    const char* nw_s = getenv("WORKER_COUNT");
    const char* issuer_s = getenv("ISSUER_TAG");
    const char* allow_s = getenv("ALLOWLIST");
    if (!key || !port_s || !issuer_s || !allow_s) {
        fprintf(stderr, "appliance: missing env (APPLIANCE_KEY/PORT/ISSUER_TAG/ALLOWLIST)\n");
        return 2;
    }
    int port = atoi(port_s);
    g_work = work_s ? atoi(work_s) : 1000;
    int nworkers = nw_s ? atoi(nw_s) : 4;
    g_issuer = from_hex(issuer_s);
    { std::string a(allow_s), cur; for (char c : a) { if (c == ',') { g_allow.push_back(cur); cur.clear(); } else cur += c; } if (!cur.empty()) g_allow.push_back(cur); }

    FILE* fp = fopen(key, "r");
    if (!fp) { perror("open key"); return 2; }
    g_pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    if (!g_pkey) { fprintf(stderr, "appliance: bad key\n"); return 2; }
    g_k = EVP_PKEY_get_size(g_pkey);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    const char* bind_addr = getenv("APPLIANCE_BIND");
    if (!bind_addr) bind_addr = "127.0.0.1";      // localhost by default; 0.0.0.0 in Docker
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, bind_addr, &addr.sin_addr);
    if (bind(srv, (sockaddr*)&addr, sizeof addr) < 0) { perror("bind"); return 2; }
    if (listen(srv, 128) < 0) { perror("listen"); return 2; }

    static Sem sem(nworkers);
    g_sem = &sem;

    fprintf(stderr, "appliance: listening 127.0.0.1:%d k=%d workers=%d work=%d\n",
            port, g_k, nworkers, g_work);
    for (;;) {
        int fd = accept(srv, nullptr, nullptr);
        if (fd < 0) continue;
        int one2 = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one2, sizeof one2);
        std::thread(handle_conn, fd).detach();
    }
}
