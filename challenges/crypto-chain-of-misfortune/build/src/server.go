package main

// NovaFest ticketing service (single binary; internally: signer + two chain
// gateways + a per-chain dedup/anti-doublespend layer + a credit ledger + the
// operator-credential mint). It reads a full instance file (holds the signing
// key) from $INSTANCE.
import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"sync"
)

type ChainCfg struct {
	ChainID int64  `json:"chain_id"`
	Name    string `json:"name"`
}

type Instance struct {
	ID     string `json:"id"`
	Seed   int    `json:"seed"`
	Signer struct {
		D       string `json:"d"`
		X       string `json:"x"`
		Y       string `json:"y"`
		Address string `json:"address"`
	} `json:"signer"`
	Domain struct {
		Name              string `json:"name"`
		Version           string `json:"version"`
		VerifyingContract string `json:"verifying_contract"`
	} `json:"domain"`
	Chains map[string]ChainCfg `json:"chains"`
	Params struct {
		FreeBudget      int `json:"free_budget"`
		MintThreshold   int `json:"mint_threshold"`
		CreditPerTicket int `json:"credit_per_ticket"`
		Port            int `json:"port"`
	} `json:"params"`
	Flag string `json:"flag"`
}

type Ticket struct {
	TicketID int64  `json:"ticket_id"`
	Holder   string `json:"holder"`   // 20-byte hex address chosen by the player
	Action   string `json:"action"`
	Tier     int64  `json:"tier"`
}

type Sig struct {
	R string `json:"r"`
	S string `json:"s"`
}

type server struct {
	inst     *Instance
	priv     *ecdsa.PrivateKey
	pub      *ecdsa.PublicKey
	contract []byte
	mu       sync.Mutex
	nextID   int64
	issued   map[string]int             // holder -> free tickets issued (per-holder budget)
	ledger   map[string]map[string]int  // chain -> holder -> credits
	dedup    map[string]map[string]bool // chain -> sigbytes -> seen
}

func mustHex(s string) []byte { b, _ := hex.DecodeString(s); return b }

func newServer(inst *Instance) *server {
	d, _ := new(big.Int).SetString(inst.Signer.D, 16)
	x, _ := new(big.Int).SetString(inst.Signer.X, 16)
	y, _ := new(big.Int).SetString(inst.Signer.Y, 16)
	s := &server{
		inst: inst, priv: privFromD(d), pub: pubFromXY(x, y),
		contract: mustHex(inst.Domain.VerifyingContract),
		issued:   map[string]int{},
		ledger:   map[string]map[string]int{},
		dedup:    map[string]map[string]bool{},
	}
	for name := range inst.Chains {
		s.ledger[name] = map[string]int{}
		s.dedup[name] = map[string]bool{}
	}
	return s
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// digest for a ticket on a chain. Tickets are the LEGACY type, whose domain
// separator omits chainId => identical across chains => replayable.
func (s *server) ticketDigest(chain string, t *Ticket) ([]byte, bool) {
	cfg, ok := s.inst.Chains[chain]
	if !ok {
		return nil, false
	}
	dom := domainSeparator(s.inst.Domain.Name, s.inst.Domain.Version,
		big.NewInt(cfg.ChainID), s.contract, false /* legacy: no chainId */)
	sh := hashTicket(big.NewInt(t.TicketID), mustHex(t.Holder), t.Action, big.NewInt(t.Tier))
	return digest(dom, sh), true
}

func (s *server) handleInfo(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"id":     s.inst.ID,
		"signer": map[string]string{"x": s.inst.Signer.X, "y": s.inst.Signer.Y, "address": s.inst.Signer.Address},
		"domain": s.inst.Domain,
		"chains": s.inst.Chains,
		"curve":  map[string]string{"name": "P-256", "n": curveN().Text(16)},
		"types":  map[string]string{"legacy_domain": legacyDomainType, "modern_domain": modernDomainType, "ticket": ticketType},
		"params": map[string]int{"free_budget": s.inst.Params.FreeBudget,
			"mint_threshold": s.inst.Params.MintThreshold, "credit_per_ticket": s.inst.Params.CreditPerTicket},
		"note": "Free tickets are issued on TestStage only. Mint requires MainStage loyalty credits.",
	})
}

func (s *server) handleFreeTicket(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Holder string `json:"holder"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	if len(mustHex(req.Holder)) != 20 {
		writeJSON(w, map[string]string{"status": "error", "reason": "holder must be a 20-byte hex address"})
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.issued[req.Holder] >= s.inst.Params.FreeBudget {
		writeJSON(w, map[string]any{"status": "budget_exhausted", "issued": s.issued[req.Holder]})
		return
	}
	s.issued[req.Holder]++
	s.nextID++
	t := &Ticket{TicketID: s.nextID, Holder: req.Holder, Action: "ADMIT", Tier: 1}
	dig, _ := s.ticketDigest("teststage", t)
	r1, s1 := sign(s.priv, dig)
	writeJSON(w, map[string]any{"status": "issued", "chain": "teststage",
		"ticket": t, "signature": Sig{R: r1.Text(16), S: s1.Text(16)}})
}

func (s *server) handleSubmit(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Chain     string  `json:"chain"`
		Ticket    *Ticket `json:"ticket"`
		Signature Sig     `json:"signature"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil || req.Ticket == nil {
		writeJSON(w, map[string]string{"status": "error", "reason": "bad request"})
		return
	}
	dig, ok := s.ticketDigest(req.Chain, req.Ticket)
	if !ok {
		writeJSON(w, map[string]string{"status": "error", "reason": "unknown chain"})
		return
	}
	rr, ok1 := new(big.Int).SetString(req.Signature.R, 16)
	ss, ok2 := new(big.Int).SetString(req.Signature.S, 16)
	if !ok1 || !ok2 || !verify(s.pub, dig, rr, ss) {
		writeJSON(w, map[string]string{"status": "rejected", "reason": "invalid signature"})
		return
	}
	// dedup keys on the raw signature bytes, PER CHAIN.
	key := req.Signature.R + ":" + req.Signature.S
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dedup[req.Chain][key] {
		writeJSON(w, map[string]any{"status": "duplicate", "chain": req.Chain})
		return
	}
	s.dedup[req.Chain][key] = true
	s.ledger[req.Chain][req.Ticket.Holder] += s.inst.Params.CreditPerTicket
	writeJSON(w, map[string]any{"status": "credited", "chain": req.Chain,
		"holder": req.Ticket.Holder, "credits": s.ledger[req.Chain][req.Ticket.Holder]})
}

func (s *server) handleCredits(w http.ResponseWriter, r *http.Request) {
	chain := r.URL.Query().Get("chain")
	holder := r.URL.Query().Get("holder")
	s.mu.Lock()
	defer s.mu.Unlock()
	writeJSON(w, map[string]any{"chain": chain, "holder": holder, "credits": s.ledger[chain][holder]})
}

func (s *server) handleMint(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Holder string `json:"holder"`
	}
	json.NewDecoder(r.Body).Decode(&req)
	s.mu.Lock()
	defer s.mu.Unlock()
	have := s.ledger["mainstage"][req.Holder]
	if have < s.inst.Params.MintThreshold {
		writeJSON(w, map[string]any{"status": "insufficient", "have": have,
			"need": s.inst.Params.MintThreshold, "chain": "mainstage"})
		return
	}
	writeJSON(w, map[string]any{"status": "minted", "credential": "BACKSTAGE_ZERO", "flag": s.inst.Flag})
}

func serve() {
	inst := loadInstance()
	s := newServer(inst)
	mux := http.NewServeMux()
	mux.HandleFunc("/info", s.handleInfo)
	mux.HandleFunc("/freeticket", s.handleFreeTicket)
	mux.HandleFunc("/submit", s.handleSubmit)
	mux.HandleFunc("/credits", s.handleCredits)
	mux.HandleFunc("/mint", s.handleMint)
	bind := os.Getenv("GATEWAY_BIND")
	if bind == "" {
		bind = "127.0.0.1"
	}
	addr := fmt.Sprintf("%s:%d", bind, inst.Params.Port)
	fmt.Printf("gateway: listening %s (chains: mainstage=%d teststage=%d, threshold=%d, budget=%d)\n",
		addr, inst.Chains["mainstage"].ChainID, inst.Chains["teststage"].ChainID,
		inst.Params.MintThreshold, inst.Params.FreeBudget)
	if err := http.ListenAndServe(addr, mux); err != nil {
		panic(err)
	}
}

func loadInstance() *Instance {
	path := os.Getenv("INSTANCE")
	if path == "" {
		path = "instance/state/instance.json"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	inst := new(Instance)
	if err := json.Unmarshal(b, inst); err != nil {
		panic(err)
	}
	return inst
}
