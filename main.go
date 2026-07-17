package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
	"git.sr.ht/~rockorager/go-jmap/mail/email"
	"git.sr.ht/~rockorager/go-jmap/mail/emailsubmission"
	"git.sr.ht/~rockorager/go-jmap/mail/mailbox"
	jmapserver "github.com/yno9/go-jmapserver"
)

// ── config ──────────────────────────────────────────────────────────────────────

type AccountConfig struct {
	Alias []string `json:"alias"`
}

type DomainConfig struct {
	Accounts map[string]AccountConfig `json:"account"`
	// allow_provision: open self-service. provision_secret: gated creation
	// (privileged apex; needs the shared secret, not creatable from the UI).
	AllowProvision  bool   `json:"allow_provision"`
	ProvisionSecret string `json:"provision_secret,omitempty"`
}

type Config struct {
	jmapserver.Config
	Hostname   string                  `json:"hostname"`
	Domains    map[string]DomainConfig `json:"domain"`
	RelayLabel string                  `json:"relay_label"`
	RelayColor string                  `json:"relay_color"`
	// WebRoot, when set, serves biset's single-file HTML app to browsers (content-
	// negotiated against the AP actor doc). Empty = no static serving (pure relay).
	// Relative paths resolve against the binary's directory.
	WebRoot string `json:"web_root"`
	// AppHost, when set, splits browser serving by host: the app is served only on
	// this subdomain (e.g. app.non.md), while the apex serves per-user profile
	// pages at /<localpart> and redirects its root there. Empty = serve the app on
	// every host (no split).
	AppHost string `json:"app_host"`
	// InactivePurgeDays removes accounts on allow_provision domains that have
	// had no activity for this many days. 0 = disabled.
	InactivePurgeDays int `json:"inactive_purge_days"`
	// PeerDataDirs lists sibling relay data directories to check for activity
	// before purging. An account is only purged if all peers are also inactive.
	PeerDataDirs []string `json:"peer_data_dirs"`
	// AnchorURL points at the standalone identity anchor (biset-anchor) that
	// jmapap defers every DID question to: proving a DID belongs to whoever
	// claims it, the cross-relay name registry, the DNS record, and the
	// Pkarr/DHT gateway /pkarr forwards to. jmapap holds no anchor storage, no
	// Cloudflare credential and no DID crypto of its own — it stopped being the
	// anchor at c25743f and stopped judging DIDs entirely a while after.
	//
	// **This is the whole opt-in.** Set = this relay serves DID identities.
	// Empty = anchorless, and anchorless means no DIDs at all, not DIDs without
	// coordination (ANCHOR.md decision 2). It is a stricter mode, not a laxer
	// one: an account with a DID is REFUSED (400), because the proof is checked
	// by the anchor and there is nobody to check it — and there is nowhere left
	// here to record one. Plain JMAP accounts are unaffected and behave
	// identically either way; /pkarr is not mounted at all.
	AnchorURL string `json:"anchor_url"`
	// AnchorToken is the shared secret the anchor knows as relay_token. It is
	// REQUIRED whenever anchor_url is set: the anchor is on the public internet
	// (its DIDComm mediator has to be), so without it anyone who can reach the
	// anchor can claim a name nobody holds, or release the claim of somebody who
	// does and take it. Startup refuses rather than run unauthenticated.
	AnchorToken string `json:"anchor_token"`
}

// anchorRef bundles where this relay's anchor is with the secret that proves it
// may write there — the two always travel together and both come from config.
func anchorRef() jmapserver.AnchorRef {
	return jmapserver.AnchorRef{URL: cfg.AnchorURL, Token: cfg.AnchorToken}
}

// requireAnchorToken refuses to start an anchored relay that cannot authenticate
// itself. There is deliberately no "just warn and carry on": an anchor whose
// writes are unauthenticated lets anyone on the internet claim a name nobody
// holds, or release somebody else's claim and take it, DNS record and all. A
// silent fallback here would be exactly the *quiet* security degradation
// src/did/freshness.ts refuses for the same reason — it also has no default and
// throws instead.
func requireAnchorToken() {
	if cfg.AnchorURL != "" && cfg.AnchorToken == "" {
		log.Fatalf("config: anchor_url is set but anchor_token is empty — the anchor's writes would be unauthenticated (set it to the anchor's relay_token)")
	}
}

var cfg Config

// version is overridable at build time: -ldflags "-X main.version=$(git rev-parse --short HEAD)".
var version = "dev"

// ── id / mailbox helpers ─────────────────────────────────────────────────────────

func makeMailboxID(addr string) string {
	return "mbx-" + strings.ReplaceAll(addr, "/", "~")
}

func feedsMailboxID(primary string) string { return makeMailboxID(primary + "/feeds") }

func makeMessageID(messageID, addr string, ts time.Time) string {
	if messageID != "" {
		return "msg-" + strings.ReplaceAll(messageID, "/", "_")
	}
	return fmt.Sprintf("msg-%s-%d", strings.ReplaceAll(addr, "/", "-"), ts.UnixMilli())
}

func newID() jmap.ID {
	b := make([]byte, 8)
	rand.Read(b) //nolint:errcheck
	return jmap.ID(fmt.Sprintf("ap-%d-%s", time.Now().UnixMilli(), hex.EncodeToString(b)))
}

func tokenFile(dataDir, domain, localpart string) string {
	return filepath.Join(dataDir, domain, localpart, "setup.token")
}

func defaultInbox(addr string) mailbox.Mailbox {
	return mailbox.Mailbox{
		ID:   jmap.ID(makeMailboxID(addr)),
		Name: addr,
		Role: mailbox.RoleInbox,
		Rights: &mailbox.Rights{
			MayReadItems:   true,
			MayAddItems:    true,
			MayRemoveItems: true,
			MaySetSeen:     true,
			MaySetKeywords: true,
			MaySubmit:      true,
		},
		IsSubscribed: true,
	}
}

func feedsMailbox(addr string) mailbox.Mailbox {
	return mailbox.Mailbox{
		ID:           jmap.ID(feedsMailboxID(addr)),
		Name:         "feeds",
		Rights:       &mailbox.Rights{MayReadItems: true, MayAddItems: true, MayRemoveItems: true, MaySetSeen: true, MaySetKeywords: true},
		IsSubscribed: true,
	}
}

func firstTo(msg email.Email) string {
	if len(msg.To) > 0 && msg.To[0] != nil {
		return msg.To[0].Email
	}
	return ""
}

// ── handler ──────────────────────────────────────────────────────────────────────

type handler struct {
	mu      sync.RWMutex
	stores  map[string]*jmapserver.Store // primary email → store
	aliases map[string]string            // alias → primary
	apKeys  map[string]*rsa.PrivateKey   // primary email → actor signing key
	hub     *jmapserver.Hub
	dyn     map[string]bool
	dataDir string
}

func (h *handler) Capabilities() []jmap.URI {
	return []jmap.URI{
		"urn:ietf:params:jmap:mail",
		"urn:ietf:params:jmap:submission",
	}
}

func (h *handler) Accounts() []jmapserver.Account {
	h.mu.RLock()
	defer h.mu.RUnlock()
	var out []jmapserver.Account
	for primary := range h.stores {
		out = append(out, jmapserver.Account{ID: jmap.ID(primary), Name: primary})
	}
	return out
}

func (h *handler) hasAccount(primary string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.stores[strings.ToLower(primary)]
	return ok
}

func (h *handler) storeForPrimary(primary string) *jmapserver.Store {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.stores[strings.ToLower(primary)]
}

func (h *handler) storeFor(args json.RawMessage) (*jmapserver.Store, jmap.ID, error) {
	var base struct {
		AccountID jmap.ID `json:"accountId"`
	}
	if err := json.Unmarshal(args, &base); err != nil {
		return nil, "", err
	}
	h.mu.RLock()
	store, ok := h.stores[string(base.AccountID)]
	h.mu.RUnlock()
	if !ok {
		return nil, "", fmt.Errorf("accountNotFound: %s", base.AccountID)
	}
	return store, base.AccountID, nil
}

func (h *handler) Handle(method string, args json.RawMessage) (any, error) {
	store, accountID, err := h.storeFor(args)
	if err != nil {
		return nil, err
	}
	return store.Dispatch(accountID, method, args)
}

// apKey loads (or generates+persists) the per-account ActivityPub HTTP-signature
// RSA key. This key is independent of the account's PGP/MLS material.
func (h *handler) apKey(domain, localpart string) *rsa.PrivateKey {
	primary := strings.ToLower(localpart + "@" + domain)
	h.mu.RLock()
	k := h.apKeys[primary]
	h.mu.RUnlock()
	if k != nil {
		return k
	}
	k = loadOrGenAPKey(h.dataDir, domain, localpart)
	h.mu.Lock()
	h.apKeys[primary] = k
	h.mu.Unlock()
	return k
}

func loadOrGenAPKey(dataDir, domain, localpart string) *rsa.PrivateKey {
	path := filepath.Join(dataDir, domain, localpart, "ap-key.pem")
	if b, err := os.ReadFile(path); err == nil {
		if block, _ := pem.Decode(b); block != nil {
			if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				if rk, ok := k.(*rsa.PrivateKey); ok {
					return rk
				}
			}
		}
	}
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("[ap] keygen %s@%s: %v", localpart, domain, err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err == nil {
		_ = os.MkdirAll(filepath.Dir(path), 0700)
		_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600)
	}
	log.Printf("[ap] generated actor key for %s@%s", localpart, domain)
	return k
}

// makeStore creates and wires a JMAP store for one account.
func (h *handler) makeStore(localpart, domain string) (*jmapserver.Store, error) {
	primary := strings.ToLower(localpart + "@" + domain)
	store, err := jmapserver.NewStore(filepath.Join(h.dataDir, domain, localpart))
	if err != nil {
		return nil, err
	}
	store.PutMailboxes([]mailbox.Mailbox{defaultInbox(primary), feedsMailbox(primary)}) //nolint:errcheck

	// Create: a message dropped into the feeds mailbox is a follow request;
	// everything else is a normal draft awaiting submission.
	store.OnCreateEmail(func(raw json.RawMessage) (email.Email, error) {
		var msg email.Email
		if err := json.Unmarshal(raw, &msg); err != nil {
			return email.Email{}, err
		}
		if msg.ID == "" {
			msg.ID = newID()
		}
		now := time.Now().UTC()
		msg.ReceivedAt = &now

		if msg.MailboxIDs[jmap.ID(feedsMailboxID(primary))] {
			target := firstTo(msg)
			if target == "" {
				return email.Email{}, fmt.Errorf("missing to address for follow")
			}
			if _, err := sendFollow(h, domain, localpart, target); err != nil {
				return email.Email{}, err
			}
			if msg.Keywords == nil {
				msg.Keywords = map[string]bool{}
			}
			msg.Keywords["$follow_pending"] = true
			if len(msg.MessageID) == 0 {
				msg.MessageID = []string{string(msg.ID)}
			}
			if ra, err := resolveActor(target); err == nil {
				followedActors.Store(followKey(primary, ra.actorURL), followEntry{handle: target, followMsgID: msg.ID})
			}
			return msg, nil
		}
		store.PutPending(msg)
		return msg, nil
	})

	// Submit: deliver the draft to the recipient actor as a Create(Note).
	store.OnSubmitEmail(func(msg email.Email, env emailsubmission.Envelope) error {
		target := ""
		if len(env.RcptTo) > 0 && env.RcptTo[0] != nil {
			target = env.RcptTo[0].Email
		} else {
			target = firstTo(msg)
		}
		if target == "" {
			return fmt.Errorf("no recipient")
		}
		noteID, err := sendToActor(h, domain, localpart, msg, target)
		if err != nil {
			return err
		}
		if msg.Keywords == nil {
			msg.Keywords = map[string]bool{}
		}
		msg.Keywords["$seen"] = true
		msg.MessageID = []string{noteID}
		if err := store.Put(msg); err != nil {
			return err
		}
		h.hub.Notify()
		return nil
	})

	// Destroy: deleting a follow record unfollows the actor.
	store.OnDestroyEmail(func(id jmap.ID) error {
		msg, ok := store.Get(id)
		if !ok {
			return nil
		}
		if msg.MailboxIDs[jmap.ID(feedsMailboxID(primary))] {
			if target := firstTo(msg); target != "" {
				if err := sendUnfollow(h, domain, localpart, msg.ID, target); err != nil {
					log.Printf("[ap] unfollow %s: %v", target, err)
				}
			}
		}
		return nil
	})

	return store, nil
}

// addDynAccount registers a dynamically provisioned account at runtime.
func (h *handler) addDynAccount(localpart, domain, dataDir string) {
	primary := strings.ToLower(localpart + "@" + domain)
	store, err := h.makeStore(localpart, domain)
	if err != nil {
		log.Printf("[provision] store error for %s: %v", primary, err)
		return
	}
	h.mu.Lock()
	h.stores[primary] = store
	h.aliases[primary] = primary
	h.dyn[primary] = true
	h.mu.Unlock()
	h.apKey(domain, localpart) // eager-generate the actor key
	log.Printf("[provision] registered account %s", primary)
}

// scanDynAccounts recovers dynamically provisioned accounts from disk on
// restart. Existence is an auth_token_hash credential, not an envelope —
// envelope-less third-party/DID-only accounts are a legitimate, common case
// (see DID.md third-party portability) and must survive a restart exactly
// like any other account.
func scanDynAccounts(h *handler) {
	for domain, dc := range cfg.Domains {
		entries, err := os.ReadDir(filepath.Join(h.dataDir, domain))
		if err != nil {
			continue
		}
		static := map[string]bool{}
		for lp := range dc.Accounts {
			static[lp] = true
		}
		for _, e := range entries {
			if !e.IsDir() || static[e.Name()] {
				continue
			}
			if readAuthHash(h.dataDir, domain, e.Name()) != "" {
				h.addDynAccount(e.Name(), domain, h.dataDir)
			}
		}
	}
}

// ── main ──────────────────────────────────────────────────────────────────────────

func main() {
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		log.Fatalf("dir: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "config.json"))
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Fatalf("config: %v", err)
	}
	if len(cfg.Domains) == 0 {
		log.Fatalf("config: no domains defined")
	}
	requireAnchorToken()
	if cfg.WebRoot != "" && !filepath.IsAbs(cfg.WebRoot) {
		cfg.WebRoot = filepath.Join(dir, cfg.WebRoot)
	}

	dataDir := filepath.Join(dir, "data")
	h := &handler{
		stores:  map[string]*jmapserver.Store{},
		aliases: map[string]string{},
		apKeys:  map[string]*rsa.PrivateKey{},
		hub:     jmapserver.NewHub(),
		dyn:     map[string]bool{},
		dataDir: dataDir,
	}
	h.hub.SetPersistDir(dataDir)

	cfg.AuthFunc = func(username, password string) (jmap.ID, bool) {
		parts := strings.SplitN(strings.ToLower(username), "@", 2)
		if len(parts) != 2 {
			return "", false
		}
		localpart, domain := parts[0], parts[1]
		if !h.hasAccount(username) {
			if _, ok := cfg.Domains[domain]; !ok {
				return "", false
			}
			if _, ok := cfg.Domains[domain].Accounts[localpart]; !ok {
				return "", false
			}
		}
		hash := readAuthHash(dataDir, domain, localpart)
		if hash == "" {
			return "", false
		}
		tok, err := decodeAuthToken(password)
		if err != nil || !jmapserver.VerifyAuthToken(tok, hash) {
			return "", false
		}
		return jmap.ID(strings.ToLower(username)), true
	}

	// Static accounts from config.
	for domain, dc := range cfg.Domains {
		for localpart, acc := range dc.Accounts {
			primary := strings.ToLower(localpart) + "@" + domain
			h.aliases[primary] = primary
			for _, a := range acc.Alias {
				alias := strings.ToLower(a)
				if !strings.Contains(alias, "@") {
					alias += "@" + domain
				}
				h.aliases[alias] = primary
			}
			store, err := h.makeStore(localpart, domain)
			if err != nil {
				log.Fatalf("store %s: %v", primary, err)
			}
			h.stores[primary] = store
			h.apKey(domain, localpart)
		}
	}

	// Recover dynamic accounts and restore follow state.
	scanDynAccounts(h)
	for primary, store := range h.stores {
		fmbx := jmap.ID(feedsMailboxID(primary))
		for _, msg := range store.All() {
			if !msg.MailboxIDs[fmbx] || !msg.Keywords["$follow_accepted"] {
				continue
			}
			if len(msg.To) > 0 && msg.To[0] != nil {
				if ra, err := resolveActor(msg.To[0].Email); err == nil {
					followedActors.Store(followKey(primary, ra.actorURL), followEntry{handle: msg.To[0].Email, followMsgID: msg.ID})
				}
			}
		}
	}

	mux := jmapserver.NewMux(cfg.Config, h, h.hub)
	registerAuthEnv(mux, dataDir)
	registerProvision(mux, h, dataDir)
	registerAPRoutes(mux, h)
	registerDidUpdate(mux, h, dataDir)
	// GET /identity/local/<did> is gone: the anchor's by-did answers the same
	// question across every relay, not just this one (ANCHOR.md decision 1).
	jmapserver.RegisterContactsEndpoints(mux, dataDir, authenticate)
	// Pkarr/did:dht gateway: this relay no longer runs a DHT node, it forwards
	// to the anchor's (ANCHOR.md decision 1). The route stays because clients
	// derive their gateway URL from their own relay and publish only there.
	jmapserver.RegisterPkarrProxy(mux, anchorRef())
	registerAccountDelete(mux, h, dataDir)
	jmapserver.RegisterStorageEndpoints(mux, dataDir, authenticate, func(email string) int {
		h.mu.RLock()
		st := h.stores[email]
		h.mu.RUnlock()
		if st == nil {
			return 0
		}
		n := st.Purge()
		h.hub.Notify()
		return n
	})
	jmapserver.RegisterMetrics(mux, jmapserver.MetricsOptions{
		DataDir:    dataDir,
		RelayLabel: cfg.RelayLabel,
		Version:    version,
		Token:      os.Getenv("METRICS_TOKEN"),
	}, relayCollectors()...)
	jmapserver.RegisterAdmin(mux, jmapserver.AdminOptions{
		DataDir:    dataDir,
		RelayLabel: cfg.RelayLabel,
		Version:    version,
		Token:      os.Getenv("ADMIN_TOKEN"),
	})
	backfillAnchor(h) // record fingerprints for accounts created before the anchor
	startMaintenance(h)

	addr := cfg.ListenAddr
	if addr == "" {
		addr = "0.0.0.0:8768"
	}
	log.Printf("go-jmapap: ActivityPub + JMAP listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, jmapserver.WrapCORS(mux)))
}
