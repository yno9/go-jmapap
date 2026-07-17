package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/yno9/go-jmapap/cryptenv"
	jmapserver "github.com/yno9/go-jmapserver"
)

// ── identity anchor (client side) ──────────────────────────────────────────
//
// The identity registry itself now lives in the standalone `anchor` service
// (DID.md "no-core") — this file only calls out to it (cfg.AnchorURL), the
// same way go-jmapsmtp already does. jmapap keeps no local anchor storage and
// holds no Cloudflare credential. If cfg.AnchorURL is unset, DID coordination
// is simply skipped (DID.md "DID is optional" / "anchorless" mode).

// envelopeFingerprint is a stable hash of the cryptenv envelope. biset sends the
// identical envelope to every relay, so the fingerprint is identical across them.
func envelopeFingerprint(env *cryptenv.Envelope) string {
	b, err := env.Bytes()
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// backfillAnchor pushes fingerprints for accounts that predate the anchor
// (or that were created while anchorless), so existing identities are
// protected too, once/if an anchor is configured.
func backfillAnchor(h *handler) {
	if cfg.AnchorURL == "" {
		return
	}
	h.mu.RLock()
	primaries := make([]string, 0, len(h.stores))
	for p := range h.stores {
		primaries = append(primaries, p)
	}
	h.mu.RUnlock()
	for _, primary := range primaries {
		parts := strings.SplitN(primary, "@", 2)
		if len(parts) != 2 {
			continue
		}
		lp, dm := parts[0], parts[1]
		if env := readEnvelope(h.dataDir, dm, lp); env != nil {
			// No DID at backfill time — backfill has no client interaction to
			// derive one from. It fills in on this account's next lazy-migration
			// login (DID.md's "Existing account" flow), same as any other
			// pre-DID identity.
			if jmapserver.AnchorClaim(cfg.AnchorURL, lp, dm, envelopeFingerprint(env), "", nil) == "conflict" {
				log.Printf("[anchor] SPLIT DETECTED: %s is already claimed with a different key on the anchor", primary)
			}
		}
	}
}

// registerDidUpdate exposes PUT /account/did (Basic Auth) so an already-
// provisioned account can register its DID after the fact — DID.md's "lazy
// migration on next login" for identities that predate DID support. The
// fingerprint is read from the account's own envelope on disk (never trusted
// from the request), so this can only ever fill in / confirm the DID for the
// caller's own identity, never claim someone else's.
func registerDidUpdate(mux *http.ServeMux, h *handler, dataDir string) {
	mux.HandleFunc("/account/did", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "PUT, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		domain, localpart, ok := authenticate(r, dataDir)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="biset"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		var body struct {
			DID    string `json:"did"`
			BindTS int64  `json:"bind_ts"`
			DIDSig string `json:"did_sig"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&body); err != nil || body.DID == "" {
			http.Error(w, "did required", http.StatusBadRequest)
			return
		}
		// Basic Auth proves the caller owns this ACCOUNT. It says nothing about
		// whether they own the DID they are naming, and those are different
		// claims: without a signature anyone with a self-service account could
		// have the anchor bind a stranger's DID to their address, and publish a
		// DNS record asserting it. Same rule as /account/provision.
		if body.DIDSig == "" {
			http.Error(w, "did_sig required", http.StatusBadRequest)
			return
		}
		if cfg.AnchorURL == "" {
			w.WriteHeader(http.StatusNoContent) // anchorless: nothing to register
			return
		}
		env := readEnvelope(dataDir, domain, localpart)
		if env == nil {
			http.Error(w, "no envelope on file", http.StatusInternalServerError)
			return
		}
		proof := &jmapserver.BindingProof{Sig: body.DIDSig, TS: body.BindTS, Host: r.Host}
		switch jmapserver.AnchorClaim(cfg.AnchorURL, localpart, domain, envelopeFingerprint(env), body.DID, proof) {
		case "invalid":
			http.Error(w, "did binding rejected", http.StatusUnauthorized)
			return
		case "conflict":
			http.Error(w, "did mismatch for this identity", http.StatusConflict)
			return
		case "error":
			http.Error(w, "identity anchor unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// registerAccountDelete exposes POST /account/delete (Basic Auth) — the
// missing counterpart to /account/provision (create) and PUT /account/did
// (update): permanently removes the caller's OWN account data. Same
// no-email-in-the-body property as registerDidUpdate: the target comes only
// from the authenticated credential, so this can never touch anyone else's
// account. Mirrors purgeInactiveAccounts' cleanup (maintenance.go) — same
// map deletions (including apKeys, jmapap-only), same os.RemoveAll — just
// on-demand for one account instead of a periodic sweep over all of them.
//
// Nothing about a DID is needed here any more. AnchorRelease tells the anchor
// the address is gone, and the anchor takes it from there: it reads the DID off
// the claim it is about to release, withdraws the DNS record, and stops
// re-announcing the DHT record. Clients still send {"did":"..."} and it is
// simply ignored — it was only ever there because this relay had no way to look
// the DID up, and the anchor has never had that problem.
func registerAccountDelete(mux *http.ServeMux, h *handler, dataDir string) {
	mux.HandleFunc("/account/delete", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		domain, localpart, ok := authenticate(r, dataDir)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Basic realm="biset"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if dc, exists := cfg.Domains[domain]; exists {
			if _, static := dc.Accounts[localpart]; static {
				http.Error(w, "this account is server-managed and can't be self-deleted", http.StatusForbidden)
				return
			}
		}
		email := localpart + "@" + domain
		acctDir := filepath.Join(dataDir, domain, localpart)

		h.mu.Lock()
		delete(h.stores, email)
		delete(h.dyn, email)
		delete(h.apKeys, email)
		for alias, target := range h.aliases {
			if target == email || strings.EqualFold(alias, email) {
				delete(h.aliases, alias)
			}
		}
		h.mu.Unlock()

		jmapserver.AnchorRelease(cfg.AnchorURL, localpart, domain)
		if err := os.RemoveAll(acctDir); err != nil {
			log.Printf("[delete] failed to remove %s: %v", acctDir, err)
			http.Error(w, "failed to delete account data", http.StatusInternalServerError)
			return
		}
		log.Printf("[delete] account %s deleted (self-service)", email)
		w.WriteHeader(http.StatusNoContent)
	})
}
