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
	"github.com/yno9/go-jmapserver/pkarr"
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
// The optional {"did":"..."} body field is used only to evict the record from
// this relay's own pkarr gateway cache
// if it runs one (gw may be nil — PKARR_GATEWAY is opt-in) so it stops
// indefinitely re-announcing an orphaned DID document (see pkarr.Gateway.
// Forget's comment: BEP44 records only fade in ~2 hours once nothing is
// left re-announcing them). There's no email→DID reverse index on disk to
// derive any of this from, so the client (which already knows its own DID)
// supplies it — a wrong or omitted value only skips these cleanup steps; it
// has no bearing on which account gets deleted.
func registerAccountDelete(mux *http.ServeMux, h *handler, dataDir string, gw *pkarr.Gateway) {
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
		var body struct {
			DID string `json:"did"`
		}
		json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&body) //nolint:errcheck

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

		if body.DID != "" {
			if pk, err := jmapserver.DIDPublicKey(body.DID); err == nil && gw != nil {
				var pubkey [32]byte
				copy(pubkey[:], pk)
				gw.Forget(pubkey)
			}
		}
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
