package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/yno9/go-jmapap/cryptenv"
	jmapserver "github.com/yno9/go-jmapserver"
)

var validUsername = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,30}$`)

func primaryDomain() string {
	for d := range cfg.Domains {
		return d
	}
	return cfg.Hostname
}

func provisionDomain() string {
	for d, dc := range cfg.Domains {
		if dc.AllowProvision {
			return d
		}
	}
	return ""
}

func registerProvision(mux *http.ServeMux, h *handler, dataDir string) {
	mux.HandleFunc("/account/provision", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Signature-based provisioning (biset DID.md third-party portability).
		var body struct {
			Username        string          `json:"username"`
			Domain          string          `json:"domain,omitempty"`
			DID             string          `json:"did"`
			BindTS          int64           `json:"bind_ts"`
			DIDSig          string          `json:"did_sig"`
			AuthTokenHash   string          `json:"auth_token_hash"`
			ProvisionSecret string          `json:"provision_secret,omitempty"`
			Envelope        json.RawMessage `json:"envelope,omitempty"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<14)).Decode(&body); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		username := strings.ToLower(strings.TrimSpace(body.Username))
		if !validUsername.MatchString(username) {
			http.Error(w, "invalid username", http.StatusBadRequest)
			return
		}
		if body.AuthTokenHash == "" {
			http.Error(w, "auth_token_hash required", http.StatusBadRequest)
			return
		}
		// DID is optional (biset started as a plain JMAP server; DID is a layered
		// identity feature, not a requirement to have an account at all — see
		// DID.md "coreless" mode). A client that omits it gets a plain account:
		// no binding proof needed, no anchor claim, no DNS record, no
		// discovery/portability — same as any classic JMAP mailbox.
		hasDID := body.DID != ""
		if hasDID {
			// Anchorless first, because it is the more fundamental refusal: this
			// relay cannot take a DID at all, and saying "did_sig required" to
			// someone who then supplies one would be a lie. The proof is verified
			// by the anchor, not here (ANCHOR.md decision 1), so with no anchor
			// there is nobody to verify it — and an unverified DID must never be
			// claimed, or anyone could have a stranger's identity recorded as
			// their own. Anchorless means plain accounts, exactly as ANCHOR.md's
			// non-goals describe it.
			if cfg.AnchorURL == "" {
				http.Error(w, "did not supported on this relay (no identity anchor)", http.StatusBadRequest)
				return
			}
			if body.DIDSig == "" {
				http.Error(w, "did_sig required when did is present", http.StatusBadRequest)
				return
			}
		}

		// Domain routing + provision policy (open, or gated by a shared secret).
		domain := strings.ToLower(strings.TrimSpace(body.Domain))
		var dc DomainConfig
		if domain != "" {
			c, ok := cfg.Domains[domain]
			if !ok {
				http.Error(w, "unknown domain", http.StatusBadRequest)
				return
			}
			dc = c
		} else {
			domain = provisionDomain()
			if domain == "" {
				http.Error(w, "account creation not available", http.StatusForbidden)
				return
			}
			dc = cfg.Domains[domain]
		}
		if !dc.AllowProvision {
			if dc.ProvisionSecret == "" || body.ProvisionSecret != dc.ProvisionSecret {
				http.Error(w, "domain not open for provisioning", http.StatusForbidden)
				return
			}
		}
		email := username + "@" + domain

		// Accounts are purely dynamic (no config-managed account list) — a name is
		// taken iff it already has a credential.
		h.mu.RLock()
		_, dynExists := h.dyn[email]
		h.mu.RUnlock()
		if dynExists || readAuthHash(dataDir, domain, username) != "" {
			http.Error(w, "username taken", http.StatusConflict)
			return
		}

		// Identity anchor: prove control of the DID and claim localpart → DID —
		// one round trip, both jobs. jmapap holds no anchor storage of its own
		// anymore, and now no DID crypto either: it defers to the standalone
		// anchor service, same as jmapsmtp. r.Host is forwarded verbatim — it is
		// what the client signed against, and only this relay saw it first-hand.
		if hasDID {
			proof := jmapserver.BindingProof{Sig: body.DIDSig, TS: body.BindTS, Host: r.Host}
			switch jmapserver.AnchorClaim(anchorRef(), username, domain, body.DID, proof) {
			case "invalid":
				http.Error(w, "did binding rejected", http.StatusUnauthorized)
				return
			case "conflict":
				http.Error(w, "identity owned by a different key", http.StatusConflict)
				return
			case "error":
				log.Printf("[anchor] unreachable (%s) — refusing provision of %s@%s", cfg.AnchorURL, username, domain)
				http.Error(w, "identity anchor unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		if err := writeAuthHash(dataDir, domain, username, body.AuthTokenHash); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if len(body.Envelope) > 0 {
			if env, err := cryptenv.FromBytes(body.Envelope); err == nil {
				writeEnvelope(dataDir, domain, username, env) //nolint:errcheck
			}
		}

		// A static account already has a store from startup; only register a new
		// dynamic one when this is a genuinely new account (avoids clobbering the
		// existing store / its loaded messages).
		if !h.hasAccount(email) {
			h.addDynAccount(username, domain, dataDir)
			// No local DID index to maintain: which addresses trace back to a
			// DID is cross-relay information, so the anchor derives it from the
			// claim this provision just made (ANCHOR.md decision 1). Every
			// address still gets its own independent store (and, for AP, its own
			// actor key/URI) — that was never what the index was for.
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"email": email}) //nolint:errcheck
	})
}
