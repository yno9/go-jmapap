package main

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/yno9/go-jmapap/cryptenv"
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

		var body struct {
			Username string          `json:"username"`
			Envelope json.RawMessage `json:"envelope"`
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

		domain := provisionDomain()
		if domain == "" {
			http.Error(w, "account creation not available", http.StatusForbidden)
			return
		}
		email := username + "@" + domain

		// Check not already taken (static config or dynamic).
		//
		// A config-reserved (static) username is normally initialized via a setup
		// token, so provisioning is refused. The exception: an identity a sibling
		// relay already owns has an anchor fingerprint here but no local envelope
		// yet — it may be claimed by presenting the matching envelope (the anchor
		// check below enforces the match). This is how biset adds the AP relay to
		// a mail-only identity. Still refuse if an envelope already exists, or if
		// there is no anchor entry to gate the claim.
		if domCfg, ok := cfg.Domains[domain]; ok {
			if _, ok := domCfg.Accounts[username]; ok {
				hasEnv := readEnvelope(dataDir, domain, username) != nil
				hasAnchor := readIdentityFP(dataDir, domain, username) != ""
				if hasEnv || !hasAnchor {
					http.Error(w, "username taken", http.StatusConflict)
					return
				}
			}
		}
		h.mu.RLock()
		_, dynExists := h.dyn[email]
		h.mu.RUnlock()
		if dynExists || readEnvelope(dataDir, domain, username) != nil {
			http.Error(w, "username taken", http.StatusConflict)
			return
		}

		env, err := cryptenv.FromBytes(body.Envelope)
		if err != nil {
			http.Error(w, "invalid envelope", http.StatusBadRequest)
			return
		}
		// Identity anchor: claim (or verify) the name against its envelope
		// fingerprint so this address can't be split across relays. jmapap hosts
		// the registry, so we claim in-process.
		if !claimIdentity(dataDir, domain, username, envelopeFingerprint(env)) {
			http.Error(w, "identity owned by a different key", http.StatusConflict)
			return
		}
		if err := writeEnvelope(dataDir, domain, username, env); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		// A static account already has a store from startup; only register a new
		// dynamic one when this is a genuinely new account (avoids clobbering the
		// existing store / its loaded messages).
		if !h.hasAccount(email) {
			h.addDynAccount(username, domain, dataDir)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]string{"email": email}) //nolint:errcheck
	})
}
