package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/yno9/go-jmapap/cryptenv"
)

// ── identity anchor ──────────────────────────────────────────────────────────────
//
// biset's relays are independent: mail (jmapsmtp) and ActivityPub (jmapap) each
// own their "<localpart>" namespace on their own disk. Without coordination the
// SAME address could end up owned by two different people (different cryptenv
// envelopes) — a split identity, exploitable for fediverse impersonation.
//
// The apex (this jmapap, which already answers WebFinger for the domain) plays a
// minimal identity-anchor role: a single name-claim registry mapping localpart →
// envelope fingerprint. The first claim wins; every relay's provision must present
// a matching fingerprint. This collapses the two independent first-come points
// into one, so an identity is always owned coherently across relays. The anchor
// is control-plane only (no messages/keys/state) — runtime message flow never
// touches it.

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

func identityFPPath(dataDir, domain, localpart string) string {
	return filepath.Join(dataDir, domain, localpart, "identity.fp")
}

// claimIdentity records the fingerprint for a name, or verifies it against an
// existing claim. Returns ok=false only on a genuine conflict (name already held
// by a different fingerprint). First claim and idempotent re-claims return true.
func claimIdentity(dataDir, domain, localpart, fp string) (ok bool) {
	if fp == "" {
		return false
	}
	path := identityFPPath(dataDir, domain, localpart)
	if b, err := os.ReadFile(path); err == nil {
		return strings.TrimSpace(string(b)) == fp
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return false
	}
	return os.WriteFile(path, []byte(fp), 0600) == nil
}

func readIdentityFP(dataDir, domain, localpart string) string {
	if b, err := os.ReadFile(identityFPPath(dataDir, domain, localpart)); err == nil {
		return strings.TrimSpace(string(b))
	}
	return ""
}

// backfillAnchor records fingerprints for accounts that predate the anchor, so
// existing identities are protected too. In-process for this relay's own accounts.
func backfillAnchor(h *handler) {
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
		if readIdentityFP(h.dataDir, dm, lp) != "" {
			continue
		}
		if env := readEnvelope(h.dataDir, dm, lp); env != nil {
			claimIdentity(h.dataDir, dm, lp, envelopeFingerprint(env))
		}
	}
}

// registerAnchor exposes the name-claim registry over HTTP so sibling relays
// (e.g. jmapsmtp) can consult it at provision time.
//
//	GET  /identity/<localpart> → {"fingerprint": "..."} or 404
//	POST /identity/<localpart> {"fingerprint":"..."} → 200/201 ok, 409 conflict
func registerAnchor(mux *http.ServeMux, h *handler) {
	mux.HandleFunc("/identity/", func(w http.ResponseWriter, r *http.Request) {
		localpart := strings.ToLower(strings.TrimPrefix(r.URL.Path, "/identity/"))
		if localpart == "" || strings.Contains(localpart, "/") {
			http.NotFound(w, r)
			return
		}
		domain := primaryDomain()
		w.Header().Set("Content-Type", "application/json")

		switch r.Method {
		case http.MethodGet:
			fp := readIdentityFP(h.dataDir, domain, localpart)
			if fp == "" {
				http.NotFound(w, r)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"fingerprint": fp}) //nolint:errcheck

		case http.MethodPost:
			var body struct {
				Fingerprint string `json:"fingerprint"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&body); err != nil || body.Fingerprint == "" {
				http.Error(w, "fingerprint required", http.StatusBadRequest)
				return
			}
			existing := readIdentityFP(h.dataDir, domain, localpart)
			if claimIdentity(h.dataDir, domain, localpart, body.Fingerprint) {
				if existing == "" {
					w.WriteHeader(http.StatusCreated)
				} else {
					w.WriteHeader(http.StatusOK)
				}
				json.NewEncoder(w).Encode(map[string]string{"fingerprint": body.Fingerprint}) //nolint:errcheck
				return
			}
			http.Error(w, "identity owned by a different key", http.StatusConflict)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}
