package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// registerAccountDelete exposes POST /account/delete (Basic Auth) — the
// missing counterpart to /account/provision (create) and PUT /account/did
// (update): permanently removes the caller's OWN account data. The target comes
// only from the authenticated credential, so this can never touch anyone else's
// account. Mirrors purgeInactiveAccounts' cleanup (maintenance.go) — same map
// deletions (including apKeys, jmapap-only), same os.RemoveAll — just on-demand
// for one account instead of a periodic sweep over all of them.
//
// This stays in the default JMAP surface, not the DID seam: deleting your own
// account is a plain-account operation too. Only the anchor release is DID, and
// it goes through the anchorRelease seam — a no-op in the noanchor build (there
// is no claim to withdraw), so account deletion works identically either way.
// When a claim does exist, releasing it tells the anchor the address is gone and
// the anchor takes it from there: it reads the DID off the claim it is about to
// release, withdraws the DNS record, and stops re-announcing the DHT record.
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

		anchorRelease(localpart, domain)
		if err := os.RemoveAll(acctDir); err != nil {
			log.Printf("[delete] failed to remove %s: %v", acctDir, err)
			http.Error(w, "failed to delete account data", http.StatusInternalServerError)
			return
		}
		log.Printf("[delete] account %s deleted (self-service)", email)
		w.WriteHeader(http.StatusNoContent)
	})
}
