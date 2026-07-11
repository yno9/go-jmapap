package main

import (
	"net/http"
	"strings"
)

// ── host split: apex (identity surface) vs app subdomain (the biset app) ─────────
//
// The apex domain (non.md) hosts the public identity surface: WebFinger, actor
// documents, and per-user handoff at /<localpart> (a browser is redirected to the
// app to start a conversation). The biset app itself lives on a separate origin
// (app_host, e.g. app.non.md) so that its session state (localStorage, per-origin)
// is cleanly separated from the apex — and so the apex root can be repurposed.

// isAppHost reports whether the request arrived on the configured app subdomain.
// With no app_host configured (single-host / dev), everything is the app.
func isAppHost(r *http.Request) bool {
	if cfg.AppHost == "" {
		return false
	}
	h := r.Host
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return strings.EqualFold(h, cfg.AppHost)
}

// hostSplit is true when we're running the apex/app split (app_host set).
func hostSplit() bool { return cfg.AppHost != "" }
