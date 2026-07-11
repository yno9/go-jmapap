package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// ── actor avatars ────────────────────────────────────────────────────────────────
//
// Each account may advertise a profile picture, served at
// https://domain/<localpart>/avatar and referenced from the actor document's
// `icon` field so remote fediverse servers (Mastodon et al.) display it.
//
// biset uploads the bytes with PUT /<localpart>/avatar (Basic auth = the account's
// auth_token, same as the other authenticated endpoints). The image is opaque to
// the relay; only its content-type is remembered so GET can serve it back.

func avatarPath(dataDir, domain, localpart string) string {
	return filepath.Join(dataDir, domain, localpart, "avatar.bin")
}
func avatarTypePath(dataDir, domain, localpart string) string {
	return filepath.Join(dataDir, domain, localpart, "avatar.type")
}

// avatarInfo reports the served URL + media type when an avatar exists.
func avatarInfo(dataDir, domain, localpart string) (url, mediaType string, ok bool) {
	if _, err := os.Stat(avatarPath(dataDir, domain, localpart)); err != nil {
		return "", "", false
	}
	mediaType = "image/jpeg"
	if b, err := os.ReadFile(avatarTypePath(dataDir, domain, localpart)); err == nil && len(b) > 0 {
		mediaType = string(b)
	}
	return actorURL(localpart, domain) + "/avatar", mediaType, true
}

// handleAvatarPut stores the uploaded image bytes for the authenticated account.
func handleAvatarPut(w http.ResponseWriter, r *http.Request, h *handler, domain, localpart string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<21)) // 2 MiB cap
	if err != nil || len(body) == 0 {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	dir := filepath.Join(h.dataDir, domain, localpart)
	if err := os.MkdirAll(dir, 0700); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(avatarPath(h.dataDir, domain, localpart), body, 0600); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	ct := r.Header.Get("Content-Type")
	if ct == "" {
		ct = "image/jpeg"
	}
	_ = os.WriteFile(avatarTypePath(h.dataDir, domain, localpart), []byte(ct), 0600)
	// Push the profile change to known peers so remote servers refresh the
	// cached avatar immediately instead of waiting for their periodic refetch.
	go sendProfileUpdate(h, domain, localpart)
	w.WriteHeader(http.StatusNoContent)
}

// handleAvatarGet serves the stored avatar bytes (used by remote servers and the
// biset client alike).
func handleAvatarGet(w http.ResponseWriter, r *http.Request, h *handler, domain, localpart string) {
	b, err := os.ReadFile(avatarPath(h.dataDir, domain, localpart))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	ct := "image/jpeg"
	if t, err := os.ReadFile(avatarTypePath(h.dataDir, domain, localpart)); err == nil && len(t) > 0 {
		ct = string(t)
	}
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.Write(b) //nolint:errcheck
}
