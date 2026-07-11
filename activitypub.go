package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	jmap "git.sr.ht/~rockorager/go-jmap"
	"git.sr.ht/~rockorager/go-jmap/mail"
	"git.sr.ht/~rockorager/go-jmap/mail/email"
	jmapserver "github.com/yno9/go-jmapserver"
)

// ── AP identity (per-account) ───────────────────────────────────────────────────
//
// Each account localpart@domain is simultaneously an ActivityPub actor at
// https://domain/localpart. The actor's HTTP-signature RSA key is separate from
// the account's PGP/MLS material — AP delivery only proves "the server holds the
// actor key", not message-level E2EE.

func apBase(domain string) string {
	if strings.HasPrefix(domain, "localhost") || strings.HasPrefix(domain, "127.0.0.1") {
		return "http://" + domain
	}
	return "https://" + domain
}

func actorURL(localpart, domain string) string { return apBase(domain) + "/" + localpart }
func inboxURL(localpart, domain string) string  { return actorURL(localpart, domain) + "/inbox" }
func keyID(localpart, domain string) string     { return actorURL(localpart, domain) + "#main-key" }
func acctHandle(localpart, domain string) string { return localpart + "@" + domain }

func publicKeyPEM(k *rsa.PrivateKey) string {
	b, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: b}))
}

// buildActorDoc assembles the ActivityPub actor document, shared by the GET
// actor route and the Update(Person) activity used to push profile changes.
func buildActorDoc(h *handler, domain, localpart string) map[string]any {
	self := actorURL(localpart, domain)
	doc := map[string]any{
		"@context":          []string{"https://www.w3.org/ns/activitystreams", "https://w3id.org/security/v1"},
		"type":              "Person",
		"id":                self,
		"url":               self,
		"name":              localpart,
		"preferredUsername": localpart,
		"summary":           "",
		"inbox":             inboxURL(localpart, domain),
		"outbox":            self + "/outbox",
		"followers":         self + "/followers",
		"following":         self + "/following",
		"publicKey": map[string]string{
			"id":           keyID(localpart, domain),
			"owner":        self,
			"publicKeyPem": publicKeyPEM(h.apKey(domain, localpart)),
		},
	}
	if url, mediaType, ok := avatarInfo(h.dataDir, domain, localpart); ok {
		doc["icon"] = map[string]string{"type": "Image", "mediaType": mediaType, "url": url}
	}
	return doc
}

// sendProfileUpdate delivers an Update(Person) activity to every known peer's
// inbox so remote servers (Mastodon et al.) refresh their cached profile —
// otherwise a newly-set avatar only appears after their ~daily actor refetch.
// Peers are gathered from this account's conversation partners plus followed
// actors; inboxes are deduplicated.
func sendProfileUpdate(h *handler, domain, localpart string) {
	primary := acctHandle(localpart, domain)
	self := actorURL(localpart, domain)
	ts := time.Now().UTC()
	update := map[string]any{
		"@context":  []string{"https://www.w3.org/ns/activitystreams", "https://w3id.org/security/v1"},
		"type":      "Update",
		"id":        fmt.Sprintf("%s#update-%d", self, ts.UnixMilli()),
		"actor":     self,
		"to":        []string{"https://www.w3.org/ns/activitystreams#Public"},
		"object":    buildActorDoc(h, domain, localpart),
		"published": ts.Format(time.RFC3339),
	}
	payload, err := json.Marshal(update)
	if err != nil {
		return
	}

	// Collect remote peer handles from stored messages (From + To).
	handles := map[string]bool{}
	if store := h.storeForPrimary(primary); store != nil {
		for _, msg := range store.All() {
			addrs := append(append([]*mail.Address{}, msg.From...), msg.To...)
			for _, a := range addrs {
				if a == nil || a.Email == "" {
					continue
				}
				hnd := strings.ToLower(a.Email)
				if hnd == primary || !strings.Contains(hnd, "@") {
					continue
				}
				handles[hnd] = true
			}
		}
	}
	followedActors.Range(func(k, v any) bool {
		if fe, ok := v.(followEntry); ok && fe.handle != "" {
			handles[strings.ToLower(fe.handle)] = true
		}
		return true
	})

	// Resolve to inboxes and deliver once per inbox.
	inboxes := map[string]bool{}
	for hnd := range handles {
		if ra, err := resolveActor(hnd); err == nil && ra.inboxURL != "" {
			inboxes[ra.inboxURL] = true
		}
	}
	key, kid := h.apKey(domain, localpart), keyID(localpart, domain)
	for inbox := range inboxes {
		if err := httpSignedPost(inbox, payload, key, kid); err != nil {
			log.Printf("[ap] %s profile update → %s failed: %v", primary, inbox, err)
		}
	}
	log.Printf("[ap] %s profile update delivered to %d inbox(es)", primary, len(inboxes))
}

// ── remote actor resolution ─────────────────────────────────────────────────────

type resolvedActor struct {
	actorURL string
	inboxURL string
	iconURL  string
	name     string
	summary  string
}

var resolvedActorCache sync.Map // handle → *resolvedActor

func resolveActor(handle string) (*resolvedActor, error) {
	if v, ok := resolvedActorCache.Load(handle); ok {
		return v.(*resolvedActor), nil
	}
	parts := strings.SplitN(handle, "@", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid handle: %q", handle)
	}
	scheme := "https"
	if strings.HasPrefix(parts[1], "localhost") || strings.HasPrefix(parts[1], "127.0.0.1") {
		scheme = "http"
	}
	wfURL := scheme + "://" + parts[1] + "/.well-known/webfinger?resource=acct:" + handle
	resp, err := http.Get(wfURL) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("webfinger: %w", err)
	}
	defer resp.Body.Close()
	var wf struct {
		Links []struct {
			Rel  string `json:"rel"`
			Href string `json:"href"`
		} `json:"links"`
	}
	json.NewDecoder(resp.Body).Decode(&wf) //nolint:errcheck
	var selfHref string
	for _, l := range wf.Links {
		if l.Rel == "self" {
			selfHref = l.Href
			break
		}
	}
	if selfHref == "" {
		return nil, fmt.Errorf("no self link for %s", handle)
	}
	req, _ := http.NewRequest("GET", selfHref, nil)
	req.Header.Set("Accept", "application/activity+json")
	aresp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("actor fetch: %w", err)
	}
	defer aresp.Body.Close()
	var actor struct {
		Inbox             string          `json:"inbox"`
		Name              string          `json:"name"`
		PreferredUsername string          `json:"preferredUsername"`
		Summary           string          `json:"summary"`
		Icon              json.RawMessage `json:"icon"`
	}
	json.NewDecoder(aresp.Body).Decode(&actor) //nolint:errcheck
	if actor.Inbox == "" {
		return nil, fmt.Errorf("no inbox for %s", handle)
	}
	name := actor.Name
	if name == "" {
		name = actor.PreferredUsername
	}
	ra := &resolvedActor{
		actorURL: selfHref,
		inboxURL: actor.Inbox,
		iconURL:  parseIconURL(actor.Icon),
		name:     name,
		summary:  actor.Summary,
	}
	resolvedActorCache.Store(handle, ra)
	return ra, nil
}

// parseIconURL extracts an image URL from an actor's `icon`, which fediverse
// servers encode variously: an object {url}, an array of such objects, or a bare
// URL string.
func parseIconURL(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var obj struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil && obj.URL != "" {
		return obj.URL
	}
	var arr []struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(raw, &arr); err == nil {
		for _, it := range arr {
			if it.URL != "" {
				return it.URL
			}
		}
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	return ""
}

func actorURLToHandle(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1] + "@" + u.Hostname()
}

// ── follow tracking (per-account) ───────────────────────────────────────────────

type followEntry struct {
	handle      string
	followMsgID jmap.ID
}

// followedActors maps followKey(primary, actorURL) → followEntry.
var followedActors sync.Map

func followKey(primary, actorURL string) string { return primary + "\n" + actorURL }

// ── outbound signing ────────────────────────────────────────────────────────────

func httpSignedPost(targetURL string, body []byte, signingKey *rsa.PrivateKey, kid string) (err error) {
	defer func() {
		if err != nil {
			apOutbound.WithLabelValues("failed").Inc()
		} else {
			apOutbound.WithLabelValues("ok").Inc()
		}
	}()
	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}
	date := time.Now().UTC().Format(http.TimeFormat)
	hash := sha256.Sum256(body)
	digest := "SHA-256=" + base64.StdEncoding.EncodeToString(hash[:])

	signingString := strings.Join([]string{
		"(request-target): post " + u.Path,
		"host: " + u.Host,
		"date: " + date,
		"digest: " + digest,
	}, "\n")

	hh := sha256.Sum256([]byte(signingString))
	sig, err := rsa.SignPKCS1v15(rand.Reader, signingKey, crypto.SHA256, hh[:])
	if err != nil {
		return err
	}
	sigHeader := fmt.Sprintf(`keyId="%s",algorithm="rsa-sha256",headers="(request-target) host date digest",signature="%s"`,
		kid, base64.StdEncoding.EncodeToString(sig))

	req, _ := http.NewRequest("POST", targetURL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/activity+json")
	req.Header.Set("Date", date)
	req.Header.Set("Digest", digest)
	req.Header.Set("Signature", sigHeader)
	req.Header.Set("Host", u.Host)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	log.Printf("[ap] POST %s → %d %s", targetURL, resp.StatusCode, strings.TrimSpace(string(b)))
	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		return fmt.Errorf("POST %s: %d %s", targetURL, resp.StatusCode, string(b))
	}
	return nil
}

// ── send (store → AP) ───────────────────────────────────────────────────────────

func sendToActor(h *handler, domain, localpart string, msg email.Email, target string) (string, error) {
	resolved, err := resolveActor(target)
	if err != nil {
		return "", err
	}
	self := actorURL(localpart, domain)
	body := jmapserver.MessageBody(msg)
	ts := time.Now().UTC()
	noteID := fmt.Sprintf("%s/notes/%d", self, ts.UnixMilli())

	mention := "@" + target
	note := map[string]any{
		"@context":     "https://www.w3.org/ns/activitystreams",
		"type":         "Note",
		"id":           noteID,
		"url":          noteID,
		"attributedTo": self,
		"to":           []string{resolved.actorURL},
		"cc":           []string{},
		"content":      "<p>" + mention + " " + htmlEscape(body) + "</p>",
		"published":    ts.Format(time.RFC3339),
		"tag": []map[string]string{{
			"type": "Mention",
			"href": resolved.actorURL,
			"name": mention,
		}},
	}
	if len(msg.InReplyTo) > 0 {
		note["inReplyTo"] = msg.InReplyTo[0]
	}

	create := map[string]any{
		"@context":  "https://www.w3.org/ns/activitystreams",
		"type":      "Create",
		"id":        fmt.Sprintf("%s#create-%d", self, ts.UnixMilli()),
		"actor":     self,
		"to":        []string{resolved.actorURL},
		"cc":        []string{},
		"object":    note,
		"published": ts.Format(time.RFC3339),
	}
	payload, err := json.Marshal(create)
	if err != nil {
		return "", err
	}
	log.Printf("[ap] %s send → %s", acctHandle(localpart, domain), resolved.inboxURL)
	return noteID, httpSignedPost(resolved.inboxURL, payload, h.apKey(domain, localpart), keyID(localpart, domain))
}

func sendFollow(h *handler, domain, localpart, target string) (string, error) {
	resolved, err := resolveActor(target)
	if err != nil {
		return "", err
	}
	self := actorURL(localpart, domain)
	ts := time.Now().UTC()
	actID := fmt.Sprintf("%s/follows/%d", self, ts.UnixMilli())
	activity := map[string]any{
		"@context": "https://www.w3.org/ns/activitystreams",
		"type":     "Follow",
		"id":       actID,
		"actor":    self,
		"object":   resolved.actorURL,
	}
	payload, err := json.Marshal(activity)
	if err != nil {
		return "", err
	}
	log.Printf("[ap] %s follow → %s (%s)", acctHandle(localpart, domain), target, resolved.inboxURL)
	if err := httpSignedPost(resolved.inboxURL, payload, h.apKey(domain, localpart), keyID(localpart, domain)); err != nil {
		return "", err
	}
	return actID, nil
}

func sendUnfollow(h *handler, domain, localpart string, followMsgID jmap.ID, target string) error {
	resolved, err := resolveActor(target)
	if err != nil {
		return err
	}
	self := actorURL(localpart, domain)
	ts := time.Now().UTC()
	activity := map[string]any{
		"@context": "https://www.w3.org/ns/activitystreams",
		"type":     "Undo",
		"id":       fmt.Sprintf("%s/undos/%d", self, ts.UnixMilli()),
		"actor":    self,
		"object": map[string]any{
			"type":   "Follow",
			"id":     fmt.Sprintf("%s/follows/%s", self, string(followMsgID)),
			"actor":  self,
			"object": resolved.actorURL,
		},
	}
	payload, err := json.Marshal(activity)
	if err != nil {
		return err
	}
	primary := acctHandle(localpart, domain)
	followedActors.Delete(followKey(primary, resolved.actorURL))
	log.Printf("[ap] %s unfollow → %s (%s)", primary, target, resolved.inboxURL)
	return httpSignedPost(resolved.inboxURL, payload, h.apKey(domain, localpart), keyID(localpart, domain))
}

// ── receive (AP → store) ────────────────────────────────────────────────────────

var tagRe = regexp.MustCompile(`<[^>]+>`)
var mentionRe = regexp.MustCompile(`^(@\S+\s*)+`)

func handleInbox(store *jmapserver.Store, hub *jmapserver.Hub, domain, localpart string, body []byte) {
	var activity struct {
		Type   string          `json:"type"`
		Actor  string          `json:"actor"`
		Object json.RawMessage `json:"object"`
	}
	if err := json.Unmarshal(body, &activity); err != nil {
		return
	}
	switch activity.Type {
	case "Accept":
		apInbox.WithLabelValues("Accept").Inc()
		handleAccept(store, hub, domain, localpart, activity.Actor, activity.Object)
	case "Create":
		apInbox.WithLabelValues("Create").Inc()
		handleCreate(store, hub, domain, localpart, activity.Actor, activity.Object)
	default:
		apInbox.WithLabelValues("other").Inc()
		log.Printf("[ap] %s inbox: unhandled activity type %q", acctHandle(localpart, domain), activity.Type)
	}
}

func handleAccept(store *jmapserver.Store, hub *jmapserver.Hub, domain, localpart, actor string, object json.RawMessage) {
	var obj struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(object, &obj); err != nil || obj.Type != "Follow" {
		return
	}
	primary := acctHandle(localpart, domain)
	log.Printf("[ap] %s: follow accepted by %s", primary, actor)
	for _, msg := range store.All() {
		if msg.MailboxIDs[jmap.ID(feedsMailboxID(primary))] && len(msg.To) > 0 && msg.To[0] != nil {
			handle := msg.To[0].Email
			ra, err := resolveActor(handle)
			if err == nil && ra.actorURL == actor {
				store.PatchKeywords(msg.ID, map[string]any{ //nolint:errcheck
					"keywords/$follow_pending":  nil,
					"keywords/$follow_accepted": true,
				})
				followedActors.Store(followKey(primary, actor), followEntry{handle: handle, followMsgID: msg.ID})
				hub.Notify()
				break
			}
		}
	}
}

func handleCreate(store *jmapserver.Store, hub *jmapserver.Hub, domain, localpart, actor string, object json.RawMessage) {
	var obj struct {
		Type      string   `json:"type"`
		ID        string   `json:"id"`
		Content   string   `json:"content"`
		InReplyTo string   `json:"inReplyTo"`
		Published string   `json:"published"`
		To        []string `json:"to"`
		CC        []string `json:"cc"`
	}
	if err := json.Unmarshal(object, &obj); err != nil || obj.Type != "Note" {
		return
	}

	text := strings.TrimSpace(tagRe.ReplaceAllString(obj.Content, ""))
	if text == "" {
		return
	}

	primary := acctHandle(localpart, domain)
	fe, isFollowed := followedActors.Load(followKey(primary, actor))

	isPublic := false
	for _, t := range append(obj.To, obj.CC...) {
		if t == "https://www.w3.org/ns/activitystreams#Public" || t == "Public" {
			isPublic = true
			break
		}
	}
	log.Printf("[ap] %s create from=%s followed=%v public=%v", primary, actor, isFollowed, isPublic)
	if !isPublic {
		// Direct message / mention — strip leading @mentions.
		text = strings.TrimSpace(mentionRe.ReplaceAllString(text, ""))
		if text == "" {
			return
		}
	}

	from := actorURLToHandle(actor)
	if from == "" {
		from = actor
	}

	ts := time.Now().UTC()
	if obj.Published != "" {
		if t, err := time.Parse(time.RFC3339, obj.Published); err == nil {
			ts = t
		}
	}

	rawMsgID := fmt.Sprintf("<%s@ap>", strings.ReplaceAll(obj.ID, "/", "-"))
	msgID := makeMessageID(rawMsgID, primary, ts)

	// Route public posts from followed actors to the feeds mailbox, threaded
	// under the follow record. Direct messages go to the regular inbox.
	mbxID := makeMailboxID(primary)
	inReplyTo := obj.InReplyTo
	if isFollowed && isPublic {
		mbxID = feedsMailboxID(primary)
		inReplyTo = string(fe.(followEntry).followMsgID)
	}

	e := newTextMessage(msgID, obj.ID, mbxID, from, primary, text, ts, inReplyTo)
	if err := store.Put(e); err != nil {
		log.Printf("[ap] %s store put: %v", primary, err)
		return
	}
	hub.Notify()
}

// newTextMessage builds a minimal plain-text email.Email, mirroring the shape
// the SMTP relay produces so biset-ui renders AP and mail identically.
//
// id is the JMAP object id (slash-free, safe as a protocol id). msgID is the
// logical Message-ID used for threading: for AP this MUST be the original Note
// URL (obj.ID), the canonical reference every peer shares — otherwise a reply's
// inReplyTo (which carries that URL) won't match the sender's copy and the thread
// splits across relays.
func newTextMessage(id, msgID, mailboxID, from, to, body string, ts time.Time, inReplyTo string) email.Email {
	partID := "1"
	rt := ts
	if msgID == "" {
		msgID = id
	}
	e := email.Email{
		ID:         jmap.ID(id),
		MailboxIDs: map[jmap.ID]bool{jmap.ID(mailboxID): true},
		Keywords:   map[string]bool{},
		From:       []*mail.Address{{Email: from}},
		To:         []*mail.Address{{Email: to}},
		ReceivedAt: &rt,
		MessageID:  []string{msgID},
		BodyValues: map[string]*email.BodyValue{partID: {Value: body}},
		TextBody: []*email.BodyPart{{
			PartID:  partID,
			Type:    "text/plain",
			Charset: "utf-8",
			Size:    uint64(len(body)),
		}},
		Preview: preview(body),
		Size:    uint64(len(body)),
	}
	if inReplyTo != "" {
		e.InReplyTo = []string{inReplyTo}
		e.References = []string{inReplyTo}
	}
	return e
}

func preview(body string) string {
	s := strings.Join(strings.Fields(body), " ")
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// ── ActivityPub HTTP routes ─────────────────────────────────────────────────────

func logRequest(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("[ap] %s %s", r.Method, r.URL.Path)
		next(w, r)
	}
}

// wantsAP reports whether the client is asking for the ActivityPub actor document
// rather than the HTML app. Fediverse servers send an explicit activity+json /
// ld+json Accept; browsers do not. Absent that, we serve HTML.
func wantsAP(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/activity+json") ||
		strings.Contains(accept, "application/ld+json")
}

// serveUserPage answers a browser GET for /<localpart>: the biset app on the app
// host (or when there's no host split). On the apex it hands the browser off to
// the app, pre-addressed to this user (the app then shows compose when logged in,
// or account creation for a new visitor). AP clients never reach here — they get
// the actor document via the wantsAP branch.
func serveUserPage(w http.ResponseWriter, r *http.Request, h *handler, domain, localpart string) bool {
	if !hostSplit() || isAppHost(r) {
		return serveWebIndex(w, r)
	}
	http.Redirect(w, r, "https://"+cfg.AppHost+"/#compose/"+localpart+"@"+domain, http.StatusFound)
	return true
}

// iOS's "Add to Home Screen" icon fetch does not honor data: URIs for
// apple-touch-icon (unlike a regular favicon), so it needs a real fetchable
// URL — served here directly, independent of serveWebIndex's single-file app.
//
//go:embed assets/apple-touch-icon.png
var appleTouchIconPNG []byte

// serveWebIndex writes biset's single-file HTML app (when web_root is configured).
// Returns false if static serving is disabled or the file is missing, so callers
// can fall back to 404.
func serveWebIndex(w http.ResponseWriter, r *http.Request) bool {
	if cfg.WebRoot == "" {
		return false
	}
	b, err := os.ReadFile(filepath.Join(cfg.WebRoot, "index.html"))
	if err != nil {
		return false
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// The whole app is inlined into this one file, so a stale cached copy means
	// the user runs old code indefinitely — exactly what stranded an iOS PWA on
	// a pre-fix build. Force the browser to revalidate every launch so deploys
	// actually reach the device. (index.html is tiny relative to a round trip;
	// no-cache still allows a 304 when unchanged.)
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Write(b) //nolint:errcheck
	return true
}

func registerAPRoutes(mux *http.ServeMux, h *handler) {
	mux.HandleFunc("/.well-known/webfinger", logRequest(func(w http.ResponseWriter, r *http.Request) {
		resource := r.URL.Query().Get("resource")
		acct := strings.TrimPrefix(resource, "acct:")
		lastAt := strings.LastIndex(acct, "@")
		if lastAt < 0 {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		user, host := acct[:lastAt], acct[lastAt+1:]
		if !h.hasAccount(user + "@" + host) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/jrd+json")
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"subject": "acct:" + user + "@" + host,
			"links": []map[string]string{{
				"rel":  "self",
				"type": "application/activity+json",
				"href": actorURL(user, host),
			}},
		})
	}))

	// Advertise this relay's display label/color for the biset client.
	mux.HandleFunc("/relay-info", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		label, color := cfg.RelayLabel, cfg.RelayColor
		if label == "" {
			label = "AP"
		}
		if color == "" {
			color = "#8b5cf6"
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"label": label, "color": color}) //nolint:errcheck
	})

	// Recipient discovery for the biset composer: given acct:user@host, report
	// whether it resolves to an ActivityPub actor (server-side webfinger, so the
	// browser avoids cross-origin CORS on arbitrary fediverse instances).
	mux.HandleFunc("/resolve", logRequest(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		acct := strings.TrimPrefix(r.URL.Query().Get("acct"), "acct:")
		// Local account: answer from live local state (avatarInfo etc.) instead of
		// the remote-resolution cache, which never expires and so can be stale —
		// e.g. an avatar set after the actor was first resolved (its icon would
		// otherwise stay empty forever). This is the /<user>/ landing's own domain.
		if lastAt := strings.LastIndex(acct, "@"); lastAt > 0 {
			lp, host := acct[:lastAt], acct[lastAt+1:]
			if host == primaryDomain() && h.hasAccount(acct) {
				icon := ""
				if u, _, ok := avatarInfo(h.dataDir, host, lp); ok {
					icon = u
				}
				json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
					"ap": true, "actor": actorURL(lp, host), "inbox": inboxURL(lp, host),
					"icon": icon, "name": lp, "summary": "",
				})
				return
			}
		}
		ra, err := resolveActor(acct)
		if err != nil || ra == nil {
			json.NewEncoder(w).Encode(map[string]any{"ap": false}) //nolint:errcheck
			return
		}
		json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
			"ap": true, "actor": ra.actorURL, "inbox": ra.inboxURL,
			"icon": ra.iconURL, "name": ra.name, "summary": ra.summary,
		})
	}))

	mux.HandleFunc("/apple-touch-icon.png", logRequest(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=604800")
		w.Write(appleTouchIconPNG) //nolint:errcheck
	}))

	// The Service Worker (background Web Push / badge, see biset's src/sw.ts)
	// can't be inlined into index.html like the rest of the app — it must be
	// its own fetchable same-origin file, same reasoning as apple-touch-icon
	// above. Read from disk (not embedded): it's rebuilt and deployed
	// alongside index.html into web_root, not baked into this binary.
	mux.HandleFunc("/sw.js", logRequest(func(w http.ResponseWriter, r *http.Request) {
		if cfg.WebRoot == "" {
			http.NotFound(w, r)
			return
		}
		b, err := os.ReadFile(filepath.Join(cfg.WebRoot, "sw.js"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Service-Worker-Allowed", "/")
		// Never let an HTTP cache serve a stale worker: the browser's SW update
		// check must always see the latest bytes, or a fix can sit undeployed on
		// the device indefinitely (iOS PWA workers are already sticky enough).
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Write(b) //nolint:errcheck
	}))

	mux.HandleFunc("/", logRequest(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if len(parts) == 0 || parts[0] == "" {
			if r.Method == http.MethodGet {
				// App subdomain (or no split): serve the app. Apex root is being
				// repurposed — send it to the app for now.
				if !hostSplit() || isAppHost(r) {
					if serveWebIndex(w, r) {
						return
					}
				} else {
					http.Redirect(w, r, "https://"+cfg.AppHost+"/", http.StatusFound)
					return
				}
			}
			http.NotFound(w, r)
			return
		}
		localpart := parts[0]
		reqHost := r.Host
		if h, _, err := net.SplitHostPort(reqHost); err == nil {
			reqHost = h
		}
		domain := primaryDomain()
		if _, ok := cfg.Domains[reqHost]; ok {
			domain = reqHost
		}
		primary := acctHandle(localpart, domain)
		if !h.hasAccount(primary) {
			http.NotFound(w, r)
			return
		}

		// GET /<localpart> — actor document (AP clients) or, for browsers, the app
		// (on the app host) / a public profile page (on the apex).
		if len(parts) == 1 && r.Method == http.MethodGet {
			if wantsAP(r) {
				w.Header().Set("Content-Type", "application/activity+json")
				json.NewEncoder(w).Encode(buildActorDoc(h, domain, localpart)) //nolint:errcheck
				return
			}
			if serveUserPage(w, r, h, domain, localpart) {
				return
			}
			http.NotFound(w, r)
			return
		}

		// GET /<localpart>/ — trailing slash, same browser handling as above.
		if len(parts) == 2 && parts[1] == "" && r.Method == http.MethodGet {
			if serveUserPage(w, r, h, domain, localpart) {
				return
			}
			http.NotFound(w, r)
			return
		}

		// GET /<localpart>/avatar — profile image; PUT to upload (Basic auth).
		if len(parts) == 2 && parts[1] == "avatar" {
			switch r.Method {
			case http.MethodOptions:
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				w.WriteHeader(http.StatusNoContent)
			case http.MethodGet:
				handleAvatarGet(w, r, h, domain, localpart)
			case http.MethodPut:
				w.Header().Set("Access-Control-Allow-Origin", "*")
				dm, lp, okAuth := authenticate(r, h.dataDir)
				if !okAuth || !strings.EqualFold(lp+"@"+dm, primary) {
					w.Header().Set("WWW-Authenticate", `Basic realm="biset"`)
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				handleAvatarPut(w, r, h, domain, localpart)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}

		// POST /<localpart>/inbox
		if len(parts) == 2 && parts[1] == "inbox" && r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			if err := verifyHTTPSignature(r, body); err != nil {
				apSignature.WithLabelValues("failed").Inc()
				log.Printf("[ap] signature verification failed: %v", err)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			apSignature.WithLabelValues("ok").Inc()
			store := h.storeForPrimary(primary)
			if store == nil {
				http.NotFound(w, r)
				return
			}
			handleInbox(store, h.hub, domain, localpart, body)
			w.WriteHeader(http.StatusAccepted)
			return
		}

		// GET /<localpart>/outbox|followers|following — minimal collections
		if len(parts) == 2 && r.Method == http.MethodGet {
			self := actorURL(localpart, domain)
			w.Header().Set("Content-Type", "application/activity+json")
			json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck
				"@context":     "https://www.w3.org/ns/activitystreams",
				"type":         "OrderedCollection",
				"id":           self + "/" + parts[1],
				"totalItems":   0,
				"orderedItems": []any{},
			})
			return
		}

		http.NotFound(w, r)
	}))
}
