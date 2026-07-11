# go-jmapap Architecture Notes

`go-jmapap` is biset's **ActivityPub relay**. One binary, three roles:

1. **JMAP server** — mailbox storage that biset clients read and write. Embeds `go-jmapserver`.
2. **ActivityPub actor** — each account `localpart@domain` acts as a fediverse actor at `https://domain/localpart`.
3. **Static web serving** (when `web_root` is set) — serves the biset single-file HTML app from the apex. `/<localpart>[/]` uses **content negotiation** to distinguish actor documents (fediverse) from user pages (browser). User pages load biset client-side, opening a new AP inbox or showing a profile landing if unauthenticated.

Sister relay `go-jmapsmtp` (mail relay) shares **no state, only libraries** — a no-core design. The only shared contracts are the cryptenv envelope and the identity anchor.

---

## Overview

```
biset (browser, JMAP over HTTP)
   │  JMAP  ─────────────►  go-jmapserver mux  ──►  per-account Store (disk)
   │                                                   │  OnCreate/OnSubmit/OnDestroy hooks
   ▼                                                   ▼
 /auth /account/provision /identity /resolve    ActivityPub send (httpSignedPost)
   │                                                   │
   └──────────────►  fediverse (Mastodon, etc.)  ◄─────┘
        WebFinger / actor doc / inbox (HTTP Signature verified)
```

- Listens on `cfg.ListenAddr` (default `0.0.0.0:8768`). In production: **127.0.0.1:8768**, reverse-proxied by Caddy from the apex.
- Because the apex owns the domain's WebFinger, jmapap also serves as the **identity anchor** (see below).

---

## Account Model

- **primary** = `localpart@domain` (lowercased). Key in `handler.stores`.
- **Static accounts**: declared in `config.json` under `domain.<d>.account.<lp>`. Support aliases. Normally live on `allow_provision: false` domains.
- **Dynamic accounts**: registered at runtime via `POST /account/provision` (`addDynAccount`). Only allowed on `allow_provision: true` domains. Recovered from disk on restart by `scanDynAccounts` (looks for `envelope.json`).
- `provisionDomain()` — returns the single domain with `allow_provision: true`. Returns `""` if none → provision endpoint returns 403.
- All auth paths use **cryptenv envelope**. The password-derived `auth_token` is sent as the Basic auth password (base64-encoded); `env.VerifyAuth(tok)` verifies it. The server never holds the master_secret. JMAP's `cfg.AuthFunc` uses the same envelope verification.

### Disk Layout (`data/<domain>/<localpart>/`)

| File | Contents |
|---|---|
| `envelope.json` | cryptenv envelope (Argon2id + AES-GCM wrapping master_secret). Root of auth |
| `ap-key.pem` | Actor HTTP-signature RSA private key (PKCS#8). Independent of PGP/MLS material |
| `identity.fp` | Identity anchor fingerprint (`SHA-256(envelope canonical bytes)`) |
| `avatar.bin` / `avatar.type` | Avatar image bytes and Content-Type |
| `setup.token` | One-time setup token for static account initialization (consumed by `/auth/signup`) |
| (Store data) | `go-jmapserver` persists mail and mailboxes in the same directory |

---

## Source Files

| File | Responsibility |
|---|---|
| `main.go` | Config, handler, `makeStore` (JMAP hooks), startup, route registration |
| `activitypub.go` | AP core: actor doc, send/receive, follow, HTTP-signed POST, remote actor resolution |
| `httpsig.go` | Inbound HTTP Signature **verification** (fetches and caches actor public keys) |
| `auth_env.go` | Envelope read/write, Basic auth, `/auth/envelope`, `/auth/signup` |
| `provision.go` | `/account/provision` (new account creation); `provisionDomain()`; identity anchor claim |
| `maintenance.go` | Inactive account auto-purge (`lastActivity`, `startMaintenance`, `purgeInactiveAccounts`) |
| `anchor.go` | Identity anchor: name-claim registry, `/identity/<lp>` |
| `avatar.go` | Avatar storage and serving (`/<lp>/avatar` PUT/GET) |
| `cryptenv/` | Envelope implementation (shared library with jmapsmtp) |

---

## config.json

```json
{
  "listen_addr": "0.0.0.0:8768",
  "hostname": "ap.example.com",
  "app_host": "t.example.com",
  "web_root": "../biset/dist",
  "inactive_purge_days": 14,
  "peer_data_dirs": ["/root/jmapsmtp/data"],
  "domain": {
    "example.com": {
      "allow_provision": false,
      "account": {
        "you": { "alias": [] }
      }
    },
    "t.example.com": {
      "allow_provision": true,
      "account": {}
    }
  }
}
```

### Fields

| Field | Purpose |
|---|---|
| `app_host` | Serve the biset HTML only when the request host matches this value (e.g. `t.biset.md`). Empty = serve on all hosts |
| `web_root` | Path to the biset single-file HTML. Relative paths resolve from the binary's directory |
| `inactive_purge_days` | Auto-delete accounts on `allow_provision` domains inactive for this many days across all relays. 0 = disabled |
| `peer_data_dirs` | Sibling relay data directories consulted before purging; account is only purged if all peers are also inactive |
| `domain.<d>.allow_provision` | Enables self-service account creation via `POST /account/provision` |

---

## Domain Model (biset.md production)

| Domain | Role |
|---|---|
| `biset.md` | Static homepage (Caddy serves `home/index.html` directly). Account creation disabled |
| `t.biset.md` | Beta testing. `allow_provision: true`. Serves biset app as `app_host` |
| `ap.biset.md` | jmapap listener (Caddy reverse-proxy → 127.0.0.1:8768) |
| `mail.biset.md` | jmapsmtp listener (SMTP 25 + JMAP 8767). MX for `t.biset.md` |
| `app.biset.md` | Redirects → `t.biset.md` (legacy app host) |

With `app_host: "t.biset.md"`, `GET /` returns the biset HTML only for requests arriving on t.biset.md. The apex (ap.biset.md) is dedicated to actor documents and WebFinger.

---

## JMAP ⇄ ActivityPub Bridge (`makeStore` hooks)

Store operations are mapped to AP activities. **The feeds mailbox is the special follow box.**

- **OnCreateEmail**:
  - Into feeds mailbox → send `Follow`, set `$follow_pending` keyword, record in `followedActors`.
  - Elsewhere → `PutPending` (draft awaiting submission).
- **OnSubmitEmail** → deliver a `Create(Note)` to the recipient actor via `sendToActor`. Set `$seen`, assign MessageID = noteID.
- **OnDestroyEmail** → deleting a feeds record sends `Undo(Follow)` via `sendUnfollow`.

### Receive (`handleInbox`, `POST /<lp>/inbox`)

- All inbound requires **HTTP Signature verification** (`verifyHTTPSignature`). Failure → 401.
- `Accept(Follow)` → promote the matching follow record to `$follow_accepted`.
- `Create(Note)` → strip HTML tags, store as `email.Email`.
  - **public + followed actor** → feeds mailbox, threaded under the follow record.
  - **direct/mention** → regular inbox, leading `@mention` stripped.
- `newTextMessage` builds the same `email.Email` shape as jmapsmtp, so biset-ui renders mail and AP messages identically.

### Actor Document & Profile Propagation

- `buildActorDoc` generates the Person document (publicKey, inbox, icon, etc.). Used by both `GET /<lp>` and `Update(Person)`.
- `sendProfileUpdate`: on avatar change, dispatches `Update(Person)` to all known peers (conversation partners + followed actors). Forces immediate cache refresh on Mastodon etc. (otherwise they may not re-fetch for ~24h).

---

## HTTP Endpoints

| Route | Purpose |
|---|---|
| `/.well-known/webfinger` | acct → actor self link (local accounts only) |
| `GET /` | biset HTML (when `web_root` is set and host matches `app_host`) |
| `GET /<lp>` | **Content negotiation**: `activity+json`/`ld+json` → actor doc; browser (`text/html`) → biset app |
| `GET /<lp>/` | biset HTML (trailing slash always routes to app) |
| `POST /<lp>/inbox` | AP receive (signature verified) |
| `GET /<lp>/outbox\|followers\|following` | Empty OrderedCollections (minimal implementation) |
| `PUT\|GET /<lp>/avatar` | Avatar (PUT requires Basic auth) |
| `/resolve?acct=` | Server-side WebFinger proxy for the composer (avoids browser CORS). Returns ap presence, actor URL, inbox, icon, display name |
| `/relay-info` | Relay display label and color (for biset UI) |
| `/auth/envelope` | GET = fetch envelope (public, password-gated) / PUT = change password |
| `/auth/signup?token=` | Register initial envelope for a static account |
| `/account/provision` | Create a dynamic account (`allow_provision` domains only) |
| `/identity/<lp>` | Identity anchor claim/verify |

---

## Maintenance

`startMaintenance(h)` launches a goroutine that runs `purgeInactiveAccounts` every 6 hours. Does nothing if `inactive_purge_days` is 0.

**Purge criteria** (all must be true):
1. Account is on a domain with `allow_provision: true`
2. Account is not in the static `account` map
3. Newest file mtime in `data/<domain>/<lp>/` is older than `inactive_purge_days`
4. Same check passes for every path in `peer_data_dirs` — account is only purged if the sibling relay is also inactive

An account active on jmapsmtp but idle on jmapap (or vice versa) is **not** purged.

Purge operation: `os.RemoveAll(acctDir)` + evict from `h.stores`, `h.dyn`, `h.apKeys`, `h.aliases` under write lock.

---

## Identity Anchor (split-identity prevention)

**Problem**: In a no-core relay setup, the same `<localpart>` could be registered on mail and AP with **different cryptenv envelopes** (different owners), enabling fediverse impersonation. There is no central authority.

**Solution (approach b, implemented 2026-07-06)**: The apex (this jmapap instance) doubles as a minimal name-claim registry. **No new server required.**

- Key = localpart; value = **envelope fingerprint** = `SHA-256(cryptenv envelope canonical bytes)`. Because biset sends the same envelope to both relays, matching fingerprints = same owner.
- `POST /identity/<lp>` `{fingerprint}`: unclaimed → 201, same fingerprint → 200 (idempotent), **different fingerprint → 409 (split rejected)**.
- `GET /identity/<lp>` returns the current fingerprint or 404.
- Stored in `identity.fp` (first claim wins).
- **On provision**:
  - jmapap calls `claimIdentity` **in-process** (provision.go).
  - jmapsmtp POSTs to `anchor_url` (internal `http://127.0.0.1:8768`); 409 → provision refused.
- **Backfill** (`backfillAnchor`, runs at startup): registers fingerprints for accounts that existed before the anchor was introduced. If jmapsmtp's push detects a pre-existing split: `[anchor] SPLIT DETECTED` log.
- **Fail-closed**: if `anchor_url` is set but unreachable, jmapsmtp returns 503 (provision refused). If empty, single-relay mode — anchor check is skipped. The message delivery path does not depend on the anchor (provision only).

---

## Security Boundary

- **AP delivery provides server-level authenticity only** (actor RSA key HTTP signatures). No message-level E2EE. biset↔biset AP E2EE is planned as **MLS** in the future (RFC 9420, timeline TBD). Mail uses PGP; AP will use MLS.
- The envelope is password-gated, so the public `/auth/envelope` endpoint is safe — the envelope alone is useless without the password (Argon2id + AES-GCM protects master_secret).
- Provisioned usernames must match `^[a-z0-9][a-z0-9_-]{0,30}$`.
- Only one open-registration domain exists (`t.biset.md`). Attempts to provision on static-account domains are blocked: `provisionDomain()` returns `""` → 403.

---

## Build / Deploy

- Cross-compile: `GOOS=linux GOARCH=amd64 go build`.
- Transfer as `.new` via scp → `systemctl stop` → mv → chmod → `systemctl start`. systemd unit `jmapap` (127.0.0.1:8768).
- Production topology (biset.md v1): apex = AP identity, `mail.biset.md` = jmapsmtp, `ap.biset.md` = jmapap. `app_host: "t.biset.md"` routes biset HTML through t.biset.md. See memory `project-relay-topology`.
