# go-jmapap

ActivityPub relay with a JMAP API. Bridges fediverse federation to a JMAP API consumed by [biset](https://github.com/yno9/biset) or any JMAP client — the sister of [go-jmapsmtp](https://github.com/yno9/go-jmapsmtp), which does the same for mail.

One binary, three roles:

1. **JMAP server** — mailbox storage biset clients read and write. Embeds [go-jmapserver](https://github.com/yno9/go-jmapserver).
2. **ActivityPub actor** — each account `localpart@domain` is a fediverse actor at `https://domain/localpart`, federating with Mastodon and friends.
3. **Static web serving** (optional, when `web_root` is set) — serves biset's single-file HTML app from the apex.

`/<localpart>[/]` uses **content negotiation** to tell the two apart: an actor document for the fediverse, a user page for browsers.

The two relays share **no state, only libraries** — there is no core server. Their only shared contracts are the cryptenv envelope and the optional identity anchor.

## Features

- JMAP Core + Mail (`urn:ietf:params:jmap:*`), multi-account, multi-domain
- ActivityPub federation — WebFinger, actor documents, inbox/outbox, followers/following, HTTP Signatures
- KEK-based auth: Argon2id + AES-GCM + HKDF (`cryptenv/`), shared with jmapsmtp
- Optional `did:dht` identity — provisioning with a signed DID→relay binding, claimed via the identity anchor when one is configured
- Optional Pkarr/BEP44 DHT gateway (`PKARR_GATEWAY=1`), so browsers — which can't speak the DHT — resolve and publish through a relay that already sees their traffic
- Web push (VAPID) and SSE for live updates
- Prometheus `/metrics`

DID is layered on, never required: provision without `did`/`did_sig` and you get a plain JMAP account. Leave `anchor_url` unset and the relay runs "anchorless".

## Build

```sh
go build -o jmapap .
```

## Config

Copy `config.example.json` to `config.json` next to the binary:

```json
{
  "listen_addr": "0.0.0.0:8768",
  "base_url": "https://biset.md",
  "hostname": "biset.md",
  "vapid_public_key": "",
  "vapid_private_key": "",
  "domain": {
    "biset.md": { "account": {} }
  }
}
```

`config.json` is gitignored — it holds keys.

## Architecture

See [`ARC.md`](ARC.md) for the request flow, the ActivityPub↔JMAP mapping, content negotiation, and the identity/anchor design.
