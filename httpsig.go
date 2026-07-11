package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// actorKeyCache caches fetched public keys by keyId URL.
var actorKeyCache sync.Map

var sigHTTPClient = &http.Client{Timeout: 5 * time.Second}

type cachedKey struct {
	key     *rsa.PublicKey
	fetchedAt time.Time
}

const keyCacheTTL = 24 * time.Hour

// verifyHTTPSignature verifies the HTTP Signature header on an incoming request.
func verifyHTTPSignature(r *http.Request, body []byte) error {
	sigHeader := r.Header.Get("Signature")
	if sigHeader == "" {
		return fmt.Errorf("missing Signature header")
	}

	fields := parseSignatureHeader(sigHeader)
	keyID := fields["keyId"]
	headersField := fields["headers"]
	sigB64 := fields["signature"]

	if keyID == "" || sigB64 == "" {
		return fmt.Errorf("incomplete Signature header")
	}

	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	// Build signing string
	headerNames := strings.Fields(headersField)
	if len(headerNames) == 0 {
		headerNames = []string{"date"}
	}
	var parts []string
	for _, h := range headerNames {
		switch h {
		case "(request-target)":
			parts = append(parts, "(request-target): "+strings.ToLower(r.Method)+" "+r.URL.RequestURI())
		case "digest":
			digest := "SHA-256=" + base64.StdEncoding.EncodeToString(sha256Sum(body))
			if got := r.Header.Get("Digest"); got != "" {
				parts = append(parts, "digest: "+got)
			} else {
				parts = append(parts, "digest: "+digest)
			}
		case "host":
			val := r.Host
			if val == "" {
				val = r.Header.Get("Host")
			}
			parts = append(parts, "host: "+val)
		default:
			val := r.Header.Get(http.CanonicalHeaderKey(h))
			parts = append(parts, h+": "+val)
		}
	}
	signingString := strings.Join(parts, "\n")

	pubKey, err := fetchActorKey(keyID)
	if err != nil {
		return fmt.Errorf("fetch key %s: %w", keyID, err)
	}

	h := sha256.Sum256([]byte(signingString))
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, h[:], sig); err != nil {
		return fmt.Errorf("invalid signature: %w", err)
	}
	return nil
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// fetchActorKey fetches the RSA public key for a keyId URL, with caching.
func fetchActorKey(keyID string) (*rsa.PublicKey, error) {
	if v, ok := actorKeyCache.Load(keyID); ok {
		ck := v.(cachedKey)
		if time.Since(ck.fetchedAt) < keyCacheTTL {
			return ck.key, nil
		}
		actorKeyCache.Delete(keyID)
	}

	// keyId is typically actorURL + "#main-key"; fetch the actor document
	actorURL := strings.SplitN(keyID, "#", 2)[0]
	req, err := http.NewRequest("GET", actorURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/activity+json")
	resp, err := sigHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GET %s: %d", actorURL, resp.StatusCode)
	}

	b, _ := io.ReadAll(resp.Body)
	var actor struct {
		PublicKey struct {
			ID           string `json:"id"`
			PublicKeyPem string `json:"publicKeyPem"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal(b, &actor); err != nil {
		return nil, fmt.Errorf("parse actor: %w", err)
	}
	if actor.PublicKey.PublicKeyPem == "" {
		return nil, fmt.Errorf("no publicKeyPem in actor document")
	}

	block, _ := pem.Decode([]byte(actor.PublicKey.PublicKeyPem))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not an RSA public key")
	}

	actorKeyCache.Store(keyID, cachedKey{key: rsaPub, fetchedAt: time.Now()})
	return rsaPub, nil
}

// parseSignatureHeader parses key=value pairs from an HTTP Signature header.
func parseSignatureHeader(h string) map[string]string {
	result := map[string]string{}
	for _, part := range strings.Split(h, ",") {
		part = strings.TrimSpace(part)
		idx := strings.IndexByte(part, '=')
		if idx < 0 {
			continue
		}
		k := strings.TrimSpace(part[:idx])
		v := strings.TrimSpace(part[idx+1:])
		v = strings.Trim(v, `"`)
		result[k] = v
	}
	return result
}
