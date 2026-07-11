package main

import (
	"crypto/sha256"
	"testing"
)

func TestParseSignatureHeader(t *testing.T) {
	h := `keyId="https://example.com/actor#main-key",algorithm="rsa-sha256",headers="(request-target) date",signature="abc123"`
	fields := parseSignatureHeader(h)

	if fields["keyId"] != "https://example.com/actor#main-key" {
		t.Errorf("keyId = %q", fields["keyId"])
	}
	if fields["algorithm"] != "rsa-sha256" {
		t.Errorf("algorithm = %q", fields["algorithm"])
	}
	if fields["headers"] != "(request-target) date" {
		t.Errorf("headers = %q", fields["headers"])
	}
	if fields["signature"] != "abc123" {
		t.Errorf("signature = %q", fields["signature"])
	}
}

func TestParseSignatureHeaderEmpty(t *testing.T) {
	fields := parseSignatureHeader("")
	if len(fields) != 0 {
		t.Errorf("expected empty map, got %v", fields)
	}
}

func TestParseSignatureHeaderNoEquals(t *testing.T) {
	fields := parseSignatureHeader("keyId,badpart")
	if len(fields) != 0 {
		t.Errorf("expected empty map for no-equals parts, got %v", fields)
	}
}

func TestParseSignatureHeaderUnquoted(t *testing.T) {
	fields := parseSignatureHeader("key=value,other=test")
	if fields["key"] != "value" {
		t.Errorf("key = %q", fields["key"])
	}
	if fields["other"] != "test" {
		t.Errorf("other = %q", fields["other"])
	}
}

func TestSha256Sum(t *testing.T) {
	data := []byte("hello world")
	got := sha256Sum(data)
	want := sha256.Sum256(data)
	if len(got) != 32 {
		t.Errorf("len = %d, want 32", len(got))
	}
	for i, b := range got {
		if b != want[i] {
			t.Errorf("byte %d: got %x, want %x", i, b, want[i])
		}
	}
}

func TestSha256SumEmpty(t *testing.T) {
	got := sha256Sum(nil)
	if len(got) != 32 {
		t.Errorf("len = %d, want 32", len(got))
	}
}

func TestSha256SumDifferent(t *testing.T) {
	a := sha256Sum([]byte("a"))
	b := sha256Sum([]byte("b"))
	for i := range a {
		if a[i] != b[i] {
			return // different — pass
		}
	}
	t.Error("sha256Sum('a') == sha256Sum('b')")
}
