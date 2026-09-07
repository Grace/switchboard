package gateway

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func signed(t *testing.T, p Policy, key ed25519.PrivateKey, kid string) []byte {
	t.Helper()
	b := Canonical(p)
	return jsonBytes(Envelope{KeyID: kid, Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte("switchboard-policy-v1\n"+kid+"\n"), b...)))})
}
func testPolicy() Policy {
	return Policy{Schema: 1, Tenant: "tenant-a", Version: 1, IssuedAt: time.Now().Unix() - 1, ExpiresAt: time.Now().Unix() + 3600, Routes: []Route{{"openai", "test-model"}, {"anthropic", "test-model"}, {"gemini", "test-model"}}}
}
func TestPolicyTrustAndRollback(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	pub2, key2, _ := ed25519.GenerateKey(rand.Reader)
	s := &PolicyStore{Tenant: "tenant-a", Path: filepath.Join(t.TempDir(), "policy.json"), Keys: map[string]ed25519.PublicKey{"old": pub, "new": pub2}}
	p := testPolicy()
	b := signed(t, p, key, "old")
	if e := s.Apply(b, true); e != nil {
		t.Fatal(e)
	}
	fresh := &PolicyStore{Tenant: s.Tenant, Path: s.Path, Keys: s.Keys}
	cached, _ := os.ReadFile(s.Path)
	if e := fresh.Apply(cached, false); e != nil {
		t.Fatal(e)
	}
	p.Version = 2
	if e := s.Apply(signed(t, p, key2, "new"), true); e != nil {
		t.Fatal(e)
	}
	if s.Apply(b, true) == nil {
		t.Fatal("rollback accepted")
	}
	p.Routes[0].Model = "other"
	if s.Apply(signed(t, p, key2, "new"), false) == nil {
		t.Fatal("equivocation accepted")
	}
	delete(s.Keys, "new")
	if s.Apply(signed(t, p, key2, "new"), false) == nil {
		t.Fatal("revoked key accepted")
	}
}
func TestPolicyRejectsMalformed(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	s := &PolicyStore{Tenant: "tenant-a", Keys: map[string]ed25519.PublicKey{"k": pub}}
	for _, name := range []string{"tenant", "expired", "future", "lifetime", "provider", "unicode", "duplicate", "version"} {
		t.Run(name, func(t *testing.T) {
			p := testPolicy()
			switch name {
			case "tenant":
				p.Tenant = "tenant-b"
			case "expired":
				p.ExpiresAt = 1
			case "future":
				p.IssuedAt = time.Now().Unix() + 600
			case "lifetime":
				p.ExpiresAt += 604800
			case "provider":
				p.Routes[0].Provider = "evil"
			case "unicode":
				p.Routes[0].Model = "mödél"
			case "duplicate":
				p.Routes[1] = p.Routes[0]
			case "version":
				p.Version = 0
			}
			if _, e := s.Verify(signed(t, p, key, "k"), time.Now()); e == nil {
				t.Fatal("accepted invalid policy")
			}
		})
	}
}
func TestPolicyCanonicalTampering(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	s := &PolicyStore{Tenant: "tenant-a", Keys: map[string]ed25519.PublicKey{"k": pub}}
	p := testPolicy()
	for _, b := range [][]byte{append([]byte(" "), Canonical(p)...), bytes.Replace(Canonical(p), []byte(`"schema":1`), []byte(`"schema":1,"schema":1`), 1)} {
		e := Envelope{KeyID: "k", Payload: base64.StdEncoding.EncodeToString(b), Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, append([]byte("switchboard-policy-v1\nk\n"), b...)))}
		if _, err := s.Verify(jsonBytes(e), time.Now()); err == nil {
			t.Fatal("noncanonical accepted")
		}
	}
	var e Envelope
	json.Unmarshal(signed(t, p, key, "k"), &e)
	e.Payload = base64.StdEncoding.EncodeToString([]byte(`{}`))
	if _, err := s.Verify(jsonBytes(e), time.Now()); err == nil {
		t.Fatal("tampering accepted")
	}
}
func TestCrossLanguageFixture(t *testing.T) {
	b, e := os.ReadFile("../../testdata/policy-envelope.json")
	if e != nil {
		t.Fatal(e)
	}
	pub, e := os.ReadFile("../../testdata/public-key.txt")
	if e != nil {
		t.Fatal(e)
	}
	key, e := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(pub)))
	if e != nil {
		t.Fatal(e)
	}
	s := &PolicyStore{Tenant: "fixture", Keys: map[string]ed25519.PublicKey{"fixture": key}}
	if _, e = s.Verify(b, time.Unix(1800000000, 0)); e != nil {
		t.Fatal(e)
	}
}
