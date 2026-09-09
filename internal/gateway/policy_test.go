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

// The contract between three files, stated once so it cannot drift again. The
// gateway asks the control plane for max_schema=policySchema; the control plane
// answers with the newest policy at or *below* that ceiling; so the verifier
// must accept the whole range it advertises, not just its own version.
//
// The ceiling is passed in rather than read from policySchema precisely so this
// test can vary it. At policySchema = 1 a range and an equality behave
// identically, so a test pinned to today's value could not tell the fix from the
// bug it replaces -- the {schema 1, ceiling 2} row is the whole point.
func TestSchemaSupportedAcceptsTheRangeItAdvertises(t *testing.T) {
	for _, tc := range []struct {
		schema, ceiling int
		want            bool
	}{
		{1, 2, true},  // the case the bug got wrong: a newer gateway, an older policy
		{1, 3, true},  // and however far apart they drift
		{2, 2, true},  // its own version
		{1, 1, true},  // today
		{3, 2, false}, // newer than this build can parse; refuse, do not guess
		{2, 1, false},
		{0, 1, false}, // not a schema, and never signed
		{-1, 1, false},
	} {
		if got := schemaSupported(tc.schema, tc.ceiling); got != tc.want {
			t.Errorf("schemaSupported(schema=%d, ceiling=%d) = %v, want %v",
				tc.schema, tc.ceiling, got, tc.want)
		}
	}
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

// The signing tool is Python and the verifier is Go, so the canonical byte
// encoding is a contract between two languages with nothing but this test
// holding them together. It is checked in as a fixture rather than generated,
// because a drift in either canonicaliser should fail here rather than be
// silently reproduced on both sides.
//
// Regenerate with, using the test seed below:
//
//	SWITCHBOARD_POLICY_SEED=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8= \
//	  python -m controlplane.policytool --tenant acme-prod --key-id key-2026-09 \
//	  --route openai:gpt-4o-mini --route anthropic:claude-haiku-4-5-20251001 \
//	  --out testdata/policytool-envelope.json
func TestGoVerifierAcceptsPythonSignedPolicy(t *testing.T) {
	pub, err := base64.StdEncoding.DecodeString("A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("../../testdata/policytool-envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	s := &PolicyStore{Tenant: "acme-prod", Keys: map[string]ed25519.PublicKey{"key-2026-09": pub}}
	// Pinned inside the fixture's lifetime; a wall-clock check would start
	// failing a week after the fixture was written and say nothing useful.
	p, err := s.Verify(raw, time.Unix(1788845812+60, 0))
	if err != nil {
		t.Fatalf("Go rejected a policy signed by controlplane.policytool: %v", err)
	}
	if len(p.Routes) != 2 || p.Routes[0].Provider != "openai" || p.Routes[1].Provider != "anthropic" {
		t.Fatalf("routes did not survive the round trip: %+v", p.Routes)
	}
}
