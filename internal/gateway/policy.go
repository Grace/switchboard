package gateway

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

var identifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)

type Route struct {
	Provider string `json:"provider"`
	Model    string `json:"model"`
}
type Policy struct {
	Schema    int     `json:"schema"`
	Tenant    string  `json:"tenant"`
	Version   int64   `json:"version"`
	IssuedAt  int64   `json:"issued_at"`
	ExpiresAt int64   `json:"expires_at"`
	Routes    []Route `json:"routes"`
}
type Envelope struct {
	KeyID     string `json:"key_id"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}
type PolicyStore struct {
	mu           sync.RWMutex
	current      *Policy
	raw          []byte
	Tenant, Path string
	Keys         map[string]ed25519.PublicKey
}

func strictJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

// Canonical policy format v1: ASCII identifiers, integer fields, sorted object keys,
// no whitespace; arrays preserve order. This is a deliberately restricted JCS subset.
func Canonical(p Policy) []byte {
	routes := make([]any, 0, len(p.Routes))
	for _, r := range p.Routes {
		routes = append(routes, map[string]any{"model": r.Model, "provider": r.Provider})
	}
	b, _ := json.Marshal(map[string]any{"schema": p.Schema, "tenant": p.Tenant, "version": p.Version, "issued_at": p.IssuedAt, "expires_at": p.ExpiresAt, "routes": routes})
	return b
}
func (s *PolicyStore) Verify(raw []byte, now time.Time) (*Policy, error) {
	return s.verify(raw, now, false)
}

// policySchema is the policy document schema this build can verify. verify()
// rejects anything else outright, which is correct -- a signature over a
// document you cannot parse is worth nothing -- and is precisely why the poller
// sends this to the control plane. A gateway that silently refused every new
// policy would keep serving its cached copy and go 503 when it expired, up to
// seven days after the publish, across the whole fleet at once.
const policySchema = 1

// schemaSupported reports whether this build can verify a policy of this schema.
//
// It is a range, not an equality, and the difference is a fleet outage. The
// gateway advertises its ceiling as GET /v1/policy?max_schema=policySchema
// (see Sync in server.go), and the control plane honours that as a ceiling:
// "WHERE tenant_id=%s AND schema<=%s ORDER BY version DESC LIMIT 1"
// (controlplane/app.py). So a build with policySchema = 2 asks for "2 or lower"
// and is legitimately served a tenant's newest schema-1 policy.
//
// The check here used to be p.Schema != policySchema, which refused exactly that
// document. Every gateway in a fleet would have kept serving its cached copy and
// gone 503 when that expired, up to seven days after the publish -- which is
// precisely the delayed, silent, fleet-wide outage the max_schema mechanism was
// built to prevent. Not reachable yet only because controlplane/policy.py
// refuses to sign anything but schema 1.
//
// Strict on write, permissive downward on read. The asymmetry is deliberate:
// signing an unknown schema is a mistake, verifying an older one is the job.
//
// When a schema 2 does ship, Canonical() must dispatch on p.Schema before this
// can accept both, because it hand-enumerates one field set and verify()
// requires bytes.Equal(b, Canonical(p)).
//
// The ceiling is a parameter rather than a direct read of policySchema so the
// range behaviour is testable today. With policySchema at 1 a range and an
// equality are indistinguishable, so a test that could not vary the ceiling
// could not tell the fix from the bug.
func schemaSupported(n, ceiling int) bool { return n >= 1 && n <= ceiling }

func (s *PolicyStore) verify(raw []byte, now time.Time, allowExpired bool) (*Policy, error) {
	var e Envelope
	if len(raw) > 65536 || strictJSON(raw, &e) != nil {
		return nil, errors.New("invalid envelope")
	}
	key, ok := s.Keys[e.KeyID]
	if !ok || !identifier.MatchString(e.KeyID) {
		return nil, errors.New("untrusted signing key")
	}
	b, err := base64.StdEncoding.Strict().DecodeString(e.Payload)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(e.Signature)
	if err != nil {
		return nil, err
	}
	if !ed25519.Verify(key, append([]byte("switchboard-policy-v1\n"+e.KeyID+"\n"), b...), sig) {
		return nil, errors.New("invalid signature")
	}
	var p Policy
	if strictJSON(b, &p) != nil || !bytes.Equal(b, Canonical(p)) {
		return nil, errors.New("noncanonical policy")
	}
	if !schemaSupported(p.Schema, policySchema) || p.Tenant != s.Tenant || !identifier.MatchString(p.Tenant) || p.Version < 1 || p.Version > 9007199254740991 || p.IssuedAt > now.Unix()+60 || p.IssuedAt < 1 || (!allowExpired && p.ExpiresAt <= now.Unix()) || p.ExpiresAt <= p.IssuedAt || p.ExpiresAt-p.IssuedAt > 604800 || len(p.Routes) < 1 || len(p.Routes) > 4 {
		return nil, errors.New("invalid policy constraints")
	}
	seen := map[string]bool{}
	for _, r := range p.Routes {
		if (r.Provider != "openai" && r.Provider != "anthropic" && r.Provider != "gemini" && r.Provider != "bedrock") || !identifier.MatchString(r.Model) || seen[r.Provider] {
			return nil, errors.New("invalid route")
		}
		seen[r.Provider] = true
	}
	return &p, nil
}

// Restore retains the authenticated version high-water mark even after expiry.
// Readiness remains false until a newer valid policy is synchronized.
func (s *PolicyStore) Restore(raw []byte) error {
	p, e := s.verify(raw, time.Now(), true)
	if e != nil {
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.current = p
	s.raw = append([]byte(nil), raw...)
	return nil
}
func (s *PolicyStore) Apply(raw []byte, persist bool) error {
	p, err := s.Verify(raw, time.Now())
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current != nil {
		if p.Version < s.current.Version {
			return errors.New("policy rollback")
		}
		if p.Version == s.current.Version {
			if !bytes.Equal(Canonical(*p), Canonical(*s.current)) {
				return errors.New("version equivocation")
			}
			return nil
		}
	}
	if persist {
		if err := atomicFile(s.Path, raw); err != nil {
			return err
		}
	}
	s.current = p
	s.raw = append([]byte(nil), raw...)
	return nil
}
func (s *PolicyStore) Current() *Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil || s.current.ExpiresAt <= time.Now().Unix() {
		return nil
	}
	p := *s.current
	p.Routes = append([]Route(nil), p.Routes...)
	return &p
}

// Expired reports whether a policy is cached but past its expiry. Distinct from
// Current() == nil, which is also true when none was ever loaded, and the two
// have entirely different remedies: publish a policy, versus find out why this
// gateway stopped being able to fetch one. Without the distinction both present
// as the same empty 503.
func (s *PolicyStore) Expired() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.current != nil && s.current.ExpiresAt <= time.Now().Unix()
}

// ExpiresAt is the loaded policy's expiry, or 0 when none was ever loaded.
// Unlike Current() it keeps answering after expiry, which is the whole point:
// "expired eleven hours ago" and "never had one" need different answers and
// Current() collapses them both to nil.
func (s *PolicyStore) ExpiresAt() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.current == nil {
		return 0
	}
	return s.current.ExpiresAt
}

func atomicFile(path string, b []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".pending-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
