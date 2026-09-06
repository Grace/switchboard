// Package approval records who authorised the configuration a gateway runs.
//
// The policy archive answers "what were the rules". This answers the question
// underneath it: was anybody supposed to have changed them. A gateway that
// records every configuration it ever ran, and cannot say which of them anyone
// agreed to, has a history rather than a control.
//
// An approval is an Ed25519 signature over a policy fingerprint. Because the
// fingerprint is itself the digest of the policy document, signing it binds the
// approval to the exact bytes: an approval cannot be moved onto a configuration
// nobody looked at.
//
// The gateway holds public keys only — the same shape as the vault, and for the
// same reason. A signature the serving process could produce is not evidence
// that anyone else agreed to anything, so the private half lives with whoever
// approves changes and never on the machine whose changes are being approved.
//
// # Approved before, not approved eventually
//
// The control is that a change was authorised *before deployment*, so an
// approval carries its own signing time and the report compares it against the
// first entry served under that policy. A signature added after the fact is
// recorded as exactly that. It is a real thing to know — somebody did review
// it — and it is not the control, and collapsing the two would turn this into
// a box that is always ticked eventually.
package approval

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Suffix is the file written beside an archived policy document.
const Suffix = ".approvals"

// Approval is one signed statement that a named person approved a policy.
type Approval struct {
	Fingerprint string    `json:"fingerprint"`
	Approver    string    `json:"approver"`
	Signed      time.Time `json:"signed"`
	Note        string    `json:"note,omitempty"`
	// Signature is base64 Ed25519 over the canonical bytes of the four fields
	// above. The time is inside the signature, so a stored approval cannot be
	// backdated without invalidating itself.
	Signature string `json:"signature"`
}

// signed is the exact shape the signature covers.
//
// Its own type rather than a re-marshal of Approval, because Approval carries
// the signature and a struct cannot sign itself. Go marshals struct fields in
// declaration order, so these bytes are stable across processes and versions —
// the same property the policy fingerprint relies on.
type signed struct {
	Fingerprint string `json:"fingerprint"`
	Approver    string `json:"approver"`
	Signed      string `json:"signed"`
	Note        string `json:"note,omitempty"`
}

func (a Approval) payload() ([]byte, error) {
	// RFC3339 with nanoseconds, in UTC. Marshalling a time.Time directly would
	// work, but pinning the format here means a change to Go's time encoding
	// cannot silently invalidate every signature already written.
	return json.Marshal(signed{
		Fingerprint: a.Fingerprint,
		Approver:    a.Approver,
		Signed:      a.Signed.UTC().Format(time.RFC3339Nano),
		Note:        a.Note,
	})
}

// Sign produces an approval for a fingerprint.
func Sign(fingerprint, approver, note string, key ed25519.PrivateKey, now time.Time) (Approval, error) {
	if fingerprint == "" {
		return Approval{}, errors.New("approval: no fingerprint to sign")
	}
	if approver == "" {
		return Approval{}, errors.New("approval: an approval needs a named approver, " +
			"because the control is that somebody agreed and not that something was signed")
	}
	if len(key) != ed25519.PrivateKeySize {
		return Approval{}, errors.New("approval: not an Ed25519 private key")
	}
	a := Approval{Fingerprint: fingerprint, Approver: approver, Signed: now.UTC(), Note: note}
	payload, err := a.payload()
	if err != nil {
		return Approval{}, err
	}
	a.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key, payload))
	return a, nil
}

// Verify checks an approval against a roster of public keys, by approver name.
func (a Approval) Verify(roster map[string]ed25519.PublicKey) error {
	pub, ok := roster[a.Approver]
	if !ok {
		return fmt.Errorf("no approver named %q is configured, so this signature cannot be "+
			"checked against anything", a.Approver)
	}
	sig, err := base64.StdEncoding.DecodeString(a.Signature)
	if err != nil {
		return fmt.Errorf("approval by %s: signature is not base64", a.Approver)
	}
	payload, err := a.payload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, payload, sig) {
		return fmt.Errorf("approval by %s does not verify: either it was edited after "+
			"signing, or it was signed by a different key than the one configured", a.Approver)
	}
	return nil
}

// Record appends an approval to the file for its fingerprint.
//
// Append-only and deduplicated, so re-running an approval is a no-op and an
// earlier approver's signature is never displaced by a later one's. Two
// approvers signing the same policy is the point of a minimum above one.
func Record(dir string, a Approval) error {
	if a.Fingerprint == "" {
		return errors.New("approval: no fingerprint")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	existing, err := Load(dir, a.Fingerprint)
	if err != nil {
		return err
	}
	for _, have := range existing {
		if have.Approver == a.Approver && have.Signature == a.Signature {
			return nil
		}
	}
	line, err := json.Marshal(a)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path(dir, a.Fingerprint), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(append(line, '\n'))
	return err
}

func path(dir, fingerprint string) string {
	return filepath.Join(dir, filepath.Base(fingerprint)+Suffix)
}

// Load reads the approvals recorded for a fingerprint, verified or not.
//
// Verification is a separate step on purpose: a signature that does not check
// out is a finding, and a loader that silently dropped it would turn a tampered
// approval into a missing one.
func Load(dir, fingerprint string) ([]Approval, error) {
	if fingerprint == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path(dir, fingerprint))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Approval
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var a Approval
		if err := json.Unmarshal([]byte(line), &a); err != nil {
			return nil, fmt.Errorf("approvals for %s: %w", fingerprint, err)
		}
		out = append(out, a)
	}
	return out, nil
}

// State is what can be said about one policy's authorisation.
type State string

const (
	// Approved: enough valid signatures, all of them before the policy served
	// its first request.
	Approved State = "approved"
	// Late: enough valid signatures, at least one added after this policy was
	// already serving. Somebody did review it; nobody authorised it in advance.
	Late State = "approved late"
	// Unapproved: no valid signature, or fewer than the minimum.
	Unapproved State = "unapproved"
	// Unverifiable: signatures exist and no configured key can check them.
	// Distinct from unapproved, because "nobody signed this" and "we cannot
	// tell who signed this" are different findings with different fixes.
	Unverifiable State = "unverifiable"
	// NotInForce: change control is off, so nothing is claimed either way.
	NotInForce State = "not in force"
)

// Status is one policy's authorisation, as far as it can be established.
type Status struct {
	Fingerprint string   `json:"fingerprint"`
	State       State    `json:"state"`
	Approvers   []string `json:"approvers,omitempty"`
	// FirstServed is the earliest entry served under this policy, where a log
	// was consulted. Zero means the comparison could not be made, and Late is
	// never claimed without it.
	FirstServed time.Time `json:"first_served,omitempty"`
	// LateBy names the approvals signed after FirstServed.
	LateBy []string `json:"late_by,omitempty"`
	// Problems are signatures that did not check out, in their own words.
	Problems []string `json:"problems,omitempty"`
	Minimum  int      `json:"minimum"`
	Valid    int      `json:"valid"`
}

// Check reports the authorisation state of one policy.
//
// firstServed is the earliest moment this policy was in force, or the zero time
// where that is unknown. Without it a late approval cannot be distinguished
// from a timely one, and this reports the weaker claim rather than guessing.
func Check(dir, fingerprint string, roster map[string]ed25519.PublicKey, minimum int, firstServed time.Time) (Status, error) {
	if minimum < 1 {
		minimum = 1
	}
	st := Status{Fingerprint: fingerprint, Minimum: minimum, FirstServed: firstServed}
	if len(roster) == 0 {
		st.State = NotInForce
		return st, nil
	}
	all, err := Load(dir, fingerprint)
	if err != nil {
		return st, err
	}

	seen := map[string]bool{}
	for _, a := range all {
		if err := a.Verify(roster); err != nil {
			st.Problems = append(st.Problems, err.Error())
			continue
		}
		// One approver's signature counts once however many times it appears,
		// or a minimum of two could be met by one person signing twice.
		if seen[a.Approver] {
			continue
		}
		seen[a.Approver] = true
		st.Valid++
		st.Approvers = append(st.Approvers, a.Approver)
		if !firstServed.IsZero() && a.Signed.After(firstServed) {
			st.LateBy = append(st.LateBy, a.Approver)
		}
	}
	sort.Strings(st.Approvers)
	sort.Strings(st.LateBy)

	switch {
	case st.Valid >= minimum && len(st.LateBy) > 0:
		st.State = Late
	case st.Valid >= minimum:
		st.State = Approved
	case st.Valid == 0 && len(st.Problems) > 0:
		st.State = Unverifiable
	default:
		st.State = Unapproved
	}
	return st, nil
}

// Met reports whether this status satisfies the control as written: authorised
// before deployment.
func (s Status) Met() bool { return s.State == Approved }

// GenerateKey makes an approver keypair.
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	return ed25519.GenerateKey(rand.Reader)
}

// EncodePublic renders a public key as the one line that goes in the config.
//
// Inline rather than a path, so the policy fingerprint covers the key material
// itself. A roster held as filenames would let somebody swap the file behind a
// name without the configuration changing, which is the one substitution this
// whole mechanism exists to make visible.
func EncodePublic(pub ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// DecodePublic reads the config's one-line form.
func DecodePublic(s string) (ed25519.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("public key is not base64: %w", err)
	}
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	pub, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is %T, not Ed25519", key)
	}
	return pub, nil
}

// WritePrivateKey stores an approver's private key as PEM, readable only by its
// owner.
func WritePrivateKey(path string, priv ed25519.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	// 0600 from the moment it exists. This key is the only thing standing
	// between the gateway's operator and the ability to approve their own
	// changes, and a mode set after the write leaves a window.
	return os.WriteFile(path, block, 0o600)
}

// LoadPrivateKey reads an approver's key.
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: not PEM", path)
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%s holds %T, not an Ed25519 private key", path, key)
	}
	return priv, nil
}
