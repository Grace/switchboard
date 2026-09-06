package approval

import (
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

func at(day int) time.Time {
	return time.Date(2026, 9, day, 12, 0, 0, 0, time.UTC)
}

func keyed(t *testing.T, name string) (map[string]ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return map[string]ed25519.PublicKey{name: pub}, priv
}

func TestASignatureVerifiesAgainstItsOwnKeyAndNoOther(t *testing.T) {
	roster, priv := keyed(t, "grace")
	a, err := Sign("4f4c581392f8", "grace", "quarterly review", priv, at(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Verify(roster); err != nil {
		t.Fatalf("a signature this package just made does not verify: %v", err)
	}

	other, _ := keyed(t, "grace")
	if err := a.Verify(other); err == nil {
		t.Fatal("an approval verified against a different key under the same name")
	}
}

// The gateway holds public keys only, so the serving process cannot produce a
// signature. That is the whole reason an approval evidences anything.
func TestVerificationNeedsNoPrivateKey(t *testing.T) {
	pub, priv, _ := GenerateKey()
	a, _ := Sign("abc123", "grace", "", priv, at(1))
	// Only the public half, which is all a config ever carries.
	if err := a.Verify(map[string]ed25519.PublicKey{"grace": pub}); err != nil {
		t.Fatal(err)
	}
}

// Every signed field is inside the signature, the timestamp included — or a
// stored approval could be backdated to make a late one look timely.
func TestEditingAnyFieldBreaksTheSignature(t *testing.T) {
	roster, priv := keyed(t, "grace")
	orig, _ := Sign("4f4c581392f8", "grace", "reviewed", priv, at(10))

	for name, edit := range map[string]func(Approval) Approval{
		"fingerprint": func(a Approval) Approval { a.Fingerprint = "aaaaaaaaaaaa"; return a },
		"approver":    func(a Approval) Approval { a.Approver = "someone-else"; return a },
		"time":        func(a Approval) Approval { a.Signed = at(1); return a },
		"note":        func(a Approval) Approval { a.Note = "reviewed thoroughly"; return a },
	} {
		if err := edit(orig).Verify(roster); err == nil {
			t.Errorf("editing %s left the approval verifying", name)
		}
	}
}

// An approval names one policy. Moving it onto another is how a signature for a
// reviewed configuration ends up covering one nobody looked at.
func TestAnApprovalDoesNotTransferToAnotherPolicy(t *testing.T) {
	dir := t.TempDir()
	roster, priv := keyed(t, "grace")
	a, _ := Sign("aaaaaaaaaaaa", "grace", "", priv, at(1))
	// Filed under a different fingerprint by hand.
	a.Fingerprint = "bbbbbbbbbbbb"
	if err := Record(dir, a); err != nil {
		t.Fatal(err)
	}
	st, err := Check(dir, "bbbbbbbbbbbb", roster, 1, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	if st.State != Unverifiable {
		t.Fatalf("state = %s, want the moved signature refused", st.State)
	}
}

// The control is authorisation *before* deployment. A signature added after the
// policy was already serving is a real thing to know and is not the control.
func TestApprovalAfterTheFactIsRecordedAsLate(t *testing.T) {
	dir := t.TempDir()
	roster, priv := keyed(t, "grace")
	a, _ := Sign("4f4c581392f8", "grace", "", priv, at(20))
	if err := Record(dir, a); err != nil {
		t.Fatal(err)
	}

	// Served from the 10th; signed on the 20th.
	st, _ := Check(dir, "4f4c581392f8", roster, 1, at(10))
	if st.State != Late {
		t.Fatalf("state = %s, want %s", st.State, Late)
	}
	if st.Met() {
		t.Error("a policy approved after it was already serving reported the control met")
	}
	if len(st.LateBy) != 1 || st.LateBy[0] != "grace" {
		t.Errorf("late_by = %v", st.LateBy)
	}

	// Signed on the 20th, served from the 25th: authorised in advance.
	st, _ = Check(dir, "4f4c581392f8", roster, 1, at(25))
	if st.State != Approved || !st.Met() {
		t.Fatalf("state = %s", st.State)
	}
}

// Without knowing when the policy first served, lateness cannot be established.
// Claiming it anyway would invent a finding out of a missing timestamp.
func TestLatenessIsNotClaimedWithoutAServingTime(t *testing.T) {
	dir := t.TempDir()
	roster, priv := keyed(t, "grace")
	a, _ := Sign("4f4c581392f8", "grace", "", priv, at(20))
	Record(dir, a)

	st, _ := Check(dir, "4f4c581392f8", roster, 1, time.Time{})
	if st.State != Approved {
		t.Fatalf("state = %s, want the weaker claim rather than a guess", st.State)
	}
	if len(st.LateBy) != 0 {
		t.Errorf("late_by = %v with no serving time to compare against", st.LateBy)
	}
}

// A minimum of two exists because one person editing and signing is approving
// their own change. One person signing twice must not satisfy it.
func TestOneApproverCannotMeetAMinimumOfTwo(t *testing.T) {
	dir := t.TempDir()
	roster, priv := keyed(t, "grace")
	first, _ := Sign("4f4c581392f8", "grace", "one", priv, at(1))
	second, _ := Sign("4f4c581392f8", "grace", "two", priv, at(2))
	Record(dir, first)
	Record(dir, second)

	st, _ := Check(dir, "4f4c581392f8", roster, 2, time.Time{})
	if st.Valid != 1 {
		t.Errorf("valid = %d, want one approver counted once", st.Valid)
	}
	if st.State != Unapproved {
		t.Fatalf("state = %s, want %s", st.State, Unapproved)
	}
}

// Two people signing is what a minimum of two is for, and the second signature
// must not displace the first.
func TestASecondApproverIsAppendedNotSubstituted(t *testing.T) {
	dir := t.TempDir()
	pubA, privA, _ := GenerateKey()
	pubB, privB, _ := GenerateKey()
	roster := map[string]ed25519.PublicKey{"grace": pubA, "sam": pubB}

	a, _ := Sign("4f4c581392f8", "grace", "", privA, at(1))
	b, _ := Sign("4f4c581392f8", "sam", "", privB, at(2))
	Record(dir, a)
	Record(dir, b)

	st, _ := Check(dir, "4f4c581392f8", roster, 2, at(5))
	if st.State != Approved || st.Valid != 2 {
		t.Fatalf("state = %s, valid = %d, approvers = %v", st.State, st.Valid, st.Approvers)
	}
}

// Re-running an approval is a no-op rather than a second row.
func TestRecordingTheSameApprovalTwiceIsANoOp(t *testing.T) {
	dir := t.TempDir()
	_, priv := keyed(t, "grace")
	a, _ := Sign("4f4c581392f8", "grace", "", priv, at(1))
	Record(dir, a)
	Record(dir, a)

	all, err := Load(dir, "4f4c581392f8")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("want 1 stored approval, got %d", len(all))
	}
}

// "Nobody signed this" and "we cannot tell who signed this" are different
// findings with different fixes, and collapsing them loses the second.
func TestUnverifiableIsDistinctFromUnapproved(t *testing.T) {
	dir := t.TempDir()
	_, stranger := keyed(t, "stranger")
	a, _ := Sign("4f4c581392f8", "stranger", "", stranger, at(1))
	Record(dir, a)

	roster, _ := keyed(t, "grace")
	st, _ := Check(dir, "4f4c581392f8", roster, 1, time.Time{})
	if st.State != Unverifiable {
		t.Fatalf("state = %s, want %s", st.State, Unverifiable)
	}
	if len(st.Problems) != 1 || !strings.Contains(st.Problems[0], "stranger") {
		t.Errorf("problems = %v", st.Problems)
	}

	// And an empty archive is unapproved, which is the other one.
	empty, _ := Check(t.TempDir(), "4f4c581392f8", roster, 1, time.Time{})
	if empty.State != Unapproved {
		t.Errorf("state = %s, want %s", empty.State, Unapproved)
	}
}

// With change control off, nothing is claimed either way. Reporting every past
// policy as unapproved would be a finding manufactured from a feature nobody
// switched on.
func TestNoRosterMeansNothingIsClaimed(t *testing.T) {
	st, _ := Check(t.TempDir(), "4f4c581392f8", nil, 1, time.Time{})
	if st.State != NotInForce {
		t.Fatalf("state = %s, want %s", st.State, NotInForce)
	}
	if st.Met() {
		t.Error("a deployment with no change control reported the control met")
	}
}

// The config carries the key inline, so this round trip is the config format.
func TestPublicKeyRoundTripsThroughTheConfigForm(t *testing.T) {
	pub, _, _ := GenerateKey()
	line, err := EncodePublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	back, err := DecodePublic(line)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Equal(pub) {
		t.Fatal("the key did not survive the config form")
	}
	if _, err := DecodePublic("not-a-key"); err == nil {
		t.Error("garbage was accepted as a public key")
	}
}

func TestPrivateKeyRoundTripsAndIsOwnerOnly(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := GenerateKey()
	path := dir + "/approver.key"
	if err := WritePrivateKey(path, priv); err != nil {
		t.Fatal(err)
	}
	back, err := LoadPrivateKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Equal(priv) {
		t.Fatal("the private key did not round trip")
	}
}

// An approval with no named approver is a signature, not an authorisation.
func TestAnApprovalNeedsANamedApprover(t *testing.T) {
	_, priv := keyed(t, "grace")
	if _, err := Sign("4f4c581392f8", "", "", priv, at(1)); err == nil {
		t.Fatal("an unnamed approval was signed")
	}
}
