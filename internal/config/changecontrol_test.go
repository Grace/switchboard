package config

import (
	"strings"
	"testing"

	"github.com/Grace/switchboard/internal/approval"
)

func approver(t *testing.T, name string) Approver {
	t.Helper()
	pub, _, err := approval.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	line, err := approval.EncodePublic(pub)
	if err != nil {
		t.Fatal(err)
	}
	return Approver{Name: name, PublicKey: line}
}

// The property the whole mechanism rests on: adding yourself as an approver is
// itself a change that needs approving. If the roster sat outside the
// fingerprint it would be the one edit that authorises every edit after it.
func TestChangingTheApproverRosterMovesTheFingerprint(t *testing.T) {
	base := Default()
	base.ChangeControl = ChangeControl{Enabled: true, Approvers: []Approver{approver(t, "grace")}}
	before := base.PolicyFingerprint()

	added := *base
	added.ChangeControl.Approvers = append(append([]Approver(nil), base.ChangeControl.Approvers...),
		approver(t, "intruder"))
	if added.PolicyFingerprint() == before {
		t.Fatal("adding an approver left the fingerprint unchanged, so the roster is " +
			"outside what an approval covers")
	}

	// And so does raising or lowering the bar.
	raised := *base
	raised.ChangeControl.Minimum = 1
	raised.ChangeControl.Enabled = true
	lowered := *base
	lowered.ChangeControl.Required = true
	if lowered.PolicyFingerprint() == before {
		t.Error("turning enforcement on did not move the fingerprint")
	}
}

// Substituting the key behind a name is the one change this exists to make
// visible, which is why the key is inline rather than a path.
func TestSwappingAKeyBehindANameMovesTheFingerprint(t *testing.T) {
	base := Default()
	base.ChangeControl = ChangeControl{Enabled: true, Approvers: []Approver{approver(t, "grace")}}
	before := base.PolicyFingerprint()

	swapped := *base
	swapped.ChangeControl.Approvers = []Approver{approver(t, "grace")} // same name, new key
	if swapped.PolicyFingerprint() == before {
		t.Fatal("a different key under the same name produced the same fingerprint")
	}
}

// Configurations that could never be approved should fail at load, not at the
// first startup nobody was watching.
func TestUnsatisfiableChangeControlIsRefused(t *testing.T) {
	cases := map[string]ChangeControl{
		"no approvers":         {Enabled: true},
		"minimum above roster": {Enabled: true, Minimum: 2, Approvers: []Approver{approver(t, "grace")}},
		"duplicate approver": {Enabled: true, Minimum: 2, Approvers: []Approver{
			{Name: "grace", PublicKey: approver(t, "grace").PublicKey},
			{Name: "grace", PublicKey: approver(t, "grace").PublicKey},
		}},
		"unnamed approver": {Enabled: true, Approvers: []Approver{{Name: "", PublicKey: approver(t, "x").PublicKey}}},
		"unreadable key":   {Enabled: true, Approvers: []Approver{{Name: "grace", PublicKey: "not-a-key"}}},
	}
	for name, cc := range cases {
		c := cc
		if err := c.validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// Off is a valid state and must stay quiet.
func TestChangeControlOffValidatesAndYieldsNoRoster(t *testing.T) {
	var cc ChangeControl
	if err := cc.validate(); err != nil {
		t.Fatal(err)
	}
	roster, err := cc.Roster()
	if err != nil || roster != nil {
		t.Fatalf("roster = %v, err = %v", roster, err)
	}
}

// One person signing twice must not satisfy a minimum of two, and the config
// says so before any signature is checked.
func TestDuplicateApproverNameIsRefusedWithTheReason(t *testing.T) {
	key := approver(t, "grace").PublicKey
	cc := ChangeControl{Enabled: true, Minimum: 2, Approvers: []Approver{
		{Name: "grace", PublicKey: key}, {Name: "grace", PublicKey: key},
	}}
	err := cc.validate()
	if err == nil || !strings.Contains(err.Error(), "twice") {
		t.Fatalf("err = %v", err)
	}
}

func TestThresholdDefaultsToOne(t *testing.T) {
	if got := (ChangeControl{}).Threshold(); got != 1 {
		t.Errorf("threshold = %d", got)
	}
	if got := (ChangeControl{Minimum: 3}).Threshold(); got != 3 {
		t.Errorf("threshold = %d", got)
	}
}
