package aws

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Grace/switchboard/internal/assess"
)

func dir(t *testing.T, files map[string]string) string {
	t.Helper()
	d := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(d, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

const loggingToS3 = `{"loggingConfig":{
  "s3Config":{"bucketName":"acme-bedrock-logs","keyPrefix":"invocations/"},
  "textDataDeliveryEnabled":true,"imageDataDeliveryEnabled":false}}`

const guardrail = `{"name":"pii","guardrailId":"gr-1","status":"READY","version":"3",
  "contentPolicy":{"filters":[{"type":"HATE","inputStrength":"HIGH","outputStrength":"HIGH"}]},
  "sensitiveInformationPolicy":{
    "piiEntities":[{"type":"EMAIL","action":"ANONYMIZE"},{"type":"US_SSN","action":"BLOCK"}],
    "regexes":[{"name":"acct","action":"ANONYMIZE"}]}}`

func lock(mode string) string {
	return `{"ObjectLockConfiguration":{"ObjectLockEnabled":"Enabled",
	  "Rule":{"DefaultRetention":{"Mode":"` + mode + `","Years":7}}}}`
}

func deploy(t *testing.T, files map[string]string) assess.Deployment {
	t.Helper()
	e, err := ReadDir(dir(t, files))
	if err != nil {
		t.Fatal(err)
	}
	return e.Deployment(assess.ProfileFINRA)
}

func caveats(d assess.Deployment) string { return strings.Join(d.Caveats, "\n") }

// Files are recognised by shape, because nobody names them what you asked.
func TestFilesAreRecognisedByShapeNotName(t *testing.T) {
	e, err := ReadDir(dir(t, map[string]string{
		"whatever.json":  loggingToS3,
		"thing2.json":    guardrail,
		"aaa.json":       lock("COMPLIANCE"),
		"trails.json":    `{"trailList":[{"Name":"org","LogFileValidationEnabled":true,"IsMultiRegionTrail":true}]}`,
		"unrelated.json": `{"Vpcs":[{"VpcId":"vpc-1"}]}`,
		"notjson.txt":    `ignored, wrong extension`,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if e.Logging == nil || len(e.Guardrails) != 1 || e.ObjectLock == nil || len(e.Trails) != 1 {
		t.Fatalf("recognition missed something: %+v", e)
	}
	if len(e.Read) != 4 {
		t.Errorf("read = %v, want the four Bedrock exports", e.Read)
	}
	// What it could not place has to be reported, or the assessment silently
	// understates a deployment.
	if len(e.Skipped) != 1 || e.Skipped[0] != "unrelated.json" {
		t.Errorf("skipped = %v", e.Skipped)
	}
	if !strings.Contains(caveats(e.Deployment(assess.ProfileNone)), "unrelated.json") {
		t.Error("an unrecognised file should be named in the caveats")
	}
}

func TestADirectoryOfNothingRelevantIsAnError(t *testing.T) {
	_, err := ReadDir(dir(t, map[string]string{"vpc.json": `{"Vpcs":[]}`}))
	if err == nil {
		t.Fatal("a directory with no Bedrock exports should be refused")
	}
	if !strings.Contains(err.Error(), "get-model-invocation-logging-configuration") {
		t.Errorf("the error should name the commands to run: %v", err)
	}
}

// The most consequential row in the adapter: logging never configured is a
// finding about the account, not silence in the export. AWS returns {} for it.
func TestLoggingNeverConfiguredIsAFindingNotASilence(t *testing.T) {
	d := deploy(t, map[string]string{
		"logging.json": `{"loggingConfig":null}`,
		"g.json":       guardrail,
	})
	if d.Audit.Enabled != assess.No {
		t.Errorf("audit enabled = %v, want No", d.Audit.Enabled)
	}
	if !strings.Contains(caveats(d), "not configured") {
		t.Errorf("caveats should say logging is off:\n%s", caveats(d))
	}
}

// COMPLIANCE and GOVERNANCE are one IAM permission apart and must not score
// alike. This is the row a Bedrock deployment earns or loses honestly.
func TestObjectLockModeDecidesTamperEvidence(t *testing.T) {
	compliance := deploy(t, map[string]string{
		"l.json": loggingToS3, "lock.json": lock("COMPLIANCE"),
	})
	if compliance.Audit.TamperEvident != assess.Yes {
		t.Errorf("COMPLIANCE mode should score tamper-evident, got %v",
			compliance.Audit.TamperEvident)
	}
	if !strings.Contains(caveats(compliance), "prevents an edit rather than revealing one") {
		t.Error("the difference from a hash chain should be stated, not glossed")
	}
	if compliance.Audit.Retention == 0 {
		t.Error("a seven-year default retention should reach Audit.Retention")
	}

	governance := deploy(t, map[string]string{
		"l.json": loggingToS3, "lock.json": lock("GOVERNANCE"),
	})
	if governance.Audit.TamperEvident != assess.No {
		t.Errorf("GOVERNANCE mode is bypassable and must not score as tamper-evident, got %v",
			governance.Audit.TamperEvident)
	}
	if !strings.Contains(caveats(governance), "s3:BypassGovernanceRetention") {
		t.Error("the caveat should name the permission that bypasses it")
	}

	// Logging to S3 with no lock export is unknown, not a failure — and the
	// caveat has to say which command answers it.
	silent := deploy(t, map[string]string{"l.json": loggingToS3})
	if silent.Audit.TamperEvident != assess.Unknown {
		t.Errorf("no lock export = %v, want Unknown", silent.Audit.TamperEvident)
	}
	if !strings.Contains(caveats(silent), "get-object-lock-configuration --bucket acme-bedrock-logs") {
		t.Errorf("the caveat should name the exact command:\n%s", caveats(silent))
	}
}

// The row this adapter exists to get right. A Bedrock guardrail applies only
// when the caller passes it, so it is not a chokepoint on the evidence here.
func TestAGuardrailIsNotAssumedToBeAChokepoint(t *testing.T) {
	d := deploy(t, map[string]string{"l.json": loggingToS3, "g.json": guardrail})
	if d.Data.RedactionRules != 3 {
		t.Errorf("redaction rules = %d, want 3 (two PII entities and a regex)", d.Data.RedactionRules)
	}
	if d.Data.RedactionUnbypassable != assess.Unknown {
		t.Errorf("unbypassable = %v; a Bedrock guardrail is opt-in per call and this "+
			"export cannot show whether IAM forces it", d.Data.RedactionUnbypassable)
	}
	if !strings.Contains(caveats(d), "bedrock:InvokeModel without a guardrail") {
		t.Errorf("the caveat should name the IAM condition to ask for:\n%s", caveats(d))
	}
	if d.Assurance.ContentPolicy != assess.Yes {
		t.Errorf("content policy = %v, want Yes", d.Assurance.ContentPolicy)
	}
	if !strings.Contains(d.Assurance.ContentPolicyDetail, "1 content filters") {
		t.Errorf("detail = %q", d.Assurance.ContentPolicyDetail)
	}
}

// CloudTrail validation is a real hash chain over the wrong thing. Crediting
// the invocation record with it is the easiest mistake available here.
func TestCloudTrailValidationIsNotCreditedToTheInvocationRecord(t *testing.T) {
	d := deploy(t, map[string]string{
		"l.json":  loggingToS3,
		"ct.json": `{"trailList":[{"Name":"org","LogFileValidationEnabled":true,"IsMultiRegionTrail":true}]}`,
	})
	// No object lock export, so the invocation record's protection is unknown
	// — CloudTrail must not have filled it in.
	if d.Audit.TamperEvident != assess.Unknown {
		t.Errorf("tamper-evident = %v; CloudTrail validation covers API calls, not "+
			"invocation logs", d.Audit.TamperEvident)
	}
	c := caveats(d)
	for _, want := range []string{"genuine hash chain", "not over model invocation logs"} {
		if !strings.Contains(c, want) {
			t.Errorf("caveats should distinguish the two records: missing %q", want)
		}
	}
}

// Everything Bedrock authenticates; nothing here shows whether callers are
// distinguishable, which is the question attribution actually turns on.
func TestSignedIsNotTheSameAsAttributable(t *testing.T) {
	d := deploy(t, map[string]string{"l.json": loggingToS3})
	if d.Auth.DenyUnauthenticated != assess.Yes {
		t.Error("SigV4 means there is no anonymous invocation")
	}
	if d.Auth.PerCallerProviderCreds != assess.Unknown {
		t.Errorf("per-caller creds = %v, want Unknown", d.Auth.PerCallerProviderCreds)
	}
	if !strings.Contains(caveats(d), "one shared execution role") {
		t.Error("the caveat should name what makes spend unattributable")
	}
}

// An assessment of a foreign deployment must not invent failures.
func TestNothingIsScoredUnmetFromAbsence(t *testing.T) {
	rep := assess.Assess(deploy(t, map[string]string{"l.json": loggingToS3}))
	for _, c := range rep.Controls {
		if c.Status == assess.StatusUnmet && strings.Contains(c.Evidence, "not provided") {
			t.Errorf("a missing export produced an unmet finding: %s — %s", c.Objective, c.Evidence)
		}
	}
	if rep.Counts()[assess.StatusUnknown] == 0 {
		t.Error("a partial export should produce unknowns")
	}
}
