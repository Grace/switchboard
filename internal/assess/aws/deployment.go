package aws

import (
	"fmt"
	"strings"
	"time"

	"github.com/Grace/switchboard/internal/assess"
)

// Deployment describes the account's Bedrock setup in assess's terms.
func (e *Export) Deployment(profile assess.Profile) assess.Deployment {
	d := assess.Deployment{
		Source:  "aws-bedrock",
		Origin:  strings.Join(e.Read, ", "),
		Profile: profile,
	}
	if len(e.Skipped) > 0 {
		d.Caveats = append(d.Caveats, fmt.Sprintf(
			"Not recognised and therefore not read: %s. If one of those was a Bedrock "+
				"export, this assessment is missing what it said.", strings.Join(e.Skipped, ", ")))
	}

	e.mapAuth(&d)
	e.mapAudit(&d)
	e.mapData(&d)
	e.mapAssurance(&d)
	e.mapRuntime(&d)
	e.noteCloudTrail(&d)
	e.mapAgency(&d)
	return d
}

// mapAgency. These exports describe the account's access to models and what it
// writes down about invocations. Tool use lives one level up, in a Bedrock
// Agent's action groups or in the application's own loop, and neither appears
// here — so both agency rows stay Unknown and the caveat says where to look.
func (e *Export) mapAgency(d *assess.Deployment) {
	d.Caveats = append(d.Caveats,
		"These exports cover model access and invocation logging, not tool use. If "+
			"anything here calls tools — a Bedrock Agent's action groups, or an "+
			"application running its own tool loop — what bounds those calls is declared "+
			"outside this account configuration. Export the agent "+
			"(`aws bedrock-agent get-agent-action-group`) or name the application, and "+
			"say who may invoke each action group; a tool the model can reach is an "+
			"action it can take.")
}

// mapAuth. Bedrock authenticates every call with SigV4 — there is no anonymous
// invocation to leave open. What the export cannot show is whether callers are
// distinguishable from one another, which is the question that actually
// matters for attribution.
func (e *Export) mapAuth(d *assess.Deployment) {
	d.Auth.CloudProvider = assess.Yes
	d.Auth.DenyUnauthenticated = assess.Yes
	d.Auth.OIDC = assess.Unknown
	d.Auth.PerCallerProviderCreds = assess.Unknown
	d.Caveats = append(d.Caveats,
		"Every Bedrock call is signed, so nothing is unauthenticated. Whether spend is "+
			"attributable per team is a different question and this export cannot answer "+
			"it: if applications invoke under one shared execution role, CloudTrail and "+
			"Cost and Usage Report both see one principal. Ask which IAM principals invoke "+
			"Bedrock, and whether they differ per team.")
}

// mapAudit. Model invocation logging is Bedrock's record of what was asked and
// answered; everything about whether it can be trusted afterwards lives outside
// it, in the bucket.
func (e *Export) mapAudit(d *assess.Deployment) {
	if e.Logging == nil {
		d.Audit.Enabled = assess.Unknown
		d.Audit.TamperEvident = assess.Unknown
		d.Audit.Archived = assess.Unknown
		d.Caveats = append(d.Caveats,
			"No model invocation logging export was provided, so whether Bedrock records "+
				"invocations at all is unknown. Run: aws bedrock "+
				"get-model-invocation-logging-configuration")
		return
	}

	dest := e.destinations()
	if len(dest) == 0 {
		// The API returns an empty object when logging has never been
		// configured. That is a finding about the account, not a gap in the
		// export, and it is the single most consequential row here.
		d.Audit.Enabled = assess.No
		d.Audit.TamperEvident = assess.No
		d.Audit.Archived = assess.No
		d.Caveats = append(d.Caveats,
			"Model invocation logging is not configured. Nothing records what was sent to "+
				"a model or what came back, so no control below that depends on a record "+
				"can be satisfied by this account.")
		return
	}

	d.Audit.Enabled = assess.Yes
	d.Audit.Path = strings.Join(dest, " and ")
	// Delivery is asynchronous and best-effort; an invocation is not refused
	// because its log could not be written. This adapter does not assert that
	// from the export, because the export does not say it.
	d.Audit.FailClosed = assess.Unknown
	d.Caveats = append(d.Caveats,
		"Whether an invocation is refused when its log cannot be delivered is a property "+
			"of the service rather than of this configuration, and no export states it. "+
			"Confirm with AWS whether invocation logging is best-effort for your delivery "+
			"destination; if it is, a completion served during a logging outage leaves no "+
			"record and nothing fails.")

	// The record is in S3. Whether it can be rewritten is a property of the
	// bucket, and the object-lock export is how you find out.
	if e.Logging.S3 != nil && e.Logging.S3.BucketName != "" {
		e.mapObjectLock(d, e.Logging.S3.BucketName)
		d.Audit.Archived = assess.Yes
	} else {
		d.Audit.Archived = assess.Unknown
		d.Audit.TamperEvident = assess.Unknown
		d.Caveats = append(d.Caveats,
			"Invocation logs go to CloudWatch Logs and not to S3. CloudWatch retention is a "+
				"log group setting and immutability is not among its options, so neither "+
				"tamper-evidence nor archival can be established from here.")
	}
}

// mapObjectLock is where a Bedrock deployment earns or loses the row a hash
// chain exists for.
//
// Object Lock in COMPLIANCE mode is a genuine answer: for the retention period
// no principal, including the account root, can delete or overwrite an object.
// That is immutability at the storage layer rather than tamper-evidence in the
// record — it prevents the edit instead of revealing it — and for an auditor
// asking "could this have been changed", it is a real control and should be
// scored as one.
//
// GOVERNANCE mode is not the same claim, and the difference is one IAM
// permission. Reporting them alike would be the kind of flattery that makes a
// report worthless.
func (e *Export) mapObjectLock(d *assess.Deployment, bucket string) {
	if e.ObjectLock == nil || e.ObjectLock.Config == nil {
		d.Audit.TamperEvident = assess.Unknown
		d.Caveats = append(d.Caveats, fmt.Sprintf(
			"Invocation logs are written to s3://%s. Whether that bucket prevents them "+
				"being rewritten is unknown: run aws s3api get-object-lock-configuration "+
				"--bucket %s", bucket, bucket))
		return
	}

	cfg := e.ObjectLock.Config
	// The export does not carry the bucket it describes, so the tie to the
	// logging bucket is an assumption and is declared as one.
	d.Caveats = append(d.Caveats, fmt.Sprintf(
		"The object-lock configuration read here is assumed to describe s3://%s, the "+
			"invocation log bucket. AWS does not include the bucket name in that "+
			"response, so confirm it was exported for that bucket and not another.", bucket))

	if !strings.EqualFold(cfg.ObjectLockEnabled, "Enabled") {
		d.Audit.TamperEvident = assess.No
		d.Caveats = append(d.Caveats,
			"Object Lock is not enabled on the log bucket, so a principal with write access "+
				"can overwrite or delete invocation records and nothing would show it.")
		return
	}

	mode, retention := "", time.Duration(0)
	if cfg.Rule != nil && cfg.Rule.DefaultRetention != nil {
		r := cfg.Rule.DefaultRetention
		mode = strings.ToUpper(r.Mode)
		retention = time.Duration(r.Days)*24*time.Hour +
			time.Duration(r.Years)*365*24*time.Hour
	}
	d.Audit.Retention = retention

	switch mode {
	case "COMPLIANCE":
		d.Audit.TamperEvident = assess.Yes
		d.Caveats = append(d.Caveats,
			"Object Lock is in COMPLIANCE mode: for the retention period no principal, "+
				"including the account root, can delete or overwrite a log object. This is "+
				"immutability at the storage layer rather than tamper-evidence in the "+
				"record — it prevents an edit rather than revealing one — and it does not "+
				"cover anything that happened before an object was written.")
	case "GOVERNANCE":
		d.Audit.TamperEvident = assess.No
		d.Caveats = append(d.Caveats,
			"Object Lock is in GOVERNANCE mode, which a principal holding "+
				"s3:BypassGovernanceRetention can override. It protects against accident "+
				"and not against intent, and an auditor asking whether the record could "+
				"have been changed has to be told that it could.")
	default:
		d.Audit.TamperEvident = assess.Unknown
		d.Caveats = append(d.Caveats,
			"Object Lock is enabled on the log bucket but no default retention rule is set, "+
				"so objects are protected only where a retention date was applied per "+
				"object. Whether that happened for invocation logs is not visible here.")
	}
}

// mapData. A Bedrock guardrail's sensitive-information policy is the nearest
// thing to redaction, with one structural difference that decides the row.
func (e *Export) mapData(d *assess.Deployment) {
	d.Data.TLS = assess.Yes
	d.Data.MutualTLS = assess.No
	d.Data.SealedRecovery = assess.No

	if e.Logging != nil {
		d.Data.ContentLogged = tri(e.Logging.TextDataDelivery)
	} else {
		d.Data.ContentLogged = assess.Unknown
	}

	rules := 0
	anonymising := false
	for _, g := range e.Guardrails {
		if g.SensitiveInformationPolicy == nil {
			continue
		}
		rules += len(g.SensitiveInformationPolicy.PIIEntities) +
			len(g.SensitiveInformationPolicy.Regexes)
		for _, p := range g.SensitiveInformationPolicy.PIIEntities {
			if strings.EqualFold(p.Action, "ANONYMIZE") {
				anonymising = true
			}
		}
	}
	d.Data.RedactionRules = rules

	// The row this adapter exists to get right. A guardrail applies when the
	// caller names it in the request. An application that omits the parameter
	// is not filtered, which makes the guardrail a convention rather than a
	// control — unless an IAM policy denies invocation without one.
	d.Data.RedactionUnbypassable = assess.Unknown
	switch {
	case rules == 0 && len(e.Guardrails) > 0:
		d.Caveats = append(d.Caveats,
			"The guardrails read here define no PII entities or regexes, so nothing is "+
				"masked or blocked on the basis of sensitive content.")
	case rules > 0:
		what := "blocked"
		if anonymising {
			what = "anonymised"
		}
		d.Caveats = append(d.Caveats, fmt.Sprintf(
			"%d sensitive-information rules are defined across the guardrails read, with "+
				"matches %s. Whether they actually apply is a separate question: a Bedrock "+
				"guardrail takes effect only when the caller passes its identifier, so an "+
				"application that omits the parameter is unfiltered. Ask whether an IAM "+
				"policy denies bedrock:InvokeModel without a guardrail — that condition is "+
				"what turns this from a convention into a control, and no export here "+
				"shows it.", rules, what))
	}
}

// mapAssurance. Guardrails are the content-policy answer; adversarial testing
// is not something an AWS export can evidence at all.
func (e *Export) mapAssurance(d *assess.Deployment) {
	if len(e.Guardrails) == 0 {
		d.Assurance.ContentPolicy = assess.Unknown
		d.Caveats = append(d.Caveats,
			"No guardrail export was provided. Run aws bedrock list-guardrails, then "+
				"get-guardrail for each, or state that none are configured.")
		return
	}

	var kinds []string
	filters, topics := 0, 0
	grounding := false
	for _, g := range e.Guardrails {
		if g.ContentPolicy != nil {
			filters += len(g.ContentPolicy.Filters)
		}
		if g.TopicPolicy != nil {
			topics += len(g.TopicPolicy.Topics)
		}
		if g.WordPolicy != nil &&
			(len(g.WordPolicy.Words) > 0 || len(g.WordPolicy.ManagedWordLists) > 0) {
			kinds = append(kinds, "word filters")
		}
		if g.ContextualGroundingPolicy != nil && len(g.ContextualGroundingPolicy.Filters) > 0 {
			grounding = true
		}
	}
	if filters > 0 {
		kinds = append(kinds, fmt.Sprintf("%d content filters", filters))
	}
	if topics > 0 {
		kinds = append(kinds, fmt.Sprintf("%d denied topics", topics))
	}
	if grounding {
		kinds = append(kinds, "contextual grounding")
	}

	if len(kinds) == 0 {
		d.Assurance.ContentPolicy = assess.No
		d.Assurance.ContentPolicyDetail = fmt.Sprintf(
			"%d guardrail(s) exist but none define content, topic or word filtering.",
			len(e.Guardrails))
		return
	}
	d.Assurance.ContentPolicy = assess.Yes
	d.Assurance.ContentPolicyDetail = fmt.Sprintf(
		"%d Bedrock guardrail(s): %s. Applies only where a caller passes the guardrail "+
			"identifier.", len(e.Guardrails), strings.Join(dedupe(kinds), ", "))
}

func (e *Export) mapRuntime(d *assess.Deployment) {
	d.Runtime.FIPS = assess.Unknown
	d.Runtime.FIPSHint = "Bedrock offers FIPS 140-3 validated endpoints in US regions " +
		"(bedrock-runtime-fips.<region>.amazonaws.com). Which endpoint your applications " +
		"resolve is a client setting and is not in any export here."
	d.Runtime.Limits = assess.Unknown
	d.Caveats = append(d.Caveats,
		"What bounds one caller's consumption — service quotas, provisioned throughput, or "+
			"nothing — is not visible in these exports. Ask for the account's Bedrock "+
			"quotas and whether any application-level limiting exists.")
}

// noteCloudTrail records what CloudTrail does and, more importantly, what it
// does not.
//
// Log file validation is a hash chain over digest files, and it is real: an
// altered or deleted CloudTrail log is detectable. It covers API calls, which
// for Bedrock means InvokeModel happened, by whom, when. It does not cover what
// was sent or what came back — that is the invocation log, in a different
// bucket, under different protection. Crediting the record with CloudTrail's
// property would be the single easiest mistake to make here.
func (e *Export) noteCloudTrail(d *assess.Deployment) {
	if len(e.Trails) == 0 {
		d.Caveats = append(d.Caveats,
			"No CloudTrail export was provided, so whether Bedrock API calls are recorded "+
				"at all is unknown. Run aws cloudtrail describe-trails.")
		return
	}
	validated, multi := 0, 0
	for _, t := range e.Trails {
		if t.LogFileValidation != nil && *t.LogFileValidation {
			validated++
		}
		if t.IsMultiRegionTrail != nil && *t.IsMultiRegionTrail {
			multi++
		}
	}
	note := fmt.Sprintf("%d CloudTrail trail(s): %d with log file validation, %d multi-region. "+
		"Log file validation is a genuine hash chain and detects an altered or deleted "+
		"trail file — but over API call records, not over model invocation logs. It "+
		"evidences that a call happened and under which principal; it says nothing about "+
		"what was sent or returned, and gives the invocation log no protection.",
		len(e.Trails), validated, multi)
	if validated == 0 {
		note += " No trail here has validation enabled, so even that is not established."
	}
	d.Caveats = append(d.Caveats, note)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func (e *Export) destinations() []string {
	var out []string
	if e.Logging == nil {
		return nil
	}
	if s := e.Logging.S3; s != nil && s.BucketName != "" {
		p := "s3://" + s.BucketName
		if s.KeyPrefix != "" {
			p += "/" + strings.TrimPrefix(s.KeyPrefix, "/")
		}
		out = append(out, p)
	}
	if c := e.Logging.CloudWatch; c != nil && c.LogGroupName != "" {
		out = append(out, "CloudWatch Logs "+c.LogGroupName)
	}
	return out
}
