# Control mapping

*What switchboard does, stated against the control objectives a security review
actually asks about — and, as importantly, what it does not do.*

This exists because procurement in healthcare, financial services and government
routinely gates an AI rollout for months, and most of that time goes to
establishing what a tool actually does. A mapping that overclaims makes the
review longer, not shorter: one unsupportable row and the reviewer starts
verifying everything by hand.

So the rightmost column below is deliberately unflattering. Nothing here is a
certification. switchboard is software you run; the controls are yours.

**Legend.** ✅ implemented · ◐ partial, with the gap named · ❌ not addressed

---

## Access control and authentication

| Objective | Frameworks | Status | Evidence |
|---|---|---|---|
| Callers are authenticated before use | SOC 2 CC6.1 · ISO 27001 A.5.15 · HIPAA §164.312(d) · NIST AC-2 | ✅ | OIDC tokens from a configured issuer, or per-team API keys compared in constant time. Tokens expire on their own; the team they name must be on the roster. See [sso.md](sso.md). |
| Unauthenticated access is denied | SOC 2 CC6.1 · NIST AC-3 | ✅ | `attribution.require_caller` returns 401 for requests presenting no valid key. Off by default; on, it fails closed. |
| Least privilege for provider credentials | SOC 2 CC6.3 · NIST AC-6 | ✅ | The gateway assumes a per-caller role; the Bedrock permissions live on the assumed role, not the gateway's own. Trust policy scope is yours to set. |
| Credentials are not stored by the application | SOC 2 CC6.1 · NIST IA-5 | ✅ | AWS credentials come from the standard chain — environment, shared config, SSO, instance role. switchboard never accepts or persists a provider key. |
| Centralised identity, MFA, deprovisioning | SOC 2 CC6.2 · ISO 27001 A.5.16 | ✅ | Delegated to your identity provider. MFA, conditional access and deprovisioning are enforced where you already manage them; a revoked user stops working when their token expires. Static keys, where still used, remain a manual removal. |

## Audit and accountability

| Objective | Frameworks | Status | Evidence |
|---|---|---|---|
| Security-relevant events are recorded | SOC 2 CC7.2 · ISO 27001 A.8.15 · HIPAA §164.312(b) · NIST AU-2 | ✅ | One JSONL entry per completion: time, id, team, model, backend, token counts, stop reason, redaction counts, and errors. Backend failures are recorded too. |
| Records identify the actor | SOC 2 CC7.2 · NIST AU-3 | ✅ | Team and, when the caller presented a token, the subject — a person rather than a shared credential. Team only when a static key was used. |
| Records are protected from modification | SOC 2 CC7.2 · ISO 27001 A.8.15 · NIST AU-9 | ◐ | Entries are hash-chained; alteration, deletion and reordering are detectable via `switchboard audit verify`, which exits non-zero. With `SWITCHBOARD_AUDIT_KEY` an edit requires the key. **Tail truncation is undetectable from the file alone, and a key holder can rewrite history.** Anchor the printed head externally, or use write-once storage. |
| Individual decisions can be reconstructed | EU AI Act Art. 12 · NIST AU-3 | ✅ | `switchboard audit show -id <id>` returns the model, team, token counts, stop reason, redactions, and the redacted content when content logging is on. |
| Log retention | EU AI Act Art. 26 (≥6 months) · NIST AU-11 | ❌ | switchboard appends; it does not rotate, expire, or enforce retention. Retention is your log pipeline's job. |
| Logs are reviewed | SOC 2 CC7.2 · NIST AU-6 | ◐ | `audit verify` is designed for a scheduled job. Nothing alerts on its own. |

## Data protection

| Objective | Frameworks | Status | Evidence |
|---|---|---|---|
| Sensitive data is not written to logs | SOC 2 CC6.7 · ISO 27001 A.8.11 · HIPAA §164.312(a)(2)(iv) | ◐ | Redaction is applied inside the audit log rather than at its call sites, so no code path can skip it, and content logging is refused outright without rules configured. **Pattern-based: it catches structured identifiers, not a name or a condition described in prose.** |
| Data does not leave the trust boundary | SOC 2 CC6.6 · HIPAA §164.312(e) | ✅ | Self-hosted, single static binary. Talks only to the providers you configure. No telemetry, no phone-home, no vendor in the path. |
| Data can be kept in-region or on-premises | ISO 27001 A.5.34 · FedRAMP SA-9 | ✅ | Bedrock region is configured; the local backend serves models on the host with no cloud dependency at all, for networks where no provider is reachable. |
| Redaction toward the provider | ISO 27001 A.8.11 | ❌ | Content is redacted before it is logged. It still reaches the model as written. |
| Encryption in transit | SOC 2 CC6.7 · HIPAA §164.312(e)(1) | ◐ | Provider calls use the SDK's TLS. **The gateway's own listener is plain HTTP** and expects to sit behind a TLS terminator; it binds loopback by default. |
| Encryption at rest | HIPAA §164.312(a)(2)(iv) · NIST SC-28 | ❌ | The audit log is a file with 0600 permissions. Encryption at rest is the filesystem's job. |

## Configuration and change management

| Objective | Frameworks | Status | Evidence |
|---|---|---|---|
| Configuration is validated before use | SOC 2 CC8.1 · NIST CM-3 | ✅ | The whole config is validated at load, before the listener opens. Unknown fields are rejected rather than ignored, so a misspelled key fails in front of whoever typed it instead of silently widening behaviour. |
| Insecure combinations are refused | SOC 2 CC8.1 | ✅ | Content logging without redaction rules, and `require_caller` without attribution, are both refused at startup. |
| Builds are reproducible and attributable | SOC 2 CC8.1 · SLSA | ◐ | Tagged releases build from source in CI with pinned Go, publishing checksums; version, commit and build date are stamped into the binary. **No signed provenance or SBOM.** |
| Dependencies are minimal and auditable | ISO 27001 A.8.30 | ✅ | Standard library plus the AWS SDK. `go.mod` is the whole list; token verification is in-tree rather than a JOSE dependency. |

## Availability and operations

| Objective | Frameworks | Status | Evidence |
|---|---|---|---|
| Graceful shutdown without losing work | SOC 2 A1.1 | ✅ | Draining shutdown; local models are unloaded and their processes stopped. |
| Health checking | SOC 2 A1.1 · NIST SI-4 | ✅ | `GET /healthz`. |
| Resource limits | SOC 2 A1.1 | ❌ | No rate limiting, concurrency ceiling, or token budget. A runaway caller is not contained. |
| Failure is reported honestly | SOC 2 CC7.3 | ✅ | A mid-stream backend error becomes an error frame before `[DONE]` rather than a truncated response that reads as a short success. Backends that cannot forward tools refuse the request rather than silently dropping them. |

---

## AI-specific

| Objective | Reference | Status | Evidence |
|---|---|---|---|
| Automatic recording of events over the lifecycle | EU AI Act Art. 12 | ✅ | See Audit above. |
| Deployer retains logs ≥6 months | EU AI Act Art. 26 | ❌ | Retention is not implemented. |
| Policy enforcement at the model boundary | MITRE ATLAS AML.M0033 | ◐ | Team-scoped access and fail-closed configuration. No content policy or output filtering. |
| Telemetry logging | MITRE ATLAS AML.M0024 | ✅ | The audit log. |
| Adversarial input detection | MITRE ATLAS AML.M0015 | ❌ | Not built, deliberately: [injection-study](https://github.com/Grace/injection-study) measures why content matching does not hold up, which is the reason this design enforces at the boundary rather than trying to recognise malice. |

---

## The short version for a reviewer

switchboard is strong on **what left, on whose behalf, and can you prove it
later** — attribution the provider's own bill agrees with, redaction at a point
no application team can bypass, and an audit log where editing an entry is
detectable.

Identity is delegated to your provider over OIDC, so per-user attribution, MFA
and deprovisioning are enforced where you already manage them. Token
verification is a narrow in-house implementation rather than a JOSE dependency;
[sso.md](sso.md) explains that choice and the adversarial tests that pin it, and
swapping it for a vetted library is one file if your review requires that.

It does no content filtering, no rate limiting, and no retention management, and
does not pretend to.

Questions: **hello@gracefulco.de**
