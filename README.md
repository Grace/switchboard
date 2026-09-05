# switchboard

**An LLM gateway that can prove what happened.**

One OpenAI-compatible endpoint in front of Bedrock and on-device models — with
per-team cost attribution the provider's own bill agrees with, redaction at a
point no application can bypass, and a tamper-evident record of every
completion.

```
client ──▶ /v1/chat/completions ──▶ registry ──┬──▶ local   (llama.cpp, on-device)
             OpenAI dialect                    └──▶ bedrock (AWS Converse API)
                     │
                     └──▶ attribution · redaction · limits · audit
```

## Why

Routing is the easy half. Every gateway does it, and if that is all you need,
several mature ones will do it better than this one.

The half that is hard to buy is being able to answer, afterwards, what your
models were asked to do and on whose behalf — in a form that survives someone
disputing it.

**Attribution the provider's bill agrees with.** A gateway calls Bedrock under
one role, so every team's spend arrives on the invoice as a single identity —
the gateway erased exactly the distinction finance needs. switchboard assumes a
role per caller, so the split is one AWS itself confirms rather than a number
from your own ledger that someone has to trust.

**Redaction somewhere it cannot be skipped.** The usual advice is to mask in
each application before telemetry leaves. That is correct only if every team
configured it, configured it right, and has not regressed it — and nobody can
demonstrate that to an auditor. A gateway cannot be bypassed, which is what
makes redaction here a control rather than a convention.

**A record where editing an entry is detectable.** An append-only file is a
history right up until someone with disk access decides otherwise. Every entry
carries the digest of the one before it, across rotated segments, and the chain
is walked at startup — the window when the process is down being exactly when a
file would be edited.

And it still runs on a laptop with no cloud account at all, against a local
`llama.cpp` model, using the same config file and the same API. That is not a
second product; it is the same binary in a network where no provider is
reachable either.

## Quickstart

Sixty seconds to a working endpoint. Pick one:

```sh
# Docker — serves the Bedrock path, credentials from your environment
docker run --rm -p 11435:11435 \
  -e AWS_REGION -e AWS_PROFILE -v ~/.aws:/home/nonroot/.aws:ro \
  ghcr.io/grace/switchboard:latest
```

```sh
# Binary — no toolchain needed, macOS and Linux, amd64 and arm64
# grab the tarball for your platform from the releases page, then:
./switchboard init                # writes ~/.switchboard/switchboard.json
./switchboard serve               # http://127.0.0.1:11435
```

```sh
# From source, if you already have Go
go install github.com/Grace/switchboard/cmd/switchboard@latest
```

Then, whichever you chose:

```sh
switchboard models              # list what's configured
```

The container image serves models in your AWS account. Local models need a
`llama.cpp` process and access to the GPU, so run the binary on the host for
those — same config file, same API.

Point anything that speaks OpenAI at it:

```sh
curl http://127.0.0.1:11435/v1/chat/completions \
  -H 'content-type: application/json' \
  -d '{"model": "claude-opus", "messages": [{"role": "user", "content": "hello"}], "stream": true}'
```

Or from the terminal, without a server:

```sh
switchboard run -m qwen3-8b "explain the borrow checker"
```

Releases are signed with keyless cosign and ship an SPDX SBOM — see
[docs/verifying.md](docs/verifying.md) for how to check one, including the
`--certificate-identity` pin that makes the signature mean *this* workflow
rather than any workflow.

## Configuration

`~/.switchboard/switchboard.json`, or wherever `SWITCHBOARD_CONFIG` points. Unknown fields are rejected at load time, and the file is validated before the process starts rather than at first request.

```json
{
  "listen": "127.0.0.1:11435",
  "default_model": "qwen3-8b",
  "local": {
    "device": "auto",
    "idle_timeout": "10m"
  },
  "bedrock": {
    "region": "us-east-1",
    "profile": "default"
  },
  "models": [
    {
      "name": "qwen3-8b",
      "backend": "local",
      "path": "~/models/qwen3-8b-q4.gguf",
      "context": 8192
    },
    {
      "name": "claude-opus",
      "backend": "bedrock",
      "model_id": "us.anthropic.claude-opus-5"
    }
  ]
}
```

AWS credentials come from the standard chain — environment, shared config, SSO, instance role. switchboard never asks for a key.

## API

| Endpoint | Purpose |
| --- | --- |
| `POST /v1/chat/completions` | Completions, streaming or not. OpenAI dialect. |
| `GET /v1/models` | The routable roster, across every backend. |
| `POST /v1/connect` | Load a local model into memory ahead of first use. |
| `POST /v1/disconnect` | Unload it and reclaim the memory. |
| `GET /health` | Liveness. |

## Commands

| Command | Purpose |
| --- | --- |
| `switchboard serve` | Serve the HTTP API. |
| `switchboard run -m <model> "…"` | Talk to a model from the terminal, no server. |
| `switchboard models` | List the routable roster. |
| `switchboard connect` / `disconnect` | Load or unload a local model on a running server. |
| `switchboard init` | Write a starter config. |
| `switchboard redact` | Check redaction rules against real text before trusting them. |
| `switchboard version` | Print version, commit and build date. |

## Design notes

**The backend interface is four methods.** `Name`, `Models`, `Chat`, `Close`. Adding SageMaker, Azure OpenAI, MLX, or a raw cgo binding means implementing that and nothing else — no changes to the server, the registry, or the wire format.

**Capabilities are negotiated, not assumed.** Not every backend can do everything, so the extras are optional interfaces asked for at the door: `Connector` for backends that load and unload weights, `ToolCaller` for backends that can forward tool definitions. A backend that can't do a thing simply doesn't implement it, and the server turns the request away with a clear error. The alternative — accepting a request with tools and quietly returning prose — leaves the caller no way to discover that the tools never reached the model.

**Bedrock goes through the Converse API,** not per-model `InvokeModel` payloads. One code path covers every model family Bedrock hosts, so adding a model is a config line rather than a new marshaller.

**The roster is visible without credentials.** The Bedrock client is built lazily on first use, so switchboard starts, serves local models, and lists everything it knows about on a machine that has never seen an AWS credential. A backend that errors during listing is skipped rather than failing the whole response — one unreachable region shouldn't hide the models running on your desk.

**Local models are reaped when idle.** `idle_timeout` unloads a model that hasn't been asked anything, which matters when the weights are competing with everything else for memory.

**Streaming failures are reported honestly.** Once SSE headers are out, the status code is spent; a mid-stream backend error becomes an error frame before `[DONE]` rather than a truncated response that looks like a successful short answer.

## Status

Working: routing, both backends, streaming and non-streaming completions, tool calling on the local backend, token usage accounting, model lifecycle, graceful drain on shutdown. The HTTP surface and the tool-translation layer are covered by tests.

**TLS, and mutual TLS.** The listener speaks TLS 1.2+ given a certificate, and requires a verified client certificate given a CA. A plaintext listener bound to anything but loopback is refused at config load — "assume something terminates in front of it" is not an assumption worth making silently.

**SSO.** Callers can present an OIDC token instead of a shared key, so the audit log records a person rather than a credential. Verification is a deliberately narrow implementation over the standard library — RS256/ES256, verification only — with the algorithm chosen from the key rather than the token, and an adversarial test suite that constructs each classic attack and asserts it is refused. See [docs/sso.md](docs/sso.md).

**Recovery for an investigation.** Redacted values can be sealed to a public key the gateway does not hold the private half of, so an incident can recover the address an injected instruction was exfiltrating to — the one string redaction removes and an investigator most needs. The gateway cannot read back what it wrote; recovery runs where the private key lives. Off unless configured, because it changes what the system retains. See [docs/redaction.md](docs/redaction.md).

**Tamper-evident audit.** Each entry carries the digest of the one before it — across rotated segments, so removing a whole file is caught too — and an alteration, deletion or reordering is detectable — `switchboard audit verify` reports the first entry that does not hold, and exits non-zero — and the log walks its own chain at startup and on a timer, so a break is found rather than waited for. `SWITCHBOARD_AUDIT_KEY` makes an edit require the key as well as file access. `switchboard audit show -id …` reconstructs an individual decision, which is what Article 12 of the EU AI Act asks logging to permit.

**Redaction and audit.** A structured JSONL record of what was sent to which provider, with redaction applied inside the log itself so no call site can skip it — which is what makes it a control rather than a convention that every application team has to remember. Content logging is refused outright unless redaction rules are configured. See [docs/redaction.md](docs/redaction.md).

**Limits that stop spend, not just report it.** Per-team request rate, concurrency ceiling and token budget over a window — MITRE ATLAS AML.M0004 — enforced against the same identity the provider's bill splits by. Refusals are 429 naming which limit was reached and when it lifts.

**Per-team cost attribution.** A gateway calls Bedrock under one role, so every team's spend lands on the bill as one identity. switchboard resolves a caller's key to a team, assumes a role with that team as the session name and a session tag, and makes the call with those credentials — so the provider bills an identity you can split on. Optionally fails closed on unattributed requests. See [docs/cost-attribution.md](docs/cost-attribution.md), including how to verify it against a real bill.

Not done yet:

- **Tool forwarding on the Bedrock backend.** The local backend forwards tool definitions, `tool_choice`, and tool results to `llama-server`, and assembles streamed tool calls back out; Bedrock does not implement `ToolCaller` yet, so tool requests naming a Bedrock model are refused rather than silently served without them. Wiring Converse's tool blocks is the next piece.
- **Redaction toward the provider.** Content is redacted before it is written to the audit log, but it still reaches the model as written. Stripping it on the way *out* is a separate feature and is not built.
- **Spend caps and chargeback reporting.** Per-team attribution now reaches the provider (see below), but there is no token budget, no enforcement when one is exceeded, and no rollup finance can read.
- **Retry and backpressure.** No throttling-aware retry yet. Rate, concurrency and token budgets are enforced (see below); retrying a throttled provider is not.
An expression layer for conditional admission is [proposed but not
built](docs/policy-proposal.md) — written down so the design, and the dependency
it would cost, can be argued with before there is code to defend.

For a security review, [docs/controls.md](docs/controls.md) maps what switchboard does against SOC 2, ISO 27001, HIPAA, NIST and EU AI Act control objectives — including, deliberately, everything it does not do.

## Contributing and contact

Issues and pull requests are welcome, and [GitHub Discussions](https://github.com/Grace/switchboard/discussions)
is the right place for questions and design arguments.

**Running this at work?** I would genuinely like to hear about it — what you put
it in front of, what broke, and what you needed that is not there. Especially if
you are hitting the cost-attribution problem above.

**grace@gracefulco.de**

## License

MIT.
