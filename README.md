<p align="center">
  <img src="docs/img/switchboard.png" alt="Switchboard" width="420">
</p>

# Switchboard

Infrastructure for AI execution that can explain itself: routing decided by a
signed policy, evidence of what actually ran, and telemetry whose meaning is
traceable rather than assumed.

This repository is the umbrella. The code is in the repositories below.

> ### Something to look at first
>
> **[The normalization inspector](https://grace.github.io/demos/genai-interlingua/inspector/)**
> — click any attribute on a captured span to see which source key produced it,
> what the reading turned on, and what the translation could not carry. It runs
> the real Go normalizer compiled to WebAssembly, in your browser, so the page
> cannot disagree with the tool about what a span becomes.
>
> **[The loss landscape](https://grace.github.io/demos/genai-interlingua/conformance.html)**
> — what six instrumentation libraries disagree about, measured rather than
> asserted.

## The projects

| | |
|---|---|
| **[genai-interlingua](https://github.com/Grace/genai-interlingua)** | A normalizer for GenAI telemetry. Six instrumentation libraries emit the same facts under different names — and worse, the same name for different things. This translates between those dialects toward the OpenTelemetry GenAI semantic conventions and records *why* each mapping was valid, what it cost, and which mapping artifact decided. Ships as a CLI, a Collector processor, and the WASM demo above. |
| **[switchboard-sidecar](https://github.com/Grace/switchboard-sidecar)** | The inference gateway. One OpenAI-compatible endpoint on loopback, routed across OpenAI, Anthropic, Gemini and Bedrock by an Ed25519-signed policy it cannot itself edit, with per-provider circuit breaking, failover, and per-attempt token accounting. Postgres-backed control plane with row-level tenant isolation. |
| **[switchboard-recordkeeper](https://github.com/Grace/switchboard-recordkeeper)** | The evidence tier. A hash-chained, tamper-evident record of every completion, with rotation and retention it owns deliberately, and verification a third party can perform without running this software. Built for the retention and reconstructability obligations that regulated deployments carry. |

`genai-interlingua` is deliberately independent. It is useful without any of the
rest of this, which is why it is not a component of it.

## What these were built to find out

The thread through all three is that **a system making a claim is not the same as
evidence for it**, and the interesting bugs live in the gap:

- `requested model` ≠ `routed model` ≠ `served model`
- a successful response ≠ a complete execution
- observability telemetry ≠ durable audit evidence
- matching attribute names ≠ semantic equivalence
- a hash chain ≠ proof against every form of tampering
- a number ≠ a measurement, without a defensible denominator

Each of those distinctions has caught a real defect here. Two worth reading:

**A failed provider attempt still spends tokens.** A request that failed over was
exporting one span naming the provider that answered, carrying the sum of every
attempt's usage — so a provider that consumed 612 input tokens was recorded as
having consumed 1,098. The conformance test passed and always would have: every
attribute name was correct. It was an attribution defect, not a vocabulary one.
Fixed by giving every attempt its own span &mdash; on the
[`child-spans`](https://github.com/Grace/switchboard-sidecar/tree/child-spans) branch, not yet
merged, so `main` still carries the single-span shape.

**Capturing the real libraries found bugs in five of seven.**
[`docs/findings.md`](https://github.com/Grace/genai-interlingua/blob/main/docs/findings.md)
records what happened when hand-built fixtures were replaced with spans captured
from the libraries actually running — including a bug in the one span with the
best claim to being already correct. None was reachable by a green test suite.

## Status

`genai-interlingua` and `switchboard-sidecar` are built, tested and published —
with the caveat above: some of what is described here is on branches rather than
on `main`, and where that is true this page says so.
`switchboard-recordkeeper` is built and unreleased. A hosted control plane, a web
console and a multi-tenant deployment are designed and **not built**; where this
documentation describes them it says so.

The sidecar's full early history is preserved on the
[`sidecar`](../../tree/sidecar) branch of this repository, so older links still
resolve. That branch is a snapshot, not a mirror.
