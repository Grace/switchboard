<p align="center">
  <img src="docs/img/switchboard.png" alt="Switchboard" width="420">
</p>

# Switchboard

Switchboard is an AI infrastructure platform. This repository is the umbrella for
it. It is intentionally close to empty right now.

> **Looking for the LLM gateway that can prove what happened?** It's
> [Grace/switchboard-recordkeeper](https://github.com/Grace/switchboard-recordkeeper).

## Where the code is

| | |
|---|---|
| **Switchboard Recordkeeper** | [Grace/switchboard-recordkeeper](https://github.com/Grace/switchboard-recordkeeper) — the streaming inference gateway in Go: one OpenAI-compatible endpoint over AWS Bedrock and on-device llama.cpp, with capability gaps that refuse rather than degrade and a tamper-evident record of every completion. |
| **Switchboard Sidecar** | [Grace/switchboard-sidecar](https://github.com/Grace/switchboard-sidecar) — the Go inference sidecar and its Postgres-backed control plane. Released, signed and published from there. |

The code this repository used to hold has moved to those two repositories, which
share its early history. The sidecar's full history is preserved here on the
[`sidecar`](../../tree/sidecar) branch, so nothing is lost and old links still
resolve — but that branch is a snapshot, not a mirror. Work continues in
`switchboard-recordkeeper` and `switchboard-sidecar`.

## What lands here later

The pieces that are not the sidecar: the web UI, the hosted control plane, and
the client SDKs. Nothing is here yet, and this file will be replaced when
something is.
