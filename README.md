<p align="center">
  <img src="docs/img/switchboard.png" alt="Switchboard" width="420">
</p>

# Switchboard

Switchboard is an AI infrastructure platform. This repository is the umbrella for
it. It is intentionally close to empty right now.

## Where the code is

| | |
|---|---|
| **Switchboard Sidecar** | [Grace/switchboard-sidecar](https://github.com/Grace/switchboard-sidecar) — the Go inference sidecar and its Postgres-backed control plane. Released, signed and published from there. |

Everything this repository used to hold was the sidecar, and it has moved. Its
full history is preserved here on the [`sidecar`](../../tree/sidecar) branch, so
nothing is lost and old links still resolve — but that branch is a snapshot, not
a mirror. Work continues in `switchboard-sidecar`.

## What lands here later

The pieces that are not the sidecar: the web UI, the hosted control plane, and
the client SDKs. Nothing is here yet, and this file will be replaced when
something is.
