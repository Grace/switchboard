# switchboard

**An LLM gateway for environments where the model provider is not your choice to make.**

One OpenAI-compatible endpoint in front of models running on your own hardware and models running in your own AWS account. Callers ask for a model by name; switchboard decides whether that means a `llama.cpp` process on this laptop or Bedrock in `us-east-1`. Nothing on the client side changes when the answer changes.

```
client ──▶ /v1/chat/completions ──▶ registry ──┬──▶ local   (llama.cpp, on-device)
             OpenAI dialect                    └──▶ bedrock (AWS Converse API)
```

## Why

Most teams that adopt an LLM discover the same constraint in the same order: the data cannot leave the network, the provider is chosen by someone else, and the choice changes. That points at a gateway — a layer that owns provider selection, keeps request and response under your control, and gives every internal caller one stable interface to build against.

switchboard is a small, readable implementation of that shape. It runs on a laptop with no cloud account at all, and it runs against Bedrock with an instance role, using the same config file and the same API.

## Quickstart

```sh
go install github.com/Grace/switchboard/cmd/switchboard@latest

switchboard init                # writes ~/.switchboard/switchboard.json
switchboard models              # list what's configured
switchboard serve               # http://127.0.0.1:11435
```

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
| `GET /healthz` | Liveness. |

## Design notes

**The backend interface is four methods.** `Name`, `Models`, `Chat`, `Close`. Adding SageMaker, Azure OpenAI, MLX, or a raw cgo binding means implementing that and nothing else — no changes to the server, the registry, or the wire format.

**Capabilities are negotiated, not assumed.** Not every backend can do everything, so the extras are optional interfaces asked for at the door: `Connector` for backends that load and unload weights, `ToolCaller` for backends that can forward tool definitions. A backend that can't do a thing simply doesn't implement it, and the server turns the request away with a clear error. The alternative — accepting a request with tools and quietly returning prose — leaves the caller no way to discover that the tools never reached the model.

**Bedrock goes through the Converse API,** not per-model `InvokeModel` payloads. One code path covers every model family Bedrock hosts, so adding a model is a config line rather than a new marshaller.

**The roster is visible without credentials.** The Bedrock client is built lazily on first use, so switchboard starts, serves local models, and lists everything it knows about on a machine that has never seen an AWS credential. A backend that errors during listing is skipped rather than failing the whole response — one unreachable region shouldn't hide the models running on your desk.

**Local models are reaped when idle.** `idle_timeout` unloads a model that hasn't been asked anything, which matters when the weights are competing with everything else for memory.

**Streaming failures are reported honestly.** Once SSE headers are out, the status code is spent; a mid-stream backend error becomes an error frame before `[DONE]` rather than a truncated response that looks like a successful short answer.

## Status

Working: routing, both backends, streaming and non-streaming completions, token usage accounting, model lifecycle, graceful drain on shutdown. The HTTP surface and the tool-translation layer are covered by tests.

Not done yet:

- **Tool forwarding in the backends.** The neutral types, the OpenAI translation both directions, streamed tool-call deltas, and `finish_reason` correction are all implemented and tested — but neither shipped backend implements `ToolCaller`, so tool requests are currently refused rather than served. Wiring Bedrock's Converse tool blocks is the next piece.
- **I/O controls.** Redaction of request and response content, and a structured audit log of what was sent to which provider, are the reason a gateway earns its place in a regulated network. Not built.
- **Retry and backpressure.** No throttling-aware retry, concurrency ceiling, or token budget yet.

## License

MIT.
