"""Local stand-in for OpenAI, Anthropic and Gemini.

Speaks the subset of each provider's wire format that internal/gateway/adapter.go
normalizes, streaming and nonstreaming. It exists so the gateway can be exercised
end to end without provider credentials, network egress or per-token cost, and so
retry, circuit-breaker and failover paths can be driven deterministically.

Fault injection, by environment variable:
  MOCK_STATUS        return this HTTP status instead of a completion (e.g. 429, 503)
  MOCK_FAIL_FIRST    fail this many requests with MOCK_STATUS, then succeed
  MOCK_DELAY_MS      sleep before responding, to exercise timeouts and deadlines
  MOCK_TEXT          completion text to return (default: a fixed marker string)
Standard library only; it runs on a bare python image with nothing installed.
"""
import json
import os
import re
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TEXT = os.environ.get("MOCK_TEXT", "switchboard mock provider reached")
DELAY_MS = int(os.environ.get("MOCK_DELAY_MS", "0"))
STATUS = int(os.environ.get("MOCK_STATUS", "0"))
FAIL_FIRST = int(os.environ.get("MOCK_FAIL_FIRST", "0"))

_lock = threading.Lock()
_seen = 0


def _should_fail():
    """Fail while inside the MOCK_FAIL_FIRST window, or always if MOCK_STATUS alone is set."""
    global _seen
    if STATUS == 0:
        return False
    if FAIL_FIRST == 0:
        return True
    with _lock:
        _seen += 1
        return _seen <= FAIL_FIRST


def _sse(chunks):
    return "".join("data: " + json.dumps(c) + "\n\n" for c in chunks) + "data: [DONE]\n\n"


def openai_body(stream):
    if not stream:
        return {
            "choices": [{"index": 0, "message": {"content": TEXT}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 11, "completion_tokens": 7},
        }
    head, tail = TEXT[: len(TEXT) // 2], TEXT[len(TEXT) // 2 :]
    return _sse([
        {"choices": [{"index": 0, "delta": {"content": head}, "finish_reason": None}]},
        {"choices": [{"index": 0, "delta": {"content": tail}, "finish_reason": None}]},
        {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
         "usage": {"prompt_tokens": 11, "completion_tokens": 7}},
    ])


def anthropic_body(stream):
    if not stream:
        return {
            "content": [{"type": "text", "text": TEXT}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 11, "output_tokens": 7},
        }
    head, tail = TEXT[: len(TEXT) // 2], TEXT[len(TEXT) // 2 :]
    return _sse([
        {"type": "content_block_start", "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_delta", "delta": {"type": "text_delta", "text": head}},
        {"type": "content_block_delta", "delta": {"type": "text_delta", "text": tail}},
        {"type": "message_delta", "delta": {"stop_reason": "end_turn"},
         "usage": {"input_tokens": 11, "output_tokens": 7}},
    ])


def gemini_body(stream):
    def candidate(text, finish):
        return {"candidates": [{"index": 0, "content": {"parts": [{"text": text}]},
                                "finishReason": finish}],
                "usageMetadata": {"promptTokenCount": 11, "candidatesTokenCount": 7}}
    if not stream:
        return candidate(TEXT, "STOP")
    head, tail = TEXT[: len(TEXT) // 2], TEXT[len(TEXT) // 2 :]
    return _sse([candidate(head, ""), candidate(tail, "STOP")])


GEMINI = re.compile(r"^/v1beta/models/[^/:]+:(generateContent|streamGenerateContent)$")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("mockprovider %s\n" % (fmt % args))

    def _send(self, status, body, content_type="application/json"):
        raw = body if isinstance(body, bytes) else (
            body if isinstance(body, str) else json.dumps(body)).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        # Unauthenticated liveness probe for compose health checks.
        if self.path == "/healthz":
            return self._send(200, {"ok": True})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw or b"{}")
        except ValueError:
            return self._send(400, {"error": "invalid json"})

        if DELAY_MS:
            time.sleep(DELAY_MS / 1000.0)
        if _should_fail():
            return self._send(STATUS, {"error": {"type": "mock_injected", "status": STATUS}})

        path = self.path.split("?")[0]
        if path == "/v1/chat/completions":
            stream = bool(req.get("stream"))
            body = openai_body(stream)
        elif path == "/v1/messages":
            stream = bool(req.get("stream"))
            body = anthropic_body(stream)
        elif GEMINI.match(path):
            stream = path.endswith(":streamGenerateContent")
            body = gemini_body(stream)
        else:
            return self._send(404, {"error": "unsupported path: " + path})

        if isinstance(body, str):
            return self._send(200, body, "text/event-stream")
        self._send(200, body)


def main():
    host = os.environ.get("MOCK_HOST", "127.0.0.1")
    port = int(os.environ.get("MOCK_PORT", "9090"))
    server = ThreadingHTTPServer((host, port), Handler)
    sys.stderr.write("mockprovider listening on %s:%d\n" % (host, port))
    sys.stderr.flush()
    server.serve_forever()


if __name__ == "__main__":
    main()
