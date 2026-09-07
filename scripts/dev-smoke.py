"""End-to-end smoke test against the local stack.

Runs inside the shared network namespace so it can reach the gateway's
loopback listener, the same way an application container does on ECS.
Exercises a nonstreaming and a streaming completion and reports what the
gateway actually returned.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

GATEWAY = os.environ.get("GATEWAY_URL", "http://127.0.0.1:8080")
TOKEN = os.environ["LOCAL_TOKEN"]


def wait_ready(seconds=90):
    """The gateway polls the control plane every 15s; readiness follows the first
    verified policy, so this waits rather than races."""
    deadline = time.time() + seconds
    last = ""
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(GATEWAY + "/readyz", timeout=3) as r:
                if r.status == 200:
                    return True
                last = "status %d" % r.status
        except urllib.error.HTTPError as e:
            last = "status %d" % e.code
        except Exception as e:
            last = str(e)
        time.sleep(2)
    print("  gateway never became ready: %s" % last)
    return False


def chat(stream):
    body = json.dumps({
        "model": "preferred",
        "stream": stream,
        "max_tokens": 64,
        "messages": [{"role": "user", "content": "Say hello."}],
    }).encode()
    req = urllib.request.Request(GATEWAY + "/v1/chat/completions", data=body, method="POST")
    req.add_header("Authorization", "Bearer " + TOKEN)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.status, r.read().decode(), dict(r.headers)


def main():
    failures = []

    print("waiting for gateway readiness")
    if not wait_ready():
        sys.exit(1)
    print("  /readyz 200")

    print("nonstreaming completion")
    try:
        status, raw, _ = chat(False)
        payload = json.loads(raw)
        text = payload["choices"][0]["message"]["content"]
        print("  %d  content=%r" % (status, text))
        if status != 200 or not text:
            failures.append("nonstreaming returned %d" % status)
    except urllib.error.HTTPError as e:
        print("  HTTP %d  %s" % (e.code, e.read().decode()[:400]))
        failures.append("nonstreaming failed")
    except Exception as e:
        print("  %s" % e)
        failures.append("nonstreaming failed")

    print("streaming completion")
    try:
        status, raw, headers = chat(True)
        chunks = [l for l in raw.splitlines() if l.startswith("data:")]
        print("  %d  content-type=%s  sse_frames=%d"
              % (status, headers.get("Content-Type", "?"), len(chunks)))
        if status != 200 or not chunks:
            failures.append("streaming returned %d with %d frames" % (status, len(chunks)))
    except urllib.error.HTTPError as e:
        print("  HTTP %d  %s" % (e.code, e.read().decode()[:400]))
        failures.append("streaming failed")
    except Exception as e:
        print("  %s" % e)
        failures.append("streaming failed")

    if failures:
        print("\nFAILED: " + "; ".join(failures))
        sys.exit(1)
    print("\nOK: request traversed client -> gateway -> signed policy -> provider")


if __name__ == "__main__":
    main()
