"""Issue a chat completion through the dontlie proxy. Used by run_offline_demo.sh.
Reads prompt from stdin, prints the response JSON to stdout."""
import json
import os
import sys
import urllib.request

proxied = os.environ.get("OPENAI_BASE_URL", "http://127.0.0.1:9877/v1")
url = proxied.rstrip("/") + "/chat/completions"

prompt = sys.stdin.read()
body = json.dumps({
    "model": "mock-1",
    "messages": [{"role": "user", "content": prompt}],
}).encode()

req = urllib.request.Request(url, data=body, headers={"content-type": "application/json"})
with urllib.request.urlopen(req, timeout=10) as r:
    sys.stdout.write(r.read().decode())
    sys.stdout.write("\n")
