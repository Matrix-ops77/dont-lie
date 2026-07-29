"""Example: Don't-Lie drop-in for `requests`.

Run:
    pip install dontlie-requests
    export DONTLIE_UPSTREAM_API_KEY=sk-...
    dontlie proxy --port 8080 &
    python3 examples/python_requests.py
"""
from __future__ import annotations

import dontlie_requests as requests


def main() -> None:
    # dontlie_requests rewrites any URL ending in /chat/completions to
    # the local proxy. The Authorization header is stripped (the proxy
    # reads the real key from DONTLIE_UPSTREAM_API_KEY).
    resp = requests.post(
        "https://api.minimax.io/v1/chat/completions",
        json={
            "model": "MiniMax-M3",
            "messages": [{"role": "user", "content": "Say 'hello from don'tlie' and nothing else."}],
            "max_tokens": 32,
        },
        headers={"authorization": "Bearer dontlie-local"},
        timeout=30,
    )
    resp.raise_for_status()
    body = resp.json()
    print(body["choices"][0]["message"]["content"])


if __name__ == "__main__":
    main()
