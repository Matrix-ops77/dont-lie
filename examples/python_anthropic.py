"""Example: Don't-Lie drop-in for the Anthropic Python SDK.

Run:
    pip install dontlie-anthropic
    export DONTLIE_UPSTREAM_API_KEY=sk-ant-...
    export DONTLIE_UPSTREAM_BASE_URL=https://api.anthropic.com
    export DONTLIE_PROTOCOL=anthropic-messages@1
    dontlie proxy --port 8080 &
    python3 examples/python_anthropic.py
"""
from __future__ import annotations

import dontlie_anthropic as anthropic


def main() -> None:
    # Don't-Lie auto-points at http://127.0.0.1:8080/v1. Anthropic wire
    # format is preserved by the proxy's anthropic-messages@1 adapter.
    client = anthropic.Client()
    resp = client.messages.create(
        model="claude-3-5-sonnet-20240620",
        max_tokens=32,
        messages=[{"role": "user", "content": "Say 'hello from don'tlie' and nothing else."}],
    )
    # Anthropic returns a list of content blocks; print the first text block.
    for block in resp.content:
        if getattr(block, "type", None) == "text":
            print(block.text)
            break


if __name__ == "__main__":
    main()
