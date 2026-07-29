"""Example: Don't-Lie drop-in for the OpenAI Python SDK.

Run:
    pip install dontlie-openai
    export DONTLIE_UPSTREAM_API_KEY=sk-...
    dontlie proxy --port 8080 &
    python3 examples/python_openai.py
"""
from __future__ import annotations

import dontlie_openai as openai


def main() -> None:
    # Don't-Lie auto-points at http://127.0.0.1:8080/v1. The user's code
    # uses the same OpenAI SDK surface; only the import is different.
    client = openai.Client()
    resp = client.chat.completions.create(
        model="MiniMax-M3",
        messages=[{"role": "user", "content": "Say 'hello from don'tlie' and nothing else."}],
        max_tokens=32,
    )
    print(resp.choices[0].message.content)


if __name__ == "__main__":
    main()
