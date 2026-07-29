"""dontlie_openai — drop-in for the OpenAI SDK that routes through Don't-Lie.

Usage:

    # 1. start the don'tlie proxy (one terminal)
    #    export DONTLIE_UPSTREAM_API_KEY=sk-...
    #    export DONTLIE_UPSTREAM_BASE_URL=https://api.minimax.io/v1
    #    dontlie proxy --port 8080

    # 2. import as if it were openai:
    import dontlie_openai as openai
    client = openai.OpenAI()  # points at http://127.0.0.1:8080/v1 by default
    resp = client.chat.completions.create(
        model="MiniMax-M3",
        messages=[{"role": "user", "content": "hello"}],
    )

Env vars:
    DONTLIE_BASE_URL  default http://127.0.0.1:8080/v1
    DONTLIE_API_KEY   default "dontlie-local" (placeholder for SDKs that require one)
    DONTLIE_UPSTREAM_API_KEY  forwarded to the proxy (STARTED WITH THE PROXY)
    DONTLIE_UPSTREAM_BASE_URL forwarded to the proxy (STARTED WITH THE PROXY)
"""
from __future__ import annotations

import os as _os

# Re-export the public surface of the official OpenAI SDK verbatim.
# The proxy intercepts every request at the network layer, so the user's
# application code is unchanged.
from openai import *
from openai import OpenAI as _OpenAI

_DEFAULT_BASE_URL = "http://127.0.0.1:8080/v1"
_DEFAULT_API_KEY = "dontlie-local"


def _resolve_base_url() -> str:
    return _os.environ.get("DONTLIE_BASE_URL", _DEFAULT_BASE_URL).rstrip("/")


def _resolve_api_key() -> str:
    return _os.environ.get("DONTLIE_API_KEY", _DEFAULT_API_KEY)


# Convenience: a module-level `Client` that already points at the proxy.
# Equivalent to: openai.OpenAI(base_url=DONTLIE_BASE_URL, api_key=DONTLIE_API_KEY)
class _DontlieOpenAI(_OpenAI):
    def __init__(self, **kwargs):
        kwargs.setdefault("base_url", _resolve_base_url())
        kwargs.setdefault("api_key", _resolve_api_key())
        super().__init__(**kwargs)


Client = _DontlieOpenAI  # alias


__all__ = [name for name in dir() if not name.startswith("_")] + ["Client"]
