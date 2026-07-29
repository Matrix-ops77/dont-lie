"""dontlie_anthropic — drop-in for the Anthropic SDK that routes through Don't-Lie.

Usage:

    # 1. start the don'tlie proxy (use the anthropic-messages protocol)
    #    export DONTLIE_UPSTREAM_API_KEY=sk-ant-...
    #    export DONTLIE_UPSTREAM_BASE_URL=https://api.anthropic.com
    #    export DONTLIE_PROTOCOL=anthropic-messages@1
    #    dontlie proxy --port 8080

    # 2. import as if it were anthropic:
    import dontlie_anthropic as anthropic
    client = anthropic.Anthropic()
    resp = client.messages.create(
        model="claude-3-5-sonnet-20240620",
        max_tokens=256,
        messages=[{"role": "user", "content": "hello"}],
    )

Env vars:
    DONTLIE_BASE_URL  default http://127.0.0.1:8080/v1 — the proxy's anthropic-compatible endpoint
    DONTLIE_API_KEY   default "dontlie-local" — placeholder for the bare-metal client
    The real provider key is forwarded to the proxy via DONTLIE_UPSTREAM_API_KEY.
"""
from __future__ import annotations

import os as _os

# Re-export the public surface of the official Anthropic SDK.
from anthropic import *
from anthropic import Anthropic as _Anthropic

_DEFAULT_BASE_URL = "http://127.0.0.1:8080/v1"
_DEFAULT_API_KEY = "dontlie-local"


def _resolve_base_url() -> str:
    return _os.environ.get("DONTLIE_BASE_URL", _DEFAULT_BASE_URL).rstrip("/")


def _resolve_api_key() -> str:
    return _os.environ.get("DONTLIE_API_KEY", _DEFAULT_API_KEY)


class _DontlieAnthropic(_Anthropic):
    def __init__(self, **kwargs):
        kwargs.setdefault("base_url", _resolve_base_url())
        kwargs.setdefault("api_key", _resolve_api_key())
        super().__init__(**kwargs)


Client = _DontlieAnthropic  # alias


__all__ = [name for name in dir() if not name.startswith("_")] + ["Client"]
