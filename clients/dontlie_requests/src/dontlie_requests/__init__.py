"""dontlie_requests — drop-in for `requests` that routes chat-completions through Don't-Lie.

Usage:

    # 1. start the don'tlie proxy (it must echo back arbitrary POST bodies,
    #    so leave DONTLIE_UPSTREAM_BASE_URL unset OR point at a passthrough
    #    echo server of your own).
    #    dontlie proxy --port 8080

    # 2. import as if it were requests:
    import dontlie_requests as requests
    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",  # any URL the proxy accepts
        json={"model": "MiniMax-M3", "messages": [...]},
        headers={"authorization": "Bearer sk-..."},
    )

    # The URL is rewritten to the local proxy. The real provider key is
    # forwarded to the proxy via DONTLIE_UPSTREAM_API_KEY (set when the
    # proxy starts). Any other URL is passed through unchanged.
"""
from __future__ import annotations

import os as _os

import requests as _requests
from requests import (
    PreparedRequest,
    Request,
    Response,
    Session,
    api,
    cookies,
    exceptions,
    hooks,
    models,
    status_codes,
    utils,
)

_DEFAULT_BASE_URL = "http://127.0.0.1:8080"
_CHAT_PATH = "/v1/chat/completions"


def _resolve_base_url() -> str:
    return _os.environ.get("DONTLIE_BASE_URL", _DEFAULT_BASE_URL).rstrip("/")


def _should_proxy(url: str) -> bool:
    """Only rewrite chat-completions calls. Leave everything else alone."""
    if not url:
        return False
    return url.endswith(("/v1/chat/completions", "/chat/completions"))


def _rewrite(url: str) -> str:
    return _resolve_base_url() + "/v1/chat/completions"


def _strip_authorization(headers: dict) -> tuple[dict, str | None]:
    """Remove the Authorization header so it isn't sent to the proxy.
    The proxy reads the real key from DONTLIE_UPSTREAM_API_KEY."""
    headers = dict(headers or {})
    auth = None
    for k in list(headers.keys()):
        if k.lower() == "authorization":
            auth = headers.pop(k)
    return headers, auth


def post(url, **kwargs):
    if _should_proxy(url):
        url = _rewrite(url)
        kwargs.setdefault("headers", {})
        kwargs["headers"], _ = _strip_authorization(kwargs.get("headers", {}))
    return _requests.post(url, **kwargs)


def get(url, **kwargs):
    return _requests.get(url, **kwargs)


def request(method, url, **kwargs):
    if method.upper() == "POST" and _should_proxy(url):
        url = _rewrite(url)
        kwargs.setdefault("headers", {})
        kwargs["headers"], _ = _strip_authorization(kwargs.get("headers", {}))
    return _requests.request(method, url, **kwargs)


def session():
    """Return a Session whose `post` / `request` route chat-completions."""
    return _ProxiedSession()


class _ProxiedSession(_requests.Session):
    def request(self, method, url, **kwargs):  # type: ignore[override]
        if method.upper() == "POST" and _should_proxy(url):
            url = _rewrite(url)
            kwargs.setdefault("headers", {})
            kwargs["headers"], _ = _strip_authorization(kwargs.get("headers", {}))
        return super().request(method, url, **kwargs)


__all__ = [
    "PreparedRequest",
    "Request",
    "Response",
    "Session",
    "api",
    "cookies",
    "exceptions",
    "get",
    "hooks",
    "models",
    "post",
    "request",
    "session",
    "status_codes",
    "utils",
]
