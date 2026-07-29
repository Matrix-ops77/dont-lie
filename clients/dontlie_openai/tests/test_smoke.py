"""Public-API smoke tests for dontlie_openai.

Run: python3 -m unittest clients/dontlie_openai/tests/test_smoke.py
"""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch


def _is_available() -> bool:
    try:
        import dontlie_openai  # noqa: F401
        return True
    except ImportError:
        return False


_SKIP_REASON = "dontlie_openai not importable (pip install -e clients/dontlie_openai)"


@unittest.skipUnless(_is_available(), _SKIP_REASON)
class TestResolveBaseUrl(unittest.TestCase):
    def test_default(self):
        with patch.dict(os.environ, {}, clear=True):
            # Clear DONTLIE env vars
            for k in ("DONTLIE_BASE_URL", "DONTLIE_API_KEY"):
                os.environ.pop(k, None)
            from dontlie_openai import _resolve_api_key, _resolve_base_url
            self.assertEqual(_resolve_base_url(), "http://127.0.0.1:8080/v1")
            self.assertEqual(_resolve_api_key(), "dontlie-local")

    def test_overrides(self):
        with patch.dict(os.environ, {
            "DONTLIE_BASE_URL": "http://localhost:9000/v1/",
            "DONTLIE_API_KEY": "sk-custom",
        }):
            from dontlie_openai import _resolve_api_key, _resolve_base_url
            self.assertEqual(_resolve_base_url(), "http://localhost:9000/v1")  # trailing / stripped
            self.assertEqual(_resolve_api_key(), "sk-custom")


class TestReexports(unittest.TestCase):
    def test_openai_reexports(self):
        import dontlie_openai as dl

        # Must be re-exported from the real openai SDK
        import openai
        self.assertIs(dl.OpenAI, openai.OpenAI)
        self.assertTrue(hasattr(dl, "AsyncOpenAI"))
        # Convenience alias
        self.assertIs(dl.Client, dl._DontlieOpenAI)


class TestDontlieClientInit(unittest.TestCase):
    def test_Client_injects_defaults(self):
        for k in ("DONTLIE_BASE_URL", "DONTLIE_API_KEY"):
            os.environ.pop(k, None)
        from dontlie_openai import Client
        # Use mock to capture the kwargs without actually opening the network
        with patch("dontlie_openai._OpenAI.__init__", return_value=None) as init:
            Client()
        self.assertTrue(init.called)
        kwargs = init.call_args.kwargs
        self.assertEqual(kwargs["base_url"], "http://127.0.0.1:8080/v1")
        self.assertEqual(kwargs["api_key"], "dontlie-local")

    def test_Client_respects_user_overrides(self):
        from dontlie_openai import Client
        with patch("dontlie_openai._OpenAI.__init__", return_value=None) as init:
            Client(base_url="http://my-proxy:1234/v1", api_key="my-key")
        kwargs = init.call_args.kwargs
        self.assertEqual(kwargs["base_url"], "http://my-proxy:1234/v1")  # user override
        self.assertEqual(kwargs["api_key"], "my-key")


if __name__ == "__main__":
    unittest.main()
