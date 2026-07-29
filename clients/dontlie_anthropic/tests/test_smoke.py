"""Public-API smoke tests for dontlie_anthropic."""
from __future__ import annotations

import os
import unittest
from unittest.mock import patch


class TestResolveBaseUrl(unittest.TestCase):
    def test_default(self):
        for k in ("DONTLIE_BASE_URL", "DONTLIE_API_KEY"):
            os.environ.pop(k, None)
        from dontlie_anthropic import _resolve_api_key, _resolve_base_url
        self.assertEqual(_resolve_base_url(), "http://127.0.0.1:8080/v1")
        self.assertEqual(_resolve_api_key(), "dontlie-local")

    def test_overrides(self):
        with patch.dict(os.environ, {
            "DONTLIE_BASE_URL": "http://localhost:9000/v1/",
            "DONTLIE_API_KEY": "sk-custom",
        }):
            from dontlie_anthropic import _resolve_api_key, _resolve_base_url
            self.assertEqual(_resolve_base_url(), "http://localhost:9000/v1")
            self.assertEqual(_resolve_api_key(), "sk-custom")


class TestReexports(unittest.TestCase):
    def test_anthropic_reexports(self):
        import anthropic
        import dontlie_anthropic as dl
        self.assertIs(dl.Anthropic, anthropic.Anthropic)
        self.assertTrue(hasattr(dl, "AsyncAnthropic"))
        self.assertIs(dl.Client, dl._DontlieAnthropic)


class TestDontlieClientInit(unittest.TestCase):
    def test_Client_injects_defaults(self):
        for k in ("DONTLIE_BASE_URL", "DONTLIE_API_KEY"):
            os.environ.pop(k, None)
        from dontlie_anthropic import Client
        with patch("dontlie_anthropic._Anthropic.__init__", return_value=None) as init:
            Client()
        kwargs = init.call_args.kwargs
        self.assertEqual(kwargs["base_url"], "http://127.0.0.1:8080/v1")
        self.assertEqual(kwargs["api_key"], "dontlie-local")

    def test_Client_respects_user_overrides(self):
        from dontlie_anthropic import Client
        with patch("dontlie_anthropic._Anthropic.__init__", return_value=None) as init:
            Client(base_url="http://my-proxy:1234/v1", api_key="my-key")
        kwargs = init.call_args.kwargs
        self.assertEqual(kwargs["base_url"], "http://my-proxy:1234/v1")
        self.assertEqual(kwargs["api_key"], "my-key")


if __name__ == "__main__":
    unittest.main()
