"""Public-API smoke tests for dontlie_requests."""
from __future__ import annotations

import os
import unittest
from unittest.mock import MagicMock, patch


class TestRouting(unittest.TestCase):
    def test_chat_completions_url_is_rewritten(self):
        for k in ("DONTLIE_BASE_URL",):
            os.environ.pop(k, None)
        import dontlie_requests as r
        original = "https://api.openai.com/v1/chat/completions"
        with patch("dontlie_requests._requests.post", return_value=MagicMock()) as p:
            r.post(original, json={"a": 1})
        self.assertEqual(p.call_args.args[0], "http://127.0.0.1:8080/v1/chat/completions")

    def test_non_chat_url_is_unchanged(self):
        import dontlie_requests as r
        with patch("dontlie_requests._requests.get", return_value=MagicMock()) as g:
            r.get("https://example.com/static")
        self.assertEqual(g.call_args.args[0], "https://example.com/static")

    def test_authorization_is_stripped(self):
        import dontlie_requests as r
        with patch("dontlie_requests._requests.post", return_value=MagicMock()) as p:
            r.post(
                "https://api.openai.com/v1/chat/completions",
                json={"model": "x"},
                headers={"authorization": "Bearer sk-REAL", "x-other": "1"},
            )
        sent_headers = p.call_args.kwargs["headers"]
        self.assertNotIn("authorization", sent_headers)
        # original header is case-preserved in the kept set
        self.assertIn("x-other", sent_headers)

    def test_session_inherits_routing(self):
        import dontlie_requests as r
        s = r.session()
        with patch.object(r._requests.Session, "request", return_value=MagicMock()) as p:
            s.post("https://api.openai.com/v1/chat/completions", json={})
        self.assertEqual(p.call_args.args[1], "http://127.0.0.1:8080/v1/chat/completions")

    def test_session_non_chat_url(self):
        import dontlie_requests as r
        s = r.session()
        with patch.object(r._requests.Session, "request", return_value=MagicMock()) as p:
            s.get("https://example.com/api")
        self.assertEqual(p.call_args.args[1], "https://example.com/api")


class TestResolveBaseUrl(unittest.TestCase):
    def test_default(self):
        os.environ.pop("DONTLIE_BASE_URL", None)
        from dontlie_requests import _resolve_base_url
        self.assertEqual(_resolve_base_url(), "http://127.0.0.1:8080")

    def test_override(self):
        with patch.dict(os.environ, {"DONTLIE_BASE_URL": "http://localhost:9000/"}):
            from dontlie_requests import _resolve_base_url
            self.assertEqual(_resolve_base_url(), "http://localhost:9000")


if __name__ == "__main__":
    unittest.main()
