"""Tests for the alerts webhook module."""

from __future__ import annotations

import json
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from dontlie.alerts import (
    Alert,
    AlertSink,
    alert_chain_break,
    alert_key_revoked,
    send,
    send_event,
)


class _CollectingHandler(BaseHTTPRequestHandler):
    received: list[bytes] = []
    status: int = 200

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self.received.append(self.rfile.read(length))
        self.send_response(self.status)
        self.end_headers()

    def log_message(self, *_args: object) -> None:  # silence stderr
        pass


class WebhookDeliveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _CollectingHandler.received = []
        _CollectingHandler.status = 200
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _CollectingHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_send_event_posts_signed_payload(self) -> None:
        _CollectingHandler.received.clear()
        sink = AlertSink(
            name="test",
            url=f"http://127.0.0.1:{self.port}/hook",
            secret="topsecret",
        )
        alert = Alert("title", "body", severity="warning", tags=("x", "y"))
        status = send_event(sink, alert)
        self.assertEqual(status, 200)
        self.assertEqual(len(_CollectingHandler.received), 1)
        body = _CollectingHandler.received[0]
        payload = json.loads(body)
        self.assertEqual(payload["title"], "title")
        self.assertEqual(payload["severity"], "warning")
        self.assertEqual(payload["tags"], ["x", "y"])

    def test_send_to_multiple_sinks(self) -> None:
        _CollectingHandler.received.clear()
        sinks = [
            AlertSink(name="a", url=f"http://127.0.0.1:{self.port}/a"),
            AlertSink(name="b", url=f"http://127.0.0.1:{self.port}/b"),
        ]
        results = send(sinks, alert_chain_break(7, "hash mismatch"))
        self.assertEqual(results, {"a": 200, "b": 200})

    def test_chain_break_alert(self) -> None:
        alert = alert_chain_break(42, "signature invalid")
        self.assertEqual(alert.severity, "critical")
        self.assertIn("42", alert.body)
        self.assertIn("chain", alert.tags)

    def test_key_revoked_alert(self) -> None:
        alert = alert_key_revoked("abcdefgh1234567890")
        self.assertEqual(alert.severity, "warning")
        self.assertIn("abcdefgh", alert.body)


if __name__ == "__main__":
    unittest.main()
