"""Tests for the analytics module."""

from __future__ import annotations

import json
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from dontlie.analytics import (
    Analytics,
    AnalyticsError,
    Event,
    HttpSink,
    InMemorySink,
    capture_demo_run,
    capture_export,
    capture_receipt,
    capture_tampered,
    capture_verified,
)


class InMemorySinkTest(unittest.TestCase):
    def test_capture_records_events(self) -> None:
        capture_receipt(1, "mock-1")
        capture_verified(1, True)
        capture_tampered(2, "sha256 mismatch")
        capture_export("bundle.json", 3)
        capture_demo_run(3)
        sink = InMemorySink()
        Analytics([sink]).emit("receipt.captured", id=42)
        self.assertEqual(sink.names()[-1], "receipt.captured")


class EventTest(unittest.TestCase):
    def test_event_to_dict_round_trip(self) -> None:
        event = Event(name="receipt.verified", properties={"id": 1, "ok": True})
        data = event.to_dict()
        self.assertEqual(data["event"], "receipt.verified")
        self.assertEqual(data["properties"]["id"], 1)
        self.assertTrue(data["properties"]["ok"])


class _CollectingHandler(BaseHTTPRequestHandler):
    received: list[bytes] = []

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0"))
        self.received.append(self.rfile.read(length))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args: object) -> None:
        pass


class HttpSinkTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        _CollectingHandler.received = []
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), _CollectingHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()

    def test_http_sink_posts_event(self) -> None:
        _CollectingHandler.received.clear()
        sink = HttpSink(f"http://127.0.0.1:{self.port}/capture")
        event = Event(name="receipt.captured", properties={"id": 1})
        sink.emit(event)
        self.assertEqual(len(_CollectingHandler.received), 1)
        body = json.loads(_CollectingHandler.received[0])
        self.assertEqual(body["event"], "receipt.captured")
        self.assertEqual(body["properties"]["id"], 1)


class AnalyticsFanOutTest(unittest.TestCase):
    def test_fan_out_calls_all_sinks(self) -> None:
        a = InMemorySink()
        b = InMemorySink()
        Analytics([a, b]).emit("receipt.captured", id=1)
        self.assertEqual(len(a.events), 1)
        self.assertEqual(len(b.events), 1)

    def test_sink_failure_does_not_break_others(self) -> None:
        class BrokenSink:
            def emit(self, event: Event) -> None:
                raise AnalyticsError("boom")

        a = InMemorySink()
        Analytics([BrokenSink(), a]).emit("receipt.captured", id=1)
        self.assertEqual(len(a.events), 1)


if __name__ == "__main__":
    unittest.main()
