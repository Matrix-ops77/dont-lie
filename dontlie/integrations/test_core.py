import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

_TMP = tempfile.mkdtemp(prefix="dontlie-integrations-test-")
os.environ["DONTLIE_KEY_DIR"] = str(Path(_TMP) / "keys")
os.environ["DONTLIE_DB"] = str(Path(_TMP) / "vault.db")
os.environ["DONTLIE_NO_WAL"] = "1"

from dontlie import sign as signing
from dontlie import storage
from dontlie.integrations import (
    ActionEvent,
    ActionRecorder,
    RecordingError,
    correlation_scope,
    record_action,
)


def fresh_state(name: str) -> None:
    signing.KEY_DIR.mkdir(parents=True, exist_ok=True)
    for path in (signing.PRIVATE_FILE, signing.PUBLIC_FILE, signing.KEY_ID_FILE):
        path.unlink(missing_ok=True)
    signing.generate()
    storage.DB_PATH = Path(_TMP) / name
    with sqlite3.connect(storage.DB_PATH) as connection:
        connection.executescript(storage.SCHEMA)
        connection.execute("DELETE FROM receipts")
        connection.execute("DELETE FROM key_history")
        connection.execute("DELETE FROM sqlite_sequence WHERE name='receipts'")


class IntegrationRecordingTest(unittest.TestCase):
    def setUp(self) -> None:
        fresh_state(f"vault-{id(self)}.db")

    def test_records_each_action_in_existing_receipt_shape(self) -> None:
        for action in ("model", "tool", "approval", "denial"):
            receipt = record_action(
                action,
                f"example.{action}",
                {"request": action},
                {"result": True},
                correlation_id="run-1",
            )
            self.assertIsNotNone(receipt)
            assert receipt is not None
            self.assertEqual(receipt.extra["integration"]["action"], action)  # type: ignore[index,union-attr]
            self.assertEqual(receipt.extra["integration"]["correlation_id"], "run-1")  # type: ignore[index,union-attr]
        self.assertEqual(storage.verify_chain(), (4, 0))

    def test_redacts_common_secret_keys(self) -> None:
        receipt = record_action(
            "tool",
            "http",
            {"authorization": "Bearer secret", "nested": {"api_key": "secret"}},
            {"ok": True},
        )
        assert receipt is not None
        self.assertNotIn("secret", receipt.prompt)
        self.assertIn("[REDACTED]", receipt.prompt)

    def test_event_round_trip_preserves_transport_data(self) -> None:
        event = ActionEvent(
            action="approval",
            name="deploy",
            input={"environment": "production"},
            output={"approved": True},
            correlation_id="trace-9",
            metadata={"actor": "operator"},
            tags=("release",),
        )
        restored = ActionEvent.from_dict(event.as_dict())
        self.assertEqual(restored.action, event.action)
        self.assertEqual(restored.correlation_id, event.correlation_id)
        self.assertEqual(restored.metadata, event.metadata)
        self.assertEqual(restored.tags, event.tags)

    def test_callback_validates_envelope(self) -> None:
        with self.assertRaisesRegex(TypeError, r"event envelope data must be a mapping"):
            ActionRecorder().callback({"data": "invalid"})
        receipt = ActionRecorder().callback(
            ActionEvent(action="tool", name="lookup", output="done").as_dict()
        )
        self.assertIsNotNone(receipt)

    def test_best_effort_mode_returns_none(self) -> None:
        recorder = ActionRecorder(failure_mode="return_none")
        with patch("dontlie.integrations.core.storage.append", side_effect=OSError("full")):
            self.assertIsNone(recorder.record(ActionEvent(action="model", name="m")))
            self.assertIsNone(recorder.callback({"invalid": True}))

    def test_raise_mode_wraps_storage_failure(self) -> None:
        with patch("dontlie.integrations.core.storage.append", side_effect=OSError("full")), \
                self.assertRaises(RecordingError) as caught:
            ActionRecorder().record(ActionEvent(action="model", name="m"))
        self.assertIsInstance(caught.exception.__cause__, OSError)

    def test_context_manager_records_success_and_failure(self) -> None:
        recorder = ActionRecorder()
        with recorder.action("tool", "calculator", {"value": 2}) as event:
            event["output"] = 4
        self.assertEqual(storage.get_receipt(1).response, "4")  # type: ignore[union-attr,index]
        with self.assertRaisesRegex(RuntimeError, "boom"), \
                recorder.action("tool", "unstable"):
            raise RuntimeError("boom")
        failed = storage.get_receipt(2)
        assert failed is not None
        self.assertEqual(failed.extra["integration"]["status"], "failed")  # type: ignore[index,union-attr]
        self.assertNotIn("boom", failed.response)

    def test_decorator_records_return_and_preserves_exception(self) -> None:
        recorder = ActionRecorder()

        @recorder.decorate("tool", "add")
        def add(left: int, right: int) -> int:
            return left + right

        @recorder.decorate("tool", "explode")
        def explode() -> None:
            raise LookupError("private detail")

        with correlation_scope("workflow-2"):
            self.assertEqual(add(2, 3), 5)
            with self.assertRaises(LookupError):
                explode()
        first = storage.get_receipt(1)
        second = storage.get_receipt(2)
        assert first is not None and second is not None
        self.assertEqual(first.extra["integration"]["correlation_id"], "workflow-2")  # type: ignore[index,union-attr]
        self.assertEqual(second.extra["integration"]["correlation_id"], "workflow-2")  # type: ignore[index,union-attr]
        self.assertNotIn("private detail", second.response)


if __name__ == "__main__":
    unittest.main()
