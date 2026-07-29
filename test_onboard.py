"""SDK-free conformance tests for passive onboarding and instrumentation."""

from __future__ import annotations

import asyncio
import contextlib
import importlib.util
import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from onboard import cli, runtime


class PassivePatcherTest(unittest.TestCase):
    def test_openai_sync_call_is_captured_and_patch_is_idempotent(self) -> None:
        class Completions:
            def create(self, **kwargs):
                return {"choices": [{"message": {"content": "hello"}}]}

        Completions.__module__ = "openai.resources.chat.completions"
        module = types.ModuleType("openai.resources.chat.completions")
        module.Completions = Completions
        patcher = runtime.SDKPatcher()
        with (
            patch.dict(sys.modules, {module.__name__: module}),
            patch.object(runtime, "_append_receipt") as append,
        ):
            patcher.patch_loaded_modules()
            patcher.patch_loaded_modules()
            result = Completions().create(
                model="gpt-fixture",
                messages=[{"role": "user", "content": "hello"}],
                api_key="must-not-be-captured",
                extra_headers={"Authorization": "also-secret"},
            )

        self.assertEqual(result["choices"][0]["message"]["content"], "hello")
        append.assert_called_once()
        captured = append.call_args.kwargs
        self.assertEqual(captured["provider"], runtime.OPENAI_PROVIDER)
        self.assertEqual(captured["model"], "gpt-fixture")
        prompt = json.loads(captured["prompt"])
        self.assertEqual(
            prompt["kwargs"]["api_key"],
            "[redacted credential]",
        )
        self.assertEqual(
            prompt["kwargs"]["extra_headers"],
            "[omitted transport metadata]",
        )

    def test_signing_failure_never_breaks_provider_result(self) -> None:
        class Messages:
            def create(self, **kwargs):
                return {"content": [{"type": "text", "text": "safe"}]}

        Messages.__module__ = "anthropic.resources.messages"
        module = types.ModuleType("anthropic.resources.messages")
        module.Messages = Messages
        with (
            patch.dict(sys.modules, {module.__name__: module}),
            patch.object(
                runtime,
                "_append_receipt",
                side_effect=RuntimeError("signing unavailable"),
            ),
        ):
            runtime.SDKPatcher().patch_loaded_modules()
            result = Messages().create(
                model="claude-fixture",
                messages=[{"role": "user", "content": "hello"}],
                max_tokens=8,
            )
        self.assertEqual(result["content"][0]["text"], "safe")

    def test_original_provider_exception_is_reraised_unchanged(self) -> None:
        expected = LookupError("provider failed")

        class Messages:
            def create(self, **kwargs):
                raise expected

        Messages.__module__ = "anthropic.resources.messages.errors"
        module = types.ModuleType("anthropic.resources.messages.errors")
        module.Messages = Messages
        with (
            patch.dict(sys.modules, {module.__name__: module}),
            patch.object(runtime, "_append_receipt") as append,
        ):
            runtime.SDKPatcher().patch_loaded_modules()
            with self.assertRaises(LookupError) as raised:
                Messages().create(model="claude-fixture", max_tokens=8, messages=[])
        self.assertIs(raised.exception, expected)
        self.assertEqual(append.call_args.kwargs["outcome"], "error")

    def test_stream_is_recorded_after_consumption_without_changing_chunks(self) -> None:
        class Completions:
            def create(self, **kwargs):
                return iter(({"delta": "a"}, {"delta": "b"}))

        Completions.__module__ = "openai.resources.streaming"
        module = types.ModuleType("openai.resources.streaming")
        module.Completions = Completions
        with (
            patch.dict(sys.modules, {module.__name__: module}),
            patch.object(runtime, "_append_receipt") as append,
        ):
            runtime.SDKPatcher().patch_loaded_modules()
            stream = Completions().create(model="gpt-fixture", stream=True)
            self.assertEqual(list(stream), [{"delta": "a"}, {"delta": "b"}])
        append.assert_called_once()
        self.assertTrue(append.call_args.kwargs["streamed"])
        self.assertEqual(
            append.call_args.kwargs["response"],
            [{"delta": "a"}, {"delta": "b"}],
        )

    def test_stream_context_manager_uses_entered_iterator(self) -> None:
        class StreamManager:
            def __enter__(self):
                return iter(("one", "two"))

            def __exit__(self, exc_type, exc, tb):
                return False

        class Messages:
            def stream(self, **kwargs):
                return StreamManager()

        Messages.__module__ = "anthropic.resources.streaming"
        module = types.ModuleType("anthropic.resources.streaming")
        module.Messages = Messages
        with (
            patch.dict(sys.modules, {module.__name__: module}),
            patch.object(runtime, "_append_receipt") as append,
        ):
            runtime.SDKPatcher().patch_loaded_modules()
            with Messages().stream(model="claude-fixture") as stream:
                self.assertEqual(list(stream), ["one", "two"])
        append.assert_called_once()
        self.assertEqual(append.call_args.kwargs["response"], ["one", "two"])

    def test_anthropic_async_call_is_instrumented(self) -> None:
        class AsyncMessages:
            async def create(self, **kwargs):
                return {"content": [{"type": "text", "text": "async"}]}

        AsyncMessages.__module__ = "anthropic.resources.async_messages"
        module = types.ModuleType("anthropic.resources.async_messages")
        module.AsyncMessages = AsyncMessages

        async def exercise():
            return await AsyncMessages().create(
                model="claude-fixture",
                messages=[],
                max_tokens=4,
            )

        with (
            patch.dict(sys.modules, {module.__name__: module}),
            patch.object(runtime, "_append_receipt") as append,
        ):
            runtime.SDKPatcher().patch_loaded_modules()
            result = asyncio.run(exercise())
        self.assertEqual(result["content"][0]["text"], "async")
        append.assert_called_once()

    def test_gemini_generate_content_is_instrumented(self) -> None:
        class GenerativeModel:
            model_name = "gemini-fixture"

            def generate_content(self, prompt, **kwargs):
                return {"text": f"echo:{prompt}"}

        GenerativeModel.__module__ = "google.generativeai.generative_models"
        module = types.ModuleType("google.generativeai.generative_models")
        module.GenerativeModel = GenerativeModel
        with (
            patch.dict(sys.modules, {module.__name__: module}),
            patch.object(runtime, "_append_receipt") as append,
        ):
            runtime.SDKPatcher().patch_loaded_modules()
            result = GenerativeModel().generate_content(
                "hello",
                generation_config={"temperature": 0},
            )
        self.assertEqual(result, {"text": "echo:hello"})
        self.assertEqual(append.call_args.kwargs["provider"], runtime.GEMINI_PROVIDER)
        self.assertEqual(append.call_args.kwargs["model"], "gemini-fixture")


class VaultDiscoveryTest(unittest.TestCase):
    def test_passive_disable_values_are_explicit(self) -> None:
        for value in ("0", "false", "NO", "off", "disabled"):
            self.assertFalse(runtime.passive_enabled({"DONTLIE_PASSIVE": value}))
        self.assertTrue(runtime.passive_enabled({}))

    def test_explicit_env_file_and_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            self.assertEqual(
                runtime.discover_vault(
                    root,
                    {"DONTLIE_PROJECT_VAULT": "audit.sqlite"},
                ),
                root / "audit.sqlite",
            )
            self.assertEqual(
                runtime.discover_vault(
                    root,
                    {"DONTLIE_PROJECT_VAULT": "evidence"},
                ),
                root / "evidence" / "vault.db",
            )
            self.assertEqual(
                runtime.discover_vault(root, {"DONTLIE_DB": "legacy-vault"}),
                root / "legacy-vault",
            )

    def test_cwd_finds_project_root_and_existing_parent_vault(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            nested = root / "src" / "feature"
            nested.mkdir(parents=True)
            (root / "pyproject.toml").write_text("[project]\nname='fixture'\n")
            self.assertEqual(
                runtime.discover_vault(nested, {}),
                root / ".dontlie" / "vault.db",
            )
            existing = root / ".dontlie" / "vault.db"
            existing.parent.mkdir()
            existing.touch()
            self.assertEqual(runtime.discover_vault(nested, {}), existing)


class OnboardingCLITest(unittest.TestCase):
    def test_zero_args_and_init_print_exactly_one_shell_line(self) -> None:
        for argv in ([], ["init"]):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(cli.main(argv), 0)
            lines = output.getvalue().splitlines()
            self.assertEqual(len(lines), 1)
            self.assertIn("PYTHONPATH=", lines[0])
            self.assertIn("PATH=", lines[0])
            self.assertIn("onboard/bootstrap", lines[0])

    def test_zero_arg_executable_works_before_activation(self) -> None:
        command = Path(__file__).parent / "onboard" / "dontlie-passive"
        self.assertTrue(os.access(command, os.X_OK))
        completed = subprocess.run(
            [str(command)],
            check=True,
            capture_output=True,
            text=True,
        )
        self.assertEqual(len(completed.stdout.splitlines()), 1)
        self.assertIn("PYTHONPATH=", completed.stdout)

    def test_show_reads_recent_receipts_without_importing_core(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            vault = Path(temporary) / "vault.db"
            with sqlite3.connect(vault) as connection:
                connection.execute(
                    """
                    CREATE TABLE receipts (
                        id INTEGER, timestamp TEXT, model TEXT,
                        response TEXT, tags TEXT
                    )
                    """
                )
                connection.execute(
                    "INSERT INTO receipts VALUES (1, ?, ?, ?, ?)",
                    ("2026-07-24T00:00:00Z", "fixture", "hello", '["passive"]'),
                )
            output = io.StringIO()
            with (
                patch.dict(
                    os.environ,
                    {"DONTLIE_PROJECT_VAULT": str(vault)},
                    clear=False,
                ),
                contextlib.redirect_stdout(output),
            ):
                self.assertEqual(cli.main(["show"]), 0)
            self.assertIn("#1", output.getvalue())
            self.assertIn("[fixture]", output.getvalue())

    def test_status_reports_active_health(self) -> None:
        output = io.StringIO()

        def find_spec(name: str):
            return object() if name == "cryptography" else None

        with (
            patch.dict(os.environ, {"DONTLIE_PASSIVE_ACTIVE": "1"}, clear=False),
            patch.object(importlib.util, "find_spec", side_effect=find_spec),
            contextlib.redirect_stdout(output),
        ):
            self.assertEqual(cli.main(["status"]), 0)
        self.assertIn("passive hook: active", output.getvalue())
        self.assertIn("signing backend: available", output.getvalue())
        self.assertIn("failure mode: fail-open", output.getvalue())

    def test_sitecustomize_patches_module_loaded_after_process_start(self) -> None:
        project_root = Path(__file__).resolve().parent
        bootstrap = project_root / "onboard" / "bootstrap"
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "openai"
            package.mkdir()
            (package / "__init__.py").write_text("")
            (package / "fixture.py").write_text(
                "class Completions:\n"
                "    def create(self, **kwargs):\n"
                "        return kwargs\n"
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = os.pathsep.join(
                (str(project_root), str(bootstrap), temporary)
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import os, openai.fixture; "
                        "print(os.environ.get('DONTLIE_PASSIVE_ACTIVE')); "
                        "print(getattr(openai.fixture.Completions.create, "
                        "'__dontlie_passive__', False))"
                    ),
                ],
                cwd=temporary,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
        self.assertEqual(completed.stdout.splitlines(), ["1", "True"])

    def test_fake_sdk_calls_create_a_real_verified_chain(self) -> None:
        project_root = Path(__file__).resolve().parent
        bootstrap = project_root / "onboard" / "bootstrap"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "openai"
            package.mkdir()
            (package / "__init__.py").write_text("")
            (package / "fixture.py").write_text(
                "class Completions:\n"
                "    def create(self, **kwargs):\n"
                "        return {'choices': [{'message': {'content': 'ok'}}]}\n"
            )
            key_dir = root / "keys"
            key_dir.mkdir()
            private = Ed25519PrivateKey.generate()
            public = private.public_key()
            private_pem = private.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
            public_pem = public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
            raw_public = public.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            key_id = raw_public[:8].hex()
            (key_dir / "dontlie.key").write_bytes(private_pem)
            (key_dir / "dontlie.pub").write_bytes(public_pem)
            (key_dir / "key_id").write_text(
                json.dumps({"key_id": key_id, "created": "fixture"})
            )
            vault = root / "project-vault.db"
            environment = os.environ.copy()
            environment.update(
                {
                    "PYTHONPATH": os.pathsep.join(
                        (str(project_root), str(bootstrap), temporary)
                    ),
                    "DONTLIE_PROJECT_VAULT": str(vault),
                    "DONTLIE_KEY_DIR": str(key_dir),
                    "DONTLIE_NO_WAL": "1",
                }
            )
            code = (
                "import openai.fixture\n"
                "client = openai.fixture.Completions()\n"
                "client.create(model='fixture', messages=[{'role':'user','content':'one'}])\n"
                "client.create(model='fixture', messages=[{'role':'user','content':'two'}])\n"
                "from dontlie import storage\n"
                "from pathlib import Path\n"
                "storage.DB_PATH = Path(__import__('os').environ['DONTLIE_PROJECT_VAULT'])\n"
                "print(storage.verify_chain())\n"
            )
            completed = subprocess.run(
                [sys.executable, "-c", code],
                cwd=temporary,
                env=environment,
                check=True,
                capture_output=True,
                text=True,
            )
            with sqlite3.connect(vault) as connection:
                rows = connection.execute(
                    "SELECT id, parent_id, signature FROM receipts ORDER BY id"
                ).fetchall()
        self.assertEqual(completed.stdout.strip(), "(2, 0)")
        self.assertEqual([(row[0], row[1]) for row in rows], [(1, None), (2, 1)])
        self.assertTrue(all(len(row[2]) > 32 for row in rows))


if __name__ == "__main__":
    unittest.main()
