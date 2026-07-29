"""Smoke tests for dontlie_agent CLI.

These tests don't actually launch a proxy; they exercise the CLI shape and
the env-var construction. End-to-end proxy runs are covered by the demo
suite, not here.
"""
from __future__ import annotations

import unittest
from unittest.mock import patch


class TestEnvSubcommand(unittest.TestCase):
    def test_env_default_port(self):
        from dontlie_agent.cli import main
        with patch("sys.stdout.write") as w:
            rc = main(["env"])
        self.assertEqual(rc, 0)
        text = "".join(c.args[0] for c in w.call_args_list if c.args)
        self.assertIn("DONTLIE_BASE_URL=http://127.0.0.1:8080/v1", text)
        self.assertIn("DONTLIE_API_KEY=dontlie-local", text)

    def test_env_custom_port(self):
        from dontlie_agent.cli import main
        with patch("sys.stdout.write") as w:
            main(["env", "--port", "9877"])
        text = "".join(c.args[0] for c in w.call_args_list if c.args)
        self.assertIn("127.0.0.1:9877", text)


class TestRunSubcommand(unittest.TestCase):
    def test_run_without_command_errors(self):
        from dontlie_agent.cli import main
        with self.assertRaises(SystemExit):
            main(["run", "--port", "8080"])

    def test_run_passes_env_to_subprocess(self):
        from dontlie_agent.cli import main
        with patch("dontlie_agent.cli._check_python_pkg", return_value=True), \
             patch("dontlie_agent.cli._check_proxy_bin", return_value=True), \
             patch("subprocess.call", return_value=0) as call, \
             patch("subprocess.Popen") as popen, \
             patch("time.sleep"):
            popen.return_value.poll.return_value = None
            rc = main(["run", "--port", "9877", "--", "echo", "hi"])
        self.assertEqual(rc, 0)
        # The agent subprocess got the proxy URL
        cs = call.call_args
        env = cs.kwargs["env"]
        self.assertEqual(env["DONTLIE_BASE_URL"], "http://127.0.0.1:9877/v1")
        self.assertEqual(env["DONTLIE_API_KEY"], "dontlie-local")
        self.assertEqual(cs.args[0], ["echo", "hi"])


class TestWrapSubcommand(unittest.TestCase):
    def test_wrap_sets_env(self):
        from dontlie_agent.cli import main
        with patch("subprocess.call", return_value=0) as call:
            rc = main(["wrap", "--port", "9000", "--", "echo", "y"])
        self.assertEqual(rc, 0)
        env = call.call_args.kwargs["env"]
        self.assertEqual(env["DONTLIE_BASE_URL"], "http://127.0.0.1:9000/v1")
        self.assertEqual(env["DONTLIE_API_KEY"], "dontlie-local")


if __name__ == "__main__":
    unittest.main()
