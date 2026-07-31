from __future__ import annotations

import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
RELEASE_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "release.yml"


class ReleaseWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.source = RELEASE_WORKFLOW.read_text(encoding="utf-8")

    def test_pypi_distributions_are_staged_inside_workspace(self) -> None:
        self.assertIn("mkdir -p pypi-dist", self.source)
        self.assertIn("packages-dir: pypi-dist/", self.source)

    def test_pypi_container_does_not_receive_host_tmp_path(self) -> None:
        self.assertNotIn("packages-dir: /tmp/", self.source)


if __name__ == "__main__":
    unittest.main()
