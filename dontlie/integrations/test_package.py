import importlib
import importlib.util
import unittest
from pathlib import Path


class PackageInclusionTest(unittest.TestCase):
    def test_public_package_and_examples_are_importable(self) -> None:
        package = importlib.import_module("dontlie.integrations")
        self.assertIn("ActionRecorder", package.__all__)
        self.assertIsNotNone(importlib.util.find_spec("dontlie.integrations.core"))
        self.assertIsNotNone(importlib.util.find_spec("dontlie.integrations.examples.clients"))

    def test_distribution_discovery_includes_integrations(self) -> None:
        root = Path(__file__).resolve().parents[2]
        pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
        # The core product is shipped as the `dontlie` package. The
        # `onboard` package is also installable so end users can use
        # the sitecustomize.py instrumentation without checking out
        # the source tree. Both must be discoverable by setuptools.
        self.assertIn('"dontlie*"', pyproject)
        self.assertIn('"onboard*"', pyproject)
        self.assertTrue((Path(__file__).parent / "__init__.py").is_file())
        self.assertTrue((Path(__file__).parent / "README.md").is_file())


if __name__ == "__main__":
    unittest.main()
