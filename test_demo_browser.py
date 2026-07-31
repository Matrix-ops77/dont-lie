"""Runtime browser test for the offline Browser Proof Lab."""

from __future__ import annotations

import functools
import http.server
import os
import shutil
import tempfile
import threading
import unittest
from pathlib import Path

from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait

SITE = Path(__file__).resolve().parent / "site"
REQUIRE_BROWSER = os.environ.get("DONTLIE_REQUIRE_BROWSER_TEST") == "1"


def _chrome_binary() -> str | None:
    candidates = (
        shutil.which("google-chrome"),
        shutil.which("google-chrome-stable"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    )
    return next(
        (
            str(candidate)
            for candidate in candidates
            if candidate and Path(candidate).is_file()
        ),
        None,
    )


class _SilentHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        del format, args


class BrowserProofLabRuntimeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        chrome_binary = _chrome_binary()
        if chrome_binary is None:
            message = "Chrome or Chromium is required for the Browser Proof Lab test"
            if REQUIRE_BROWSER:
                raise RuntimeError(message)
            raise unittest.SkipTest(message)

        cls._profile = tempfile.TemporaryDirectory(prefix="dontlie-browser-")
        handler = functools.partial(_SilentHandler, directory=str(SITE))
        cls._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls._thread = threading.Thread(target=cls._server.serve_forever, daemon=True)
        cls._thread.start()

        options = webdriver.ChromeOptions()
        options.binary_location = chrome_binary
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument(f"--user-data-dir={cls._profile.name}")
        options.set_capability("goog:loggingPrefs", {"browser": "ALL"})

        try:
            cls.driver = webdriver.Chrome(options=options)
        except WebDriverException as exc:
            cls._server.shutdown()
            cls._server.server_close()
            cls._profile.cleanup()
            if REQUIRE_BROWSER:
                raise
            raise unittest.SkipTest(f"Chrome could not start: {exc}") from exc

        cls.driver.set_page_load_timeout(15)
        cls.wait = WebDriverWait(cls.driver, 10)
        port = cls._server.server_address[1]
        cls.driver.get(f"http://127.0.0.1:{port}/demo.html")

    @classmethod
    def tearDownClass(cls) -> None:
        driver = getattr(cls, "driver", None)
        if driver is not None:
            driver.quit()
        server = getattr(cls, "_server", None)
        if server is not None:
            server.shutdown()
            server.server_close()
        profile = getattr(cls, "_profile", None)
        if profile is not None:
            profile.cleanup()

    def test_create_verify_tamper_and_reset(self) -> None:
        self.wait.until(
            lambda driver: driver.find_element(By.ID, "wasm-status").text
            == "WASM: ready"
        )

        prompt = self.driver.find_element(By.ID, "prompt")
        prompt.send_keys("Summarize the evidence boundary.")
        self.driver.find_element(By.ID, "run").click()

        self.wait.until(
            lambda driver: len(driver.find_elements(By.CSS_SELECTOR, "#rows tr")) == 1
        )
        self.assertEqual(
            self.driver.find_element(By.ID, "log").text,
            "Signed receipt saved to IndexedDB.",
        )
        self.assertEqual(
            self.driver.find_element(By.ID, "proof").get_attribute("data-state"),
            "verified",
        )

        self.driver.find_element(By.ID, "verify").click()
        self.wait.until(
            lambda driver: driver.find_element(By.ID, "log").text
            == "Vault verified locally."
        )

        self.driver.find_element(By.ID, "tamper").click()
        self.wait.until(
            lambda driver: driver.find_element(By.ID, "proof").get_attribute(
                "data-state"
            )
            == "invalid"
        )
        self.assertIn(
            "Verification now fails",
            self.driver.find_element(By.ID, "log").text,
        )
        self.assertEqual(
            self.driver.find_element(By.CSS_SELECTOR, "#rows .badge").text,
            "failed",
        )

        self.driver.find_element(By.ID, "reset").click()
        self.driver.switch_to.alert.accept()
        self.wait.until(
            lambda driver: driver.find_element(By.ID, "log").text
            == "Local demo data cleared."
        )
        self.assertEqual(self.driver.find_elements(By.CSS_SELECTOR, "#rows tr"), [])

        severe_logs = [
            entry
            for entry in self.driver.get_log("browser")
            if entry.get("level") == "SEVERE"
        ]
        self.assertEqual(severe_logs, [])


if __name__ == "__main__":
    unittest.main()
