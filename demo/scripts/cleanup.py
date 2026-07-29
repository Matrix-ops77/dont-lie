"""Remove Don't-Lie demo artifacts and stop only demo-owned processes.

The run script records its child PIDs under ``demo/work``. Cleanup verifies a
process command before signalling it, so it never kills an unrelated listener
merely because that process happens to use the same port.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
from pathlib import Path

EXPECTED_COMMANDS = {
    "mock.pid": "mock_provider.py",
    "proxy.pid": "dontlie proxy",
}


def _command_for_pid(pid: int) -> str:
    try:
        return subprocess.check_output(
            ["ps", "-p", str(pid), "-o", "command="],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (FileNotFoundError, subprocess.CalledProcessError):
        return ""


def stop_demo_processes(work: Path) -> None:
    for filename, expected in EXPECTED_COMMANDS.items():
        pid_file = work / filename
        if not pid_file.exists():
            continue
        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip())
        except (OSError, ValueError):
            print(f"ignored invalid PID file: {pid_file}")
            continue

        command = _command_for_pid(pid)
        if not command:
            continue
        if expected not in command:
            print(f"refused to stop unrelated pid {pid}: {command}")
            continue
        try:
            os.kill(pid, signal.SIGTERM)
            print(f"stopped demo pid {pid}: {expected}")
        except ProcessLookupError:
            pass


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    work = root / "work"
    stop_demo_processes(work)
    if work.exists():
        shutil.rmtree(work)
        print(f"removed {work}")
    else:
        print("nothing to clean")
    print("done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
