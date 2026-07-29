"""Automatically loaded by Python when this directory is on PYTHONPATH."""

try:
    from onboard.runtime import install

    install()
except Exception:  # noqa: BLE001,S110
    # A startup hook must never prevent the user's Python process from starting.
    pass
