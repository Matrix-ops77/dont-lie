#!/usr/bin/env bash
# Prove that a built wheel works as a first-time user would use it:
# install outside the source tree, run the offline demo, then independently
# verify its portable bundle. This intentionally needs no provider key.
set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 PATH/TO/dontlie-*.whl" >&2
    exit 2
fi

WHEEL_PATH="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
if [ ! -f "$WHEEL_PATH" ]; then
    echo "wheel not found: $WHEEL_PATH" >&2
    exit 2
fi

PYTHON_BIN="${PYTHON_BIN:-python3}"
WORK_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/dontlie-repro.XXXXXX")"
VENV_DIR="$WORK_ROOT/venv"
RUN_DIR="$WORK_ROOT/first-user"
DEMO_DIR="$WORK_ROOT/demo"
TRANSCRIPT="${DONTLIE_REPRO_TRANSCRIPT:-$WORK_ROOT/reproducibility.txt}"

cleanup() {
    rm -rf "$WORK_ROOT"
}
trap cleanup EXIT

mkdir -p "$RUN_DIR" "$(dirname "$TRANSCRIPT")"
export XDG_CONFIG_HOME="$WORK_ROOT/config"
export XDG_DATA_HOME="$WORK_ROOT/data"
unset PYTHONPATH

{
    echo "wheel: $(basename "$WHEEL_PATH")"
    echo "python: $($PYTHON_BIN --version 2>&1)"
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    "$VENV_DIR/bin/python" -m pip install --quiet --upgrade pip
    "$VENV_DIR/bin/python" -m pip install --quiet "$WHEEL_PATH"

    # Work from an empty directory: no import may silently resolve from the
    # source checkout that built the wheel.
    cd "$RUN_DIR"
    "$VENV_DIR/bin/dontlie" --version
    "$VENV_DIR/bin/dontlie" version
    "$VENV_DIR/bin/dontlie-passive" --help >/dev/null
    test -x "$("$VENV_DIR/bin/python" -c 'import onboard, os; print(os.path.join(os.path.dirname(onboard.__file__), "dontlie-passive"))')"

    DONTLIE_DEMO_WORK="$DEMO_DIR" \
        "$VENV_DIR/bin/dontlie" demo --port 19879 --mock-port 19880
    test -f "$DEMO_DIR/receipts.bundle.json"
    "$VENV_DIR/bin/dontlie" verify --export "$DEMO_DIR/receipts.bundle.json"
    echo "reproducibility check: PASS"
} 2>&1 | tee "$TRANSCRIPT"
