#!/usr/bin/env bash
# Offline demo: zero network, deterministic, no API keys.
# Starts mock provider + dontlie proxy, issues 3 requests, verifies chain,
# tampers with one record, detects, and restores.
#
# Invoked by `dontlie demo` (cli.cmd_demo). The script's location is
# `dontlie/demo/run_offline_demo.sh` inside the installed package; it
# calls the sibling Python helpers as `python -m dontlie.demo.<name>`.
set -euo pipefail

# Resolve the package directory (the .sh file's parent) so we can derive
# every other path from a single source of truth. Works whether the
# package is editable-installed or installed from a wheel.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOCK_PORT="${MOCK_PORT:-9876}"
PROXY_PORT="${PROXY_PORT:-9877}"  # deliberately separate from common dev ports
WORK="${DONTLIE_DEMO_WORK:-/tmp/dontlie-demo-work}"

# Default workdir lives OUTSIDE the package so a wheel install has somewhere
# to write. Override with DONTLIE_DEMO_WORK if you want it somewhere specific.
case "$WORK" in
    ""|"/"|"$HOME"|"$HOME/.config")
        echo "FAIL: refusing to use unsafe demo workdir: $WORK" >&2
        exit 1
        ;;
esac

# isolate demo state from real user vault
export DONTLIE_KEY_DIR="$WORK/keys"
export DONTLIE_DB="$WORK/vault.db"
export DONTLIE_NO_WAL=1
export DONTLIE_UPSTREAM_BASE_URL="http://127.0.0.1:$MOCK_PORT"
export DONTLIE_UPSTREAM_API_KEY="mock-no-key-required"
export OPENAI_API_KEY="dontlie-local"
# Critical: pin the client to the proxy's actual port, not the default.
# (Previously this was hardcoded to 9877, so changing --port broke the demo.)
export OPENAI_BASE_URL="http://127.0.0.1:$PROXY_PORT/v1"

rm -rf "$WORK"
mkdir -p "$WORK"
echo "==> workdir isolated at $WORK"

# generate keypair (idempotent: returns 1 if already exists)
PY="${PYTHON:-python3}"
"$PY" -m dontlie gen-key 2>&1 | sed 's/^/    /'

# --- start mock provider ---
# Fail fast if either configured port is already occupied. This stdlib check
# works on macOS, Linux, and Windows environments with Python.
port_available() {
    "$PY" - "$1" <<'PY'
import socket
import sys
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    try:
        sock.bind(("127.0.0.1", int(sys.argv[1])))
    except OSError:
        raise SystemExit(1)
PY
}
if ! port_available "$MOCK_PORT"; then
    echo "FAIL: port $MOCK_PORT already in use"; exit 1
fi
if ! port_available "$PROXY_PORT"; then
    echo "FAIL: port $PROXY_PORT already in use"; exit 1
fi
"$PY" -m dontlie.demo.mock_provider --port "$MOCK_PORT" >"$WORK/mock.log" 2>&1 &
MOCK_PID=$!
printf '%s\n' "$MOCK_PID" > "$WORK/mock.pid"

# Wait up to 5s for the mock provider to actually be listening. The
# `sleep 0.5` was racey on slow CI runners where Python startup +
# import can exceed 500ms.
for _ in $(seq 1 50); do
    if curl -fsS "http://127.0.0.1:$MOCK_PORT/health" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

# --- start dontlie proxy ---
"$PY" -m dontlie proxy --port "$PROXY_PORT" >"$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
printf '%s\n' "$PROXY_PID" > "$WORK/proxy.pid"

# Same wait-for-listen pattern for the proxy.
for _ in $(seq 1 50); do
    if curl -fsS "http://127.0.0.1:$PROXY_PORT/_dontlie/health" >/dev/null 2>&1; then
        break
    fi
    sleep 0.1
done

cleanup() {
    kill "$PROXY_PID" "$MOCK_PID" 2>/dev/null || true
    wait 2>/dev/null || true
}
trap cleanup EXIT

# --- sanity: mock provider reachable ---
if ! curl -fsS "http://127.0.0.1:$MOCK_PORT/health" >/dev/null; then
    echo "FAIL: mock provider did not start"; exit 1
fi
echo "==> mock provider up"

# --- three deterministic requests ---
issue() {
    local label="$1" content="$2"
    echo "$content" | "$PY" -m dontlie.demo.issue_request | tee "$WORK/last_response.json"
    echo "==> '$label' request sent"
}

issue "ping"           "ping"
issue "knowledge"      "What is the capital of France?"
issue "product-pitch"  "Summarize what Don't-Lie does in one sentence."

# --- verify chain ---
echo "==> verifying receipt chain"
"$PY" -m dontlie list --limit 5 | tee "$WORK/list.out"
"$PY" -m dontlie verify --verbose | tee "$WORK/verify.out"

# --- export both human-friendly JSONL and a self-contained verification bundle ---
"$PY" -m dontlie export "$WORK/receipts.jsonl"
"$PY" -m dontlie export "$WORK/receipts.bundle.json" --bundle
"$PY" -m dontlie.demo.render_report \
    "$WORK/receipts.bundle.json" "$WORK/receipt-report.html"

# Show the central product moment: mutate a signed record, detect it, restore it.
echo ""
echo "=== TAMPER-PROOF CHECK ==="
"$PY" -m dontlie.demo.tamper_walkthrough "$WORK"
"$PY" -m dontlie list --limit 100 > "$WORK/all_receipts.txt"
"$PY" - "$WORK/vault.db" > "$WORK/vault.db.sha256" <<'PY'
import hashlib
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
print(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path}")
PY

echo ""
echo "================================================"
echo "Demo complete."
echo "  - mock port:    $MOCK_PORT"
echo "  - proxy port:   $PROXY_PORT"
echo "  - vault:        $WORK/vault.db"
echo "  - sha256:       $(<"$WORK/vault.db.sha256")"
echo "  - exports:      $WORK/receipts.jsonl and receipts.bundle.json"
echo "  - report:       $WORK/receipt-report.html"
echo "  - logs:         $WORK/{mock,proxy}.log"
echo "================================================"
