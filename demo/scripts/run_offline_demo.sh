#!/usr/bin/env bash
# Offline demo: zero network, deterministic, no API keys.
# Starts mock provider + dontlie proxy, issues 3 requests, verifies chain.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
DEMO="$ROOT/demo"
MOCK_PORT="${MOCK_PORT:-9876}"
PROXY_PORT="${PROXY_PORT:-9877}"  # deliberately separate from common dev ports
WORK="${DONTLIE_DEMO_WORK:-$DEMO/work}"

# isolate demo state from real user vault
export DONTLIE_KEY_DIR="$WORK/keys"
export DONTLIE_DB="$WORK/vault.db"
export DONTLIE_NO_WAL=1
export DONTLIE_UPSTREAM_BASE_URL="http://127.0.0.1:$MOCK_PORT"
export DONTLIE_UPSTREAM_API_KEY="mock-no-key-required"
export OPENAI_API_KEY="dontlie-local"

case "$WORK" in
    ""|"/"|"$ROOT"|"$HOME"|"$HOME/.config")
        echo "FAIL: refusing to use unsafe demo workdir: $WORK" >&2
        exit 1
        ;;
esac
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
"$PY" "$DEMO/scripts/mock_provider.py" --port "$MOCK_PORT" >"$WORK/mock.log" 2>&1 &
MOCK_PID=$!
printf '%s\n' "$MOCK_PID" > "$WORK/mock.pid"
sleep 0.5

# --- start dontlie proxy ---
"$PY" -m dontlie proxy --port "$PROXY_PORT" >"$WORK/proxy.log" 2>&1 &
PROXY_PID=$!
printf '%s\n' "$PROXY_PID" > "$WORK/proxy.pid"
sleep 1

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
    echo "$content" | "$PY" "$DEMO/scripts/issue_request.py" | tee "$WORK/last_response.json"
    echo "==> '$label' request sent"
}

issue "ping"           "ping"
issue "knowledge"      "What is the capital of France?"
issue "product-pitch"  "Summarize what Don't-Lie does in one sentence."

# --- verify chain ---
echo "==> verifying receipt chain"
cd "$ROOT"
"$PY" -m dontlie list --limit 5 | tee "$WORK/list.out"
"$PY" -m dontlie verify --verbose | tee "$WORK/verify.out"

# --- export both human-friendly JSONL and a self-contained verification bundle ---
"$PY" -m dontlie export "$WORK/receipts.jsonl"
"$PY" -m dontlie export "$WORK/receipts.bundle.json" --bundle
"$PY" "$DEMO/scripts/render_report.py" \
    "$WORK/receipts.bundle.json" "$WORK/receipt-report.html"

# Show the central product moment: mutate a signed record, detect it, restore it.
echo ""
echo "=== TAMPER-PROOF CHECK ==="
"$PY" "$DEMO/scripts/tamper_walkthrough.py" "$WORK"
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
echo "  - vault:  $WORK/vault.db"
echo "  - sha256: $(<"$WORK/vault.db.sha256")"
echo "  - exports: $WORK/receipts.jsonl and receipts.bundle.json"
echo "  - report:  $WORK/receipt-report.html"
echo "  - logs:   $WORK/{mock,proxy}.log"
echo "================================================"
