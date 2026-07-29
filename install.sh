#!/usr/bin/env bash
# dontlie installer - single-file, idempotent, curl-pipe-safe
set -euo pipefail

REPO="${DONTLIE_REPO:-https://github.com/Matrix-ops77/dontlie.git}"
PREFIX="${DONTLIE_PREFIX:-$HOME/.local}"
PROXY_PORT="${DONTLIE_PORT:-8765}"
PROXY_LOG="$HOME/.dontlie/proxy.log"
PROXY_PIDFILE="$HOME/.dontlie/proxy.pid"

echo ">>> dontlie installer (v1)"

# 1. Python
command -v python3 >/dev/null || { echo "ERR: python3 not found"; exit 1; }
PY="$(command -v python3)"

# 2. Clone + install (skip if local editable install exists)
if [ -n "${DONTLIE_LOCAL:-}" ]; then
  if [ "$DONTLIE_LOCAL" = "1" ]; then
    SRC="$(pwd)/dontlie"
  else
    SRC="$DONTLIE_LOCAL"
  fi
  echo ">>> using local source at $SRC"
elif [ -d "$HOME/.dontlie-src/dontlie" ]; then
  echo ">>> using existing source at ~/.dontlie-src/dontlie"
  (cd "$HOME/.dontlie-src/dontlie" && git pull --ff-only || true)
  SRC="$HOME/.dontlie-src/dontlie"
elif [ -f "./dontlie/pyproject.toml" ]; then
  echo ">>> using local ./dontlie project"
  SRC="$(pwd)/dontlie"
elif [ -f "./pyproject.toml" ]; then
  echo ">>> using local project root"
  SRC="$(pwd)"
else
  echo ">>> cloning repo"
  mkdir -p "$HOME/.dontlie-src"
  git clone --depth=1 "$REPO" "$HOME/.dontlie-src/dontlie"
  SRC="$HOME/.dontlie-src/dontlie"
fi
"$PY" -m pip install --user --quiet "$SRC"
export PATH="$HOME/.local/bin:$PATH"

# 3. Generate key (idempotent: gen-key returns 1 if key already exists)
echo ">>> generating Ed25519 keypair -> $HOME/.config/dontlie/keys"
"$PY" -m dontlie gen-key || true

# 4. Init DB (storage.init() runs on first list/verify/proxy call)
"$PY" -m dontlie list --limit 1 >/dev/null 2>&1 || true
echo ">>> SQLite ready at ~/.local/share/dontlie/vault.db (WAL mode)"

# 5. Start proxy when an upstream provider key is available.
mkdir -p "$HOME/.dontlie"
UPSTREAM_KEY="${DONTLIE_UPSTREAM_API_KEY:-}"
if [ -z "$UPSTREAM_KEY" ]; then
  echo ">>> proxy not started: set DONTLIE_UPSTREAM_API_KEY, then run dontlie proxy"
elif [ -f "$PROXY_PIDFILE" ] && kill -0 "$(cat "$PROXY_PIDFILE")" 2>/dev/null; then
  echo ">>> proxy already running (pid $(cat "$PROXY_PIDFILE"))"
else
  echo ">>> starting proxy on 127.0.0.1:$PROXY_PORT"
  DONTLIE_UPSTREAM_API_KEY="$UPSTREAM_KEY" \
  nohup "$PY" -m dontlie proxy --port "$PROXY_PORT" \
    >"$PROXY_LOG" 2>&1 &
  PROXY_PID=$!
  echo "$PROXY_PID" >"$PROXY_PIDFILE"
  sleep 1
  if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo ">>> proxy failed to start; inspect $PROXY_LOG"
  fi
fi
# 6. Smoke check: list + verify
"$PY" -m dontlie list --limit 1 || true
"$PY" -m dontlie verify || true

# 7. Print usage banner
cat <<EOF

============================================================
dontlie installed. To use in a new shell:

  export DONTLIE_UPSTREAM_BASE_URL="https://api.minimax.io/v1"
  export DONTLIE_UPSTREAM_API_KEY="sk-..."   # real provider key
  dontlie proxy --port "$PROXY_PORT"

Then configure the client separately:

  export OPENAI_BASE_URL="http://127.0.0.1:$PROXY_PORT/v1"
  export OPENAI_API_KEY="dontlie-local"      # client placeholder only

  openai-python, LangChain, and other OpenAI-compatible clients -> signed vault

Verify:
  dontlie doctor
  dontlie verify --verbose

Proxy log: $PROXY_LOG
DB:        ~/.local/share/dontlie/vault.db
============================================================
EOF
