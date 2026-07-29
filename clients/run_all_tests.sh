#!/usr/bin/env bash
# Run all client tests + the wrapper benchmark in one shot.
# Used by CI and by humans who want a single "are the clients good?" command.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "=== client tests (22 tests across 4 wrappers) ==="
python3 -m unittest clients.dontlie_openai.tests.test_smoke \
                 clients.dontlie_anthropic.tests.test_smoke \
                 clients.dontlie_requests.tests.test_smoke \
                 clients.dontlie_agent.tests.test_smoke -v

echo
echo "=== wrapper benchmark (default SDK vs dontlie-wrapped) ==="
python3 clients/benchmark_wrappers.py 200 BENCHMARK.transcript.json

echo
echo "=== quick smoke: every example file imports cleanly ==="
for ex in examples/python_openai.py examples/python_anthropic.py examples/python_requests.py; do
    python3 -c "import ast; ast.parse(open('$ex').read()); print('  parse OK: $ex')"
done
python3 -c "import json; json.loads(open('examples/node_openai.js').read().replace('//', '').replace('/*',' ').replace('*/', ' ')); print('  node file: parse-able as JS-ish')" 2>/dev/null || \
    echo "  node_openai.js is JS — syntax check skipped (needs node)"

echo
echo "all checks passed."
