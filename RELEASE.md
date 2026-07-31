# Release checklist

This is the internal checklist to clear before shipping a release of
Don't-Lie. Not customer-facing.

## Before tagging

- [ ] `DONTLIE_REQUIRE_BROWSER_TEST=1 python -m unittest discover -t . -v`
      — full suite passes, including the Browser Proof Lab runtime flow
- [ ] `ruff check dontlie test_*.py` — clean
- [ ] `mypy --strict dontlie/sign.py dontlie/protocols.py` — clean
- [ ] `python tools/public_claims_scan.py` — clean
- [ ] `python -m compileall -q dontlie` — bytecode builds
- [ ] `dontlie demo` — exit 0
- [ ] `python3 -m dontlie.demo.tamper_walkthrough /tmp/dontlie-demo-work` — exit 0
- [ ] `python3 -m dontlie.demo.render_report /tmp/dontlie-demo-work/receipts.bundle.json /tmp/r.html` — written
- [ ] `python3 -m dontlie.demo.benchmark 1000 demo/output/benchmark.transcript.json` — written
- [ ] `python3 -m dontlie.demo.cleanup` — no orphans on demo ports
- [ ] Build the wheel and run
      `bash tools/reproducibility_check.sh dist/dontlie-*.whl`
- [ ] No `print()` debug remnants in `dontlie/demo/` (lint catches them)
- [ ] Git status: working tree clean of stray artifacts
- [ ] Git status: no tracked changes to `dontlie/storage.py`, `sign.py`,
      `proxy.py`, `cli.py`, `test_dontlie.py`, `test_integrity.py`,
      `test_proxy_security.py` outside the explicit core change

## Version bump

- [ ] Bump version in `pyproject.toml` (`[project] version`)
- [ ] Add a `## X.Y.Z — YYYY-MM-DD` entry in `CHANGELOG.md` with the
      user-visible changes since the last tag
- [ ] Confirm `from dontlie import __version__` matches the new version

## Documentation sweep

- [ ] `README.md` "Quickstart" works on a fresh install
- [ ] `demo/README.md` quickstart works on a fresh checkout
- [ ] `demo/runbooks/OFFLINE.md` and `demo/runbooks/MINIMAX_LIVE.md`
      commands actually work as written
- [ ] GitHub release notes match `CHANGELOG.md`
- [ ] `LAUNCH.md` (this repo) "What it proves / does not prove" list
      matches the current capability surface
- [ ] No references to deleted files (e.g. a removed runbook, an old
      CLI subcommand name)

## Security & privacy

- [ ] No secrets, API keys, or tokens in any committed file
- [ ] `demo/samples/` contains only deterministic mock data
- [ ] `demo/work/` is in `.gitignore` (run `git check-ignore demo/work`)

## Tag

- [ ] `git tag -s vX.Y.Z -m "Release X.Y.Z"`
- [ ] Push tag: `git push origin vX.Y.Z`
- [ ] Trigger PyPI publish via GitHub Actions (manual step if not auto)

## Post-release

- [ ] Confirm PyPI release is visible
- [ ] Smoke-test `pip install dontlie` in a clean venv
- [ ] Update any external docs (e.g. product wiki) if the public API changed
