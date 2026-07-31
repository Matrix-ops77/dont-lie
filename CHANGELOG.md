# Changelog

## 0.3.8 — 2026-07-30

- Added `dontlie compliance hipaa-security|eu-ai-act` with text, gap-only, and
  deterministic JSON output. The maps separate supported evidence,
  supporting evidence, operator-required controls, and out-of-scope duties.
- Rewrote the HIPAA and EU AI Act operator memos against official HHS,
  EUR-Lex, and European Commission sources. Removed unsupported claims about
  Article 12 coverage, HIPAA log retention, capture completeness, regulatory
  deadlines, and universal integration time.
- Refreshed the competitive scorecard against current primary project
  documentation and converted competitor strengths into an evidence-driven
  priority order.
- Extended the public-claims gate to reject unsupported HIPAA, AI Act, and
  audit-pass language, and removed blanket compliance-memo exemptions.
- Pinned the remaining PyPI-publish and GitHub-release Actions to exact commit
  SHAs.
- Added a reproducible CycloneDX 1.6 SBOM, `SHA256SUMS`, and keyless SLSA
  provenance to the controlled release workflow. Release publication now
  waits for the provenance job as well as the full test and reproducibility
  matrices.

## 0.3.7 — 2026-07-30

- Added `dontlie prove OUTPUT_DIR`, a single command that verifies the local
  chain and atomically produces a portable evidence packet containing the
  canonical bundle, self-contained HTML report, manifest, checksums, and
  offline verification instructions.
- Made proof reports explicit about their trust boundary: chain integrity is
  verified, while signer identity requires external key pinning, provider
  identity is not independently attested, and answer truth is not evaluated.
- Replaced demo-only report reproduction paths with truthful packet-relative
  and standalone-bundle instructions.
- Added focused failure-path coverage for empty or invalid vaults, unsafe
  output replacement, export verification, artifact hashes, and report
  instructions.
- Normalized source-archive file modes in addition to timestamps and ownership,
  eliminating the macOS/Linux permission-metadata difference while preserving
  intentional executable bits.
- Added an isolated strict-type gate for the proof-packet implementation and
  report renderer, plus regression tests for cross-platform sdist modes.

## 0.3.6 — 2026-07-30

- Fixed the Browser Proof Lab receipt write path and added a real headless
  browser test for create, verify, tamper detection, and reset.
- Replaced stale hard-coded test totals with the live CI badge and descriptive
  test coverage.
- Pointed package metadata to the GitHub repository until a single official
  project site is deployed, and documented the working GitHub release-wheel
  install while PyPI publication remains unavailable.
- Replaced a nonexistent, silently ignored mypy target with a real strict
  type-check gate over the signing and protocol modules.
- Updated the release checklist to require the runtime browser test, public
  claims scan, honest type-check scope, and built-wheel reproducibility gate.
- Corrected the Browser Proof Lab copy so it describes the implemented local
  reset flow instead of claiming an unimplemented browser export restore.
- Made wheel and source-archive builds byte-reproducible using a fixed source
  epoch, pinned build tooling, normalized archive metadata, and two-build hash
  comparison.
- Added an explicit Chrome/ChromeDriver inventory check before mandatory
  browser tests, and gated PyPI publication behind an operator-controlled
  repository variable until Trusted Publishing is configured.

## 0.3.5 — 2026-07-30

Stress-test hardening for the receipt system before launch.

- `cmd_witness_attest` now recomputes the canonical payload hash locally and
  refuses to attest a tampered receipt. The witness service is a hash notary
  by design; the CLI was the place to enforce "what I sign matches what's in
  the vault."
- `storage._connect()` defensively wraps a `str` `db_path` in `Path()` so
  callers that pass `args.vault` (a string) don't crash on
  `db_path.parent.mkdir`.
- `onboard/dontlie-passive` is now actually tracked in git with mode
  `100755`; it was previously excluded by `.gitignore`, which made every
  fresh checkout (and the CI run) fail
  `test_zero_arg_executable_works_before_activation`.
- Test suite now runs cleanly on Python 3.10, 3.11, 3.12 from a fresh
  checkout — no `PYTHONPATH=REPO_ROOT` shadowing, no port collisions on
  the demo, no `httpx`/`cryptography` missing in subprocess tests.
- Release workflow now treats the wheel-install smoke test as a hard
  gate before publishing to PyPI or creating a GitHub release.
- Public paperwork (Terms, Privacy, DPA, README pricing) rewritten to
  match v0.3.x local-first reality; hosted-service terms are drafted but
  labeled "when the hosted service ships."

## 0.3.4 — 2026-07-29

- Three release-blocking onboarding bugs reported by Codex in a fresh
  venv: missing `dontlie-passive` on PATH after `pip install`,
  zero-arg invocation before activation, and the launcher pointing at a
  non-existent bootstrap directory.
- Encryption + verify-url + phone-home tests now respect whether
  `dontlie` is already installed in the test runner.
- Demo scripts refactored into `dontlie/demo/` and hardened against
  port collisions and slow CI runners.
- Live provider tests gated behind `DONTLIE_RUN_LIVE_TESTS=1` so CI
  never makes silent network calls.

## 0.3.3 — 2026-07-28

- Force-push to a clean repo history to drop early scaffold commits
  and start the public history at a clean v0.3.x state.
- README rewritten as a visual story; the dark, screenshot-driven
  layout matches the v0.3.x visual direction.
- Internal strategy / sales / personal docs moved to a private
  `dontlie-internal` repo via `git-filter-repo` + force-push.
- GitHub repo renamed `Matrix-ops77/dontlie` → `Matrix-ops77/dont-lie`
  via the API; the Python package name stays `dontlie` to match the
  CLI.

## 0.2.0 — 2026-07-24

- Added chain-v2 previous-payload SHA-256 links and parent continuity checks.
- Added per-key public-key retention, rotation-aware verification, revocation,
  and portable signed bundles.
- Added `dontlie doctor`, `revoke-key`, verbose verification, and bundle export.
- Hardened proxy request limits, validation, header filtering, streaming, error
  status propagation, health checks, and graceful shutdown.
- Added `show ID` for full receipt inspection and a standalone HTML proof report.
- Added CI, Makefile, package metadata, and release documentation.

## 0.1.0

Initial local SQLite receipt vault and OpenAI-compatible proxy.
