# Contributing to Don't-Lie

## Setup

```sh
cd dontlie
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
```

## Required checks

```sh
make test
make lint
make typecheck
make demo
```

The offline demo must not require network access or a provider key. Live
MiniMax testing is optional and must use synthetic prompts and environment
variables; never commit credentials or production receipts.

## Integrity changes

Treat `storage._canonical_payload`, chain-v2 metadata, and public-key handling
as compatibility-sensitive. Add migration and tamper tests for any schema or
canonicalization change. Preserve the legacy `verify_chain()` tuple API while
using `verify_chain_report()` for new diagnostics.

## Proxy changes

Keep client-to-proxy and proxy-to-provider configuration separate. Never log
provider credentials, signing keys, or raw authorization headers. Test both
non-streaming and streaming status/error paths, and keep the proxy bound to
loopback by default.

## Claims

Documentation must distinguish local record integrity from model truth and
provider provenance. Do not describe roadmap features—cloud sync, native
Anthropic Messages support, encryption, or team administration—as shipped.
