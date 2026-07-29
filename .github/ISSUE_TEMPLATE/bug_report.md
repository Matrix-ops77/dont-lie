---
name: Bug report
about: A reproducible bug in the Don't-Lie CLI, proxy, or one of the client packages.
title: "[bug] "
labels: bug
assignees: []
---

## What happened

A clear, concise description.

## Steps to reproduce

```
$ git clone https://github.com/Matrix-ops77/dont-lie
$ cd dont-lie
$ pip install -e .
$ dontlie ...
```

## Expected

What you expected to see.

## Actual

What you actually saw, including the exact command output, traceback, and
exit code.

## Environment

- OS and version:
- Python version (`python3 --version`):
- Don't-Lie version (`dontlie version`):
- Provider (OpenAI / Anthropic / mock / …):
- Client version (`dontlie-openai==…`, `dontlie-langchain==…`):

## Receipt package

If the bug involves a receipt failure, attach `receipts.bundle.json` and
the output of `dontlie verify --export receipts.bundle.json --verbose`.

## Severity

- [ ] data loss / corruption
- [ ] security / privacy
- [ ] functional regression
- [ ] cosmetic / docs
