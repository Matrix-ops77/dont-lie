---
name: Pull request
about: Ship a focused change to Don't-Lie.
title: ""
labels: []
assignees: []
---

## What changed

A single sentence plus a short list.

## Why

The customer pain or incident it addresses.

## What Don't-Lie proves (and doesn't)

Walk through any change to the integrity surface. If your change is
purely cosmetic, state that explicitly.

## Tests

- [ ] Added tests covering the new behavior.
- [ ] `python3 -m unittest discover -t .` exits 0.
- [ ] `ruff check` and `mypy --strict` on the integrity core.

## Documentation

- [ ] README updated if user-facing.
- [ ] SECURITY.md updated if the threat model changed.
- [ ] BRAND.md updated if a new UI element introduces a new claim.

## Brand voice

- [ ] No "truth verified," "AI is correct," or "tamper-proof."
- [ ] No fake testimonials.
- [ ] No gradients in the UI.
- [ ] Single status color (verified / failed / neutral).
