# Passive capture: privacy and operational limits

## The important boundary

**Don't-Lie signs what the model sees, not what the user thinks they sent.**

The passive wrappers capture the arguments at the provider SDK's final public
request method. That includes system instructions, expanded conversation
history, tool schemas, sampling settings, and other values a framework may have
added after the user's original prompt. Credentials and transport headers are
redacted or omitted.

This is still not a packet capture. A provider SDK can transform arguments after
the wrapped method begins, and a remote gateway can transform them again. When
byte-for-byte HTTP evidence is required, use the Don't-Lie proxy rather than the
passive SDK hook.

## Storage

- `DONTLIE_PROJECT_VAULT` selects an explicit database file or directory.
- `DONTLIE_DB` is accepted for compatibility.
- Otherwise the hook searches upward for an existing `.dontlie/vault.db`, then
  for a project marker (`.git`, `pyproject.toml`, `package.json`, or `setup.py`).
  It stores receipts at `<project>/.dontlie/vault.db`.
- If no project marker exists, it uses `<current-working-directory>/.dontlie/vault.db`.

Prompts and responses are stored locally in plaintext SQLite and signed with the
existing Don't-Lie key. Disk encryption and repository ignore rules remain the
operator's responsibility. Do not enable passive capture in a project whose
model traffic cannot be stored locally.

## Fail-open behavior

Provider calls keep their original behavior if serialization, key loading,
key generation, SQLite, signing, or receipt append fails. Provider exceptions
are re-raised unchanged after a best-effort error receipt.

Streams are signed when fully consumed, closed, or exited from their context
manager. A stream that is abandoned without exhaustion or close may not produce
a receipt because Python provides no reliable completion signal for that object.
The returned stream is an attribute-forwarding proxy, not the provider SDK's
exact concrete type; code that relies on stream `isinstance` checks should use
the explicit Don't-Lie HTTP proxy instead.

Set `DONTLIE_PASSIVE=0` to disable the startup hook for a process.
