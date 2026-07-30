# Don't-Lie — Privacy Policy

**Last updated:** 2026-07-30

**Scope:** This policy applies to Don't-Lie as it ships today — the
open-source local-first software at
`github.com/Matrix-ops77/dont-lie`. We do not operate a hosted
service, we do not run a website that collects personal data, and
we do not have a billing or account system. The policy below states
what the released software does and does not do, and what will
change if we ever ship a hosted service.

## What we (the project maintainers) collect

**Nothing.** The released v0.3.x software runs entirely on your
hardware. The project maintainers do not see your prompts, your
responses, your receipts, your signing keys, or your upstream API
keys. There is no analytics endpoint, no telemetry, no remote
beacon. The No-Phone-Home pledge in `PLDG.md` is enforced by an
automated test (`test_phone_home.py`).

## What the local software does and does not do

The local software:

- Generates an Ed25519 signing keypair on your machine, stored under
  your `$DONTLIE_KEY_DIR` (defaults to `~/.config/dontlie/keys/`).
- Records signed receipts to a local SQLite database under
  `$DONTLIE_DB` (defaults to `~/.local/share/dontlie/vault.db`).
- Optionally forwards receipts through a `witness notary` you
  configure. The default witness is not deployed; if you point at
  one, that witness sees the receipt hash (not the prompt/response
  payload) and is a third party you have chosen to trust.

The local software does **not**:

- Phone home. The PLDG is test-enforced.
- Upload your vault to any server unless you explicitly configure
  it to (e.g. via a witness notary URL, a backup target, or a remote
  anchor). All such configurations are opt-in.
- Read your prompts or responses outside the subprocess that signs
  the receipt.

## Subprocessors

**None today.** The v0.3.x release has no hosted backend and no
subprocessor relationships. If a hosted service ships in the
future, this section will be updated with the specific subprocessors
(e.g., a payment processor, a cloud host) at least 30 days before
the service opens to the public.

## Your rights (over your own data)

Because the data is on your hardware, you have all the rights
automatically. The shipped CLI supports them:

- **Access:** `dontlie export` writes a portable verification
  bundle containing every receipt in your vault.
- **Deletion:** delete the vault file. The local software will
  generate a new empty vault on next run.
- **Portability:** the portable bundle is a single JSON file with
  the receipts, signatures, and public keys. It is verifiable
  offline on a clean machine using the `dontlie verify --export`
  command.
- **Key rotation:** generate a new keypair with `dontlie gen-key`,
  re-sign the receipts you want to keep, and revoke the old key
  with `dontlie revoke-key`.

## When a hosted service exists

The first time a hosted service ships, this policy will be amended
to include:

- What data the hosted service receives from you.
- Where it is stored, for how long, and under what encryption.
- Which subprocessors handle it.
- How you can exercise access, deletion, and portability against
  the hosted service.
- A breach-notification commitment.

We will not retroactively apply hosted-service terms to anyone who
installed the v0.3.x local-first software. The contract you agreed
to when you ran `pip install dontlie` is the contract that applies.

## Children

Don't-Lie is a developer tool. We do not direct it at children and
we do not knowingly collect information from children. If a
hosted service is added, it will require users to affirm they are
of legal age in their jurisdiction.

## Contact

Open a public issue at `github.com/Matrix-ops77/dont-lie/issues`
for accountable contact. There is no private support channel today.
