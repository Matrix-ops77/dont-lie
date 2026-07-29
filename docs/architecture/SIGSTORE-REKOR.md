# Sigstore Rekor v2 integration

**Status:** design only · **Tier 3** (ship 4–8 weeks after `anchor daily` is stable, opt-in flag) · **Date:** 2026-07-29
**Closes:** `tech_edge_2026.md` §4.1, §4.2; SYNTHESIS_2026 §7 #10.

---

## 1. What Sigstore Rekor is

**Sigstore** is a CNCF project (graduated 2023) providing free
public-key infrastructure for software supply-chain signing:

- **Cosign** — container/artifact signing CLI.
- **Fulcio** — a free CA issuing short-lived (10-min) X.509
  code-signing certs bound to an OIDC identity.
- **Rekor** — the transparency log.

**Rekor v2** (GA October 2025) is the version to integrate with.
It is **tile-based, backed by Trillian-Tessera** (the modernized
successor to Trillian). Key changes from v1:

- **Yearly shards** (`log<year>-<rev>.rekor.sigstore.dev`); old
  shards frozen and archived as static tiles.
- **Integrated witnessing** (countersigning).
- **No inline timestamp.** Clients must fetch a separate
  RFC 3161 signed timestamp and include it in the bundle. The
  most important v1→v2 change: a Rekor v2 entry on its own does
  not prove the entry existed at a specific time.
- **Two entry types only:** `hashedrekord` (hash + signature)
  and `dsse`. v1's 11 entry types are gone.
- **Public SLO:** 99.5% availability. Public, no signup.

Sources: [Rekor v2 GA](https://blog.sigstore.dev/rekor-v2-ga/),
[sigstore.dev docs](https://docs.sigstore.dev/).

## 2. Why a Don't-Lie user might want it

The current daily anchor (`anchor daily`) gives a **local** +
**witness-co-signed** + **OTS-pending** chain-integrity claim —
sufficient for the 80% buyer. For the 20% who want **public,
third-party-monitored** anchoring, the optional Rekor
integration provides:

- A **public Merkle root** anyone can verify against the Rekor
  log (not just the operator's witness).
- A **monitored log**: Sigstore's infra is watched by multiple
  independent parties; an entry is harder to retroactively
  hide than a witness attestation.
- **Cited interop**: SOC 2 auditors and EU AI Act assessors
  increasingly recognize Rekor as the "transparency log"
  standard (Microsoft's "Securing AI Agents" tutorial
  recommends Rekor + RFC 3161 TSA + Object Lock).

A **Tier 3 / Pro-tier / Compliance-tier** feature, not a
default. See §3 for the privacy trade-off.

## 3. The privacy trade-off

Publishing the daily Merkle root has two leakage properties:

- **Receipt count.** The leaf count is in the entry. A
  competitor monitoring Rekor sees "this operator signed ~200
  prompts on 2026-07-28" — useful competitive intel.
- **Call timing.** The COSE envelope's `iat` is a wall-clock
  timestamp. Combined with the count, it gives a "this
  operator is a power user" or "idle today" signal.

**This is why it is opt-in.** The local-only path
(`anchor daily` without `--rekor`) gives chain-integrity for
99% of users. Rekor is for the buyer who **deliberately** wants
public proof and accepts the reputational signal.

The user opts in per-vault via a flag: `dontlie anchor daily
--rekor`. The opt-in state is written to vault metadata and is
itself signed by the operator key, so the auditor can verify
the opt-in was intentional.

## 4. Integration path

`anchor daily` gains a `--rekor` flag:

```bash
dontlie anchor daily --rekor                  # daily Merkle root → Rekor
dontlie anchor daily --rekor --rekor-url https://rekor.sigstore.dev
```

### 4.1 The Rekor entry body

A `hashedrekord` Rekor v2 entry:

```json
{
  "spec": {
    "data": {
      "hash": { "algorithm": "sha256", "value": "0a1b..." }
    },
    "signature": {
      "content":    "base64(Ed25519 sig over COSE_Sign1)",
      "public_key": "base64(SPKI Ed25519 pub)"
    }
  },
  "timestamp": {                               ; RFC 3161 timestamp
    "signed_entry": "base64...",
    "signing_cert": "base64..."                ; FreeTSA cert
  }
}
```

The workflow:

1. Build the `COSE_Sign1` envelope per
   [SCITT-ALIGNED-MERKLE.md](SCITT-ALIGNED-MERKLE.md) §2 (the
   Merkle root is the `payload`; the signature is Ed25519
   over protected headers + payload).
2. POST the COSE envelope body + signature to Rekor v2's
   `hashedrekord` endpoint.
3. POST a separate request to **FreeTSA** (a free RFC 3161
   TSA) to get the signed timestamp; embed it in the bundle.
4. Submit the combined bundle to Rekor.

### 4.2 The expected response

```json
{
  "uuid":             "abc123...",
  "body":             "base64...",
  "integrated_time":  1753833600,
  "log_index":        12345678,
  "log_id":           "0a1b...",
  "verification": {
    "inclusion_proof": {                       ; Merkle inclusion proof
      "log_index": 12345678,
      "tree_size": 87654321,
      "root_hash": "...",
      "hashes":    ["...", "...", "..."]
    },
    "signed_entry_timestamp": "base64..."      ; RFC 3161
  }
}
```

The auditor verifies the inclusion proof on a clean laptop
without contacting Sigstore. The CLI stores the response in
`~/.local/share/dontlie/rekor/<day>.json` alongside the daily
anchor.

### 4.3 Rekor v1 vs v2 endpoints

| Log | Endpoint | Notes |
|---|---|---|
| **Rekor v2** | `https://rekor.sigstore.dev/api/v2/log/entries` | **Default.** GA Oct 2025. Tile-based, Trillian-Tessera. |
| Rekor v1 | `https://rekor.sigstore.dev/api/v1/index/entries` | Legacy. Trillian-based. Deprecation path. |

**Default to v2.** v1 is for compatibility with existing
Sigstore tooling; v2 is the future.

## 5. The fallback path

If Rekor is down (the public SLO is 99.5%, not 100%), fall
back to **OpenTimestamps** (already implemented in `ots.py`
and called from `anchor_daily.py`):

```python
# Pseudo-code in anchor_daily.py
try:
    rekor_response = post_to_rekor(cose_envelope)
except RekorUnavailable:
    print("Rekor unavailable; falling back to OTS-only anchor")
    ots_path = create_ots_for_root(merkle_root, day)
    # OTS-pending is already in the daily flow
```

The fallback is **silent and lossless** — the daily anchor
always produces a valid OTS pending file even when Rekor is
unreachable. The Rekor submission is retried on the next
`anchor daily` run (idempotent: a duplicate entry with the
same COSE body is a no-op in Rekor's Merkle tree).

The `--rekor` flag does not change the existing local chain,
witness co-sign, or OTS-pending path. It is a strict superset:
**add a Rekor entry on top of the existing daily anchor**.

## 6. "No critical dependency" — why this is not vendor lock-in

Sigstore is a **public good**, not a paid SaaS. The
service-operator is the Linux Foundation / CNCF; the source
code is open (github.com/sigstore/rekor-tiles); the public
endpoints are rate-limited but not paywalled. If the public
endpoints disappear tomorrow, an operator can:

- Run their own Rekor instance (`rekor-tiles` is a Go binary
  + a SQLite/Postgres backend). The same COSE envelope body
  submits; the response is structurally identical.
- Wait for the OTS Bitcoin confirmation, which is
  Sigstore-independent.
- Rely on the local witness co-signature, a single-node
  CloudFlare Worker (or self-hosted equivalent) under the
  operator's own control.

The integration is **not vendor lock-in** because (a) the data
model is a public IETF draft (SCITT, COSE), (b) the log is
open-source, and (c) the local-first architecture means the
vault is verifiable offline without Rekor. Rekor is a **public
anchor**, not a critical path.

## 7. References

- [Rekor v2 GA blog post](https://blog.sigstore.dev/rekor-v2-ga/)
- [docs.sigstore.dev](https://docs.sigstore.dev/)
- [github.com/sigstore/rekor-tiles](https://github.com/sigstore/rekor-tiles)
- [Microsoft — Securing AI Agents with Cryptographic Receipts](https://microsoft.github.io/ai-agents-for-beginners/18-securing-ai-agents/)
- `tech_edge_2026.md` §4.1, §4.2; `SYNTHESIS_2026.md` §5.4
- [SCITT-ALIGNED-MERKLE.md](SCITT-ALIGNED-MERKLE.md) (COSE envelope spec)
