# Don't-Lie ground-truth lane

> Optional, opt-in, privacy-respecting route attestation. Offline by default.

## The bet

Every signed `Receipt` proves **local record integrity**: the receipt
was signed by your key, the chain links, and nothing inside the database
was edited after the fact. It does **not** prove that the response
actually came from the provider the operator claims. Don't-Lie's
ground-truth lane adds a vendor-independent proof-of-route channel on
top of that, without disturbing the existing receipts.

## What this lane proves

* The original request and a blinded probe request both reached the same
  upstream provider and resolved to the same model identifier.
* An external witness observed a `receipt_payload_sha256` /
  `correlation_id` / `nonce` triple at a given time and signed for it.
* An operator's blind probe and the operator's receipt agree on the
  route.

## What this lane does **not** prove

* That any model response is correct, factual, or non-hallucinated.
* That the operator's signed receipt is honest — only that the
  operator's key signed it (the existing `storage.verify_chain`
  already covers that).
* That a witness understands the conversation. Witnesses see only
  digests and a short nonce.
* Anything about content. Digests, not prompts/responses, cross process
  and network boundaries.

## Components

| Path | Role |
|---|---|
| `dontlie/dontlie/groundtruth.py` | Top-level façade: `BlindProbe`, `RouteAttestation`, `attest_receipt`, serialization |
| `dontlie/groundtruth/__init__.py` | Peer-witness subpackage façade |
| `dontlie/groundtruth/envelope.py` | Signed request/attestation dataclasses, JSON envelopes |
| `dontlie/groundtruth/client.py` | `OfflineWitness` (default), `InProcessWitness`, `RemoteHTTPWitness` stub |
| `dontlie/groundtruth/verifier.py` | `WitnessVerifier`, `verify_attestation` |
| `dontlie/test_groundtruth.py` | Conformance + hostile-actor tests |
| `docs/groundtruth.md` | This document |

## Threat model

| Adversary | Mitigation |
|---|---|
| Operator edits the receipt and back-fills a route attestation | `RouteAttestation` is signed by the operator key, not the receipt. Verifiers can cross-check `receipt_payload_sha256` against the actual `storage.Receipt`. |
| Operator reroutes traffic to a different provider | A blind probe run against the original provider returns the same digest; mismatch raises `RouteMismatchError`. |
| Witness colludes with operator | Witness holds its own Ed25519 key. Witnesses never see prompt or response text, only digests, so collusion cannot reveal content — only that a digest existed. |
| Witness forges an attestation | `PeerWitnessAttestation.verify(witness_public_pem)` is required to pass; verifiers reject unknown `witness_key_id`. |
| Replay of a stale request | `expires_at` is part of the signed payload; `is_expired()` is checked before signing. |
| Probe runner leaks prompt content | The bundled runner is operator-supplied; the in-tree default does not include any network code and uses an injected callable. Subprocess wrappers must scrub environment variables. |

## Usage

```python
from dontlie import groundtruth as gt
from dontlie.groundtruth import (
    InProcessWitness,
    WitnessKey,
    build_signed_request,
    WitnessVerifier,
)

# 1. Operator side: blind probe (offline by default; attach a runner first).
gt.attach_runner(my_runner)  # callable prompt -> BlindProbeResult
probe = gt.BlindProbe(mode="runner")
result = probe.run("hi")
att = gt.attest_receipt(receipt, result, operator_key_pair=operator)
gt.verify_route_attestation(att, receipt, result, operator_public_key=operator.public)

# 2. Operator side: ask an in-process witness to corroborate.
witness_key = WitnessKey(
    key_id="witness-prod-1",
    public_key=witness_pub,
    private_key=witness_priv,  # only on the witness side
    label="prod",
)
witness = InProcessWitness(witness_key, verify_requester=True)
request = build_signed_request(
    receipt_payload_sha256=receipt["payload_sha256"],
    provider=receipt["extra"]["provider"],
    model=receipt["model"],
    correlation_id=receipt["timestamp"],
    requester_key_id=operator.key_id,
    requester_private_key=operator.private,
)
attestation = witness.attest(request)

# 3. Verifier (separate role, separate process) cross-checks.
verifier = WitnessVerifier({witness_key.key_id: witness_key})
result = verifier.verify(attestation)
assert result, f"witness verification failed: {result.reason}"
```

## Privacy

Only SHA-256 digests and a 16-byte random nonce cross the witness
boundary. Prompts and responses never leave the operator process.

## Failure semantics

| Failure | Exception |
|---|---|
| Probe requested in offline mode | `BlindProbeUnavailable` |
| Probe returns a different provider/model | `RouteMismatchError` |
| Expired witness request | `RuntimeError` from client; `WitnessError` on verify |
| Tampered operator/witness signature | `WitnessVerification(ok=False, reason=...)` |
| Unknown witness key id | `WitnessVerification(ok=False, reason="unknown witness key")` |

## Offline default

`BlindProbe(mode="offline")` and `OfflineWitness` are the only shipped
defaults. Both short-circuit before any network call. The lane can be
opted in one component at a time.
