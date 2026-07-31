# Release artifact verification

Don't-Lie release assets are intended to be independently verifiable without
trusting a checksum copied into prose.

Starting with v0.3.8, a controlled release contains:

- `dontlie-X.Y.Z-py3-none-any.whl`
- `dontlie-X.Y.Z.tar.gz`
- `dontlie-X.Y.Z.cdx.json` — a reproducible CycloneDX 1.6 SBOM generated from
  a clean environment containing the release wheel
- `SHA256SUMS`
- `dontlie-vX.Y.Z.intoto.jsonl` — keyless SLSA provenance covering the wheel,
  sdist, SBOM, and checksum manifest

These files establish package contents, dependency inventory, artifact
digests, and the GitHub workflow identity that produced the release. They do
not establish that the software is vulnerability-free or suitable for a
particular regulated use.

## Verify checksums

Download all four subject files and run:

```bash
sha256sum --check SHA256SUMS
```

On macOS:

```bash
shasum -a 256 --check SHA256SUMS
```

## Verify build provenance

Install the official
[`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier), then run:

```bash
slsa-verifier verify-artifact \
  dontlie-0.3.8-py3-none-any.whl \
  dontlie-0.3.8.tar.gz \
  dontlie-0.3.8.cdx.json \
  SHA256SUMS \
  --provenance-path dontlie-v0.3.8.intoto.jsonl \
  --source-uri github.com/Matrix-ops77/dont-lie \
  --source-tag v0.3.8
```

A successful result verifies that the provenance signature is valid, its
transparency-log entry is valid, the source repository and tag match, and the
downloaded artifact digests are subjects of that provenance.

The upstream SLSA generator must currently be referenced by a full semantic
version tag for `slsa-verifier` compatibility. This is a documented exception
to the repository's normal commit-SHA pinning rule for third-party Actions.

## Review the SBOM

The SBOM is JSON and can be inspected directly:

```bash
python -m json.tool dontlie-0.3.8.cdx.json >/dev/null
```

CycloneDX validates the document during generation. A buyer may additionally
run its preferred SBOM policy, vulnerability, or license scanner. Findings
from those tools require review; an SBOM is an inventory, not a security
certification.
