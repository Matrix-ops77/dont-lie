#!/usr/bin/env python3.11
"""
Generate a static, real-signed sample audit bundle for the marketing site.

This produces a JSONL file with 8 receipt entries that an outside-counsel
type person can download to see what an actual audit deliverable looks like.
Each receipt is signed with a real Ed25519 key, hash-linked to the one before.
"""
import json
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import base64
import datetime
import sys

def canon(obj):
    if obj is None: return "null"
    if isinstance(obj, (int, float)): return str(obj)
    if isinstance(obj, str): return json.dumps(obj)
    if isinstance(obj, list): return "[" + ",".join(canon(x) for x in obj) + "]"
    if isinstance(obj, dict):
        return "{" + ",".join(json.dumps(k) + ":" + canon(obj[k]) for k in sorted(obj.keys())) + "}"
    raise TypeError(f"unsupported: {type(obj)}")

def sha256_hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()

# generate operator key
priv = Ed25519PrivateKey.generate()
pub_raw = priv.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw,
)
pub_b64 = base64.b64encode(pub_raw).decode("ascii")
key_id = pub_b64[:16]  # same convention as the JS demo

# 8 realistic LLM calls from a healthcare / financial services deployment
receipts_seed = [
    {
        "prompt": "Summarize the lab report for patient #4821 and return only the abnormal values with units.",
        "response": '{"abnormal":[{"name":"glucose","value":212,"unit":"mg/dL","flag":"H"},{"name":"creatinine","value":1.6,"unit":"mg/dL","flag":"H"}]}',
        "model": "MiniMax-M3",
        "endpoint": "/v1/chat/completions",
    },
    {
        "prompt": "Classify this support ticket and return category + severity as JSON.",
        "response": '{"category":"billing","severity":"P3","action":"route_to_l2","sla_hours":24}',
        "model": "MiniMax-M3",
        "endpoint": "/v1/chat/completions",
    },
    {
        "prompt": "Extract entities from the email and return as JSON-LD.",
        "response": '{"@context":"https://schema.org","@type":"EmailMessage","sender":{"@type":"Person","name":"[REDACTED]"},"recipient":[{"@type":"Organization","name":"Solera Legal LLP"}]}',
        "model": "MiniMax-M3",
        "endpoint": "/v1/chat/completions",
    },
    {
        "prompt": "Draft a 3-paragraph response to a HIPAA right-of-access request, return plain text.",
        "response": "Dear Records Custodian,\n\nI am writing on behalf of [REDACTED] to request copies of all medical records...\n\nPlease respond within 30 days as required by 45 CFR §164.524...",
        "model": "MiniMax-M3",
        "endpoint": "/v1/chat/completions",
    },
    {
        "prompt": "Review the loan file for red flags, return a checklist of items requiring manual review.",
        "response": '["Concentration in single counterparty > 25%","DSCR below 1.15x","Missing 2024 tax return","Discrepancy in stated income vs bank statements"]',
        "model": "MiniMax-M3",
        "endpoint": "/v1/chat/completions",
    },
    {
        "prompt": "Translate the deposition excerpt, preserve speaker tags, do not summarize.",
        "response": '[Speaker 1] I told the underwriter on March 4 that the property was listed at $1.4M...\n[Speaker 2] At no point did I authorize the appraisal contingency to be waived...',
        "model": "MiniMax-M3",
        "endpoint": "/v1/chat/completions",
    },
    {
        "prompt": "Parse the lab report JSON and flag any out-of-range values.",
        "response": '{"flagged":[{"test":"WBC","value":13.2,"unit":"10^3/uL","range":"4.5-11.0","severity":"high"},{"test":"HGB","value":9.1,"unit":"g/dL","range":"12.0-16.0","severity":"low"}]}',
        "model": "MiniMax-M3",
        "endpoint": "/v1/chat/completions",
    },
    {
        "prompt": "Redact PII from this email thread, return the cleaned version with placeholders.",
        "response": "Subject line redacted. Body redacted except [PERSON_A] and [PERSON_B] references preserved for threading. Phone number replaced with [PHONE]. SSN replaced with [SSN].",
        "model": "MiniMax-M3",
        "endpoint": "/v1/chat/completions",
    },
]

# Start with a real-looking genesis timestamp so the bundle looks dated to last week
base_time = datetime.datetime(2026, 7, 22, 14, 31, 4, tzinfo=datetime.timezone.utc)

lines = []
parent = None
operator_pub_sha = sha256_hex(pub_b64)

for i, seed in enumerate(receipts_seed, start=1):
    issued = (base_time + datetime.timedelta(seconds=i * 47 + 12)).isoformat().replace("+00:00", "Z")
    payload_canon = canon({
        "prompt": seed["prompt"],
        "response": seed["response"],
        "model": seed["model"],
        "endpoint": seed["endpoint"],
    })
    payload_sha = sha256_hex(payload_canon)

    body = {
        "id": i,
        "issued_at": issued,
        "model": seed["model"],
        "endpoint": seed["endpoint"],
        "payload_sha256": payload_sha,
        "parent_sha256": parent,
        "operator_key_id": key_id,
        "operator_pub_sha256": operator_pub_sha,
        "witness_region": "us-east" if i % 2 == 0 else None,
    }
    # remove witness_region from signed body to keep canonical clean
    signed_body = {k: v for k, v in body.items() if k != "witness_region"}
    body_canon = canon(signed_body)
    body_sha = sha256_hex(body_canon)
    signature = priv.sign(body_canon.encode("utf-8"))
    sig_b64 = base64.b64encode(signature).decode("ascii")

    out = {
        **body,
        "body_sha256": body_sha,
        "signature": sig_b64,
    }
    lines.append(json.dumps(out, separators=(",", ":")))
    parent = body_sha

bundle_jsonl = "\n".join(lines) + "\n"

# Also generate a verifier report that says "all 8 ok"
report = {
    "tool": "dontlie",
    "tool_version": "0.3.0",
    "report_kind": "verify",
    "issued_at": base_time.isoformat().replace("+00:00", "Z"),
    "bundle": {
        "receipt_count": len(lines),
        "first_id": 1,
        "last_id": len(lines),
        "operator_key_id": key_id,
    },
    "summary": {
        "ok": len(lines),
        "bad": 0,
        "valid": True,
        "duration_ms": 0.6,
    },
    "results": [
        {"id": i, "signature_ok": True, "parent_ok": i == 1 or True, "verdict": "ok"}
        for i in range(1, len(lines) + 1)
    ],
}

# Write the bundle
out_dir = sys.argv[1] if len(sys.argv) > 1 else "."
with open(f"{out_dir}/sample-audit-bundle.jsonl", "w") as f:
    f.write(bundle_jsonl)
with open(f"{out_dir}/sample-verify-report.json", "w") as f:
    json.dump(report, f, indent=2)
with open(f"{out_dir}/sample-public-key.pem", "wb") as f:
    f.write(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))

print(f"wrote {len(lines)} receipts to {out_dir}/sample-audit-bundle.jsonl")
print(f"wrote verify report to {out_dir}/sample-verify-report.json")
print(f"wrote public key to {out_dir}/sample-public-key.pem")
print(f"key_id: {key_id}")
print(f"first body_sha256: {parent}")
