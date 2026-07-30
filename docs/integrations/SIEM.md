# SIEM integration — shipping Don't-Lie receipts into your existing stack

Don't-Lie receipts are designed to be SIEM-friendly. Every receipt is a self-describing JSON object with Ed25519 signature, SHA-256 payload hash, parent link, and metadata. There is **no proprietary format** and no custom parser needed.

## The one command

```bash
dontlie tail --follow --json
```

Output is NDJSON (one receipt per line). Every line includes the vault path and a content hash so an SIEM can dedup.

```json
{"id":1024,"model":"MiniMax-M3","timestamp":"2026-07-25T17:11:18.133109+00:00","payload_sha256":"5d6f9a32...","signature":"ob5XGDNF...","prompt":"...","response":"...","_source":"dontlie","_vault":"/Users/me/.local/share/dontlie/vault.db"}
```

## Splunk (HTTP Event Collector)

```bash
SPLUNK_HEC="https://splunk.example.com:8088/services/collector/event"
SPLUNK_TOKEN="your-hec-token"

dontlie tail --follow --json | while read -r line; do
  curl -sS -X POST "$SPLUNK_HEC" \
    -H "Authorization: Splunk $SPLUNK_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"event\": $line, \"sourcetype\": \"dontlie:receipt\", \"index\": \"ai_audit\"}"
done
```

Or as a one-shot bulk upload (last 7 days of receipts):

```bash
dontlie tail --last 10000 --json > /tmp/receipts.ndjson
curl -sS -X POST "$SPLUNK_HEC" \
  -H "Authorization: Splunk $SPLUNK_TOKEN" \
  -d "{\"event\": $(jq -c . /tmp/receipts.ndjson | head -1), ...}"
# (production: use the Splunk HEC batch endpoint with proper framing)
```

## Datadog (Logs API)

```bash
DD_API_KEY="..."
DD_SITE="datadoghq.com"  # or datadoghq.eu

dontlie tail --follow --json | while read -r line; do
  curl -sS -X POST "https://http-intake.logs.$DD_SITE/api/v2/logs" \
    -H "DD-API-KEY: $DD_API_KEY" \
    -H "Content-Type: application/json" \
    -d "[$(echo "$line" | jq -c '{message: ., ddsource: \"dontlie\", service: \"ai-audit\", status: \"info\"}')]"
done
```

## Elastic / OpenSearch (Logstash or direct)

```bash
ES_URL="https://elastic.example.com:9200/ai-audit-receipts/_doc"
ES_AUTH="Authorization: ApiKey $ELASTIC_API_KEY"

dontlie tail --follow --json | while read -r line; do
  ID=$(echo "$line" | jq -r .id)
  curl -sS -X POST "$ES_URL?id=$ID" -H "$ES_AUTH" -H "Content-Type: application/json" -d "$line"
done
```

## Sumo Logic (HTTP Source)

```bash
SUMO_URL="https://collectors.sumologic.com/receiver/v1/http/..."

dontlie tail --follow --json | while read -r line; do
  curl -sS -X POST "$SUMO_URL" -H "Content-Type: application/json" -d "$line"
done
```

## S3 (long-term archive — example: the operator's own retention policy)

This section is an **example** of one way an operator might keep an
off-vault copy of the daily bundle. Don't-Lie does not provide
retention storage; you choose the storage, the retention period, and
the access policy. The example below uses 7 years to match a typical
audit-retention requirement, but the period is yours to set.

```bash
# Daily: export the bundle, upload to your own S3 bucket with Object Lock
# for whatever retention period your compliance program requires.
BUCKET="s3://my-audit-vault/dontlie/"
python3 -m dontlie export /tmp/daily.bundle.json --bundle
aws s3 cp /tmp/daily.bundle.json "$BUCKET$(date +%Y-%m-%d).bundle.json" \
  --object-lock-mode COMPLIANCE --object-lock-retain-until-date 2033-07-30T00:00:00Z
```

## Why this is the right shape

- **Open format.** NDJSON, no proprietary wire protocol, no client SDK required.
- **Verifiable at the SIEM.** An auditor with the public key can re-verify any receipt from the SIEM without trusting you, your DB, or your future self.
- **Tamper-evident at the storage layer.** If the SIEM itself is breached, the Ed25519 signatures on every line still hold. The attacker would need the signing key, not just DB write access.
- **Cheap.** Receipts are ~1 KB each. A year of 1,000 receipts/day is ~365 MB.

## Verifying an SIEM-stored receipt

You can verify any receipt from any of these systems, on a clean laptop, without the operator:

```bash
# Pull one receipt line
RECEIPT=$(curl -sS "https://splunk.../services/search/jobs/export?search=search%20index%3Dai_audit%20id%3D1024" | jq -c '.[0]')

# Re-verify
echo "$RECEIPT" | python3 -c "
import json, sys
from dontlie import storage
r = json.loads(sys.stdin.read())
# construct a Receipt and call storage.verify_receipts([r])
"
```

The full verify story lives in the portable bundle. A bundle is a self-contained JSON you can hand to anyone; they verify it offline with `dontlie verify --export <bundle>`.

## What this does NOT do

- It does not push to PagerDuty / Opsgenie. (That's a v0.4 thing. Today: write a Splunk alert that fires on `bad_count > 0`.)
- It does not deduplicate receipts across multiple vaults. (Witness protocol does this — see `docs/WITNESS_PROTOCOL.md`, future work.)
- It does not normalize to OCSF / ECS. The receipt is the source of truth; if you want ECS fields, do it in the SIEM with a search-time field extraction.
