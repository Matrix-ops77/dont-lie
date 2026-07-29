#!/usr/bin/env bash
# deploy-witness.sh — one-shot deploy script for the public witness notary.
#
# Usage:
#   ./deploy-witness.sh                         # deploy to default app "dontlie-witness"
#   ./deploy-witness.sh --name my-witness       # deploy to a different app name
#   ./deploy-witness.sh --region lhr            # change primary region
#   ./deploy-witness.sh --dry-run               # print the commands without running them
#
# Requires: flyctl (https://fly.io/docs/hands-on/install-flyctl/) and `fly auth login`.
#
# What it does:
#   1. `fly launch --copy-config` to create the app using fly.toml (only the first time)
#   2. `fly volumes create witness_keys` for the persistent signing key
#   3. `fly deploy` to push the image and start the service
#   4. `fly status` to confirm it's running
#   5. prints the public URL + the /pubkey endpoint to verify

set -euo pipefail

APP_NAME="dontlie-witness"
REGION="iad"
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --name) APP_NAME="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --dry-run) DRY_RUN=true; shift ;;
    *) echo "unknown arg: $1"; exit 1 ;;
  esac
done

run() {
  if $DRY_RUN; then
    echo "  $ $*"
  else
    echo "  $ $*"
    eval "$@"
  fi
}

echo "==> Deploying don't-lie witness notary"
echo "  app:    $APP_NAME"
echo "  region: $REGION"
echo ""

echo "==> 1. Launching app (one-time, idempotent)"
run fly launch --copy-config --name "$APP_NAME" --region "$REGION" --no-deploy
echo ""

echo "==> 2. Creating persistent volume for the signing key"
run fly volumes create witness_keys --size 1 --region "$REGION" --yes
echo ""

echo "==> 3. Deploying"
run fly deploy --remote-only
echo ""

echo "==> 4. Status"
run fly status
echo ""

echo "==> 5. Public endpoints"
echo "  https://$APP_NAME.fly.dev/             # service banner"
echo "  https://$APP_NAME.fly.dev/pubkey       # the service's signing public key (PEM)"
echo "  https://$APP_NAME.fly.dev/stats        # request + attestation counts"
echo "  https://$APP_NAME.fly.dev/attestations # the most recent 100 attestations"
echo ""
echo "  POST https://$APP_NAME.fly.dev/attest  # request a co-signature"
echo "    body: {\"receipt_sha256\":\"<hex64>\",\"operator_key_id\":\"<key_id>\",\"parent_sha256\":\"<hex64|null>\",\"nonce\":\"<opaque>\"}"
echo ""

if ! $DRY_RUN; then
  echo "==> 6. Sanity check"
  sleep 5
  echo "  testing GET /pubkey..."
  if curl -fsS --max-time 10 "https://$APP_NAME.fly.dev/pubkey" | head -c 200; then
    echo
    echo "  ✓ service is up and serving /pubkey"
  else
    echo "  ! service not yet responding (may need a minute to start)"
  fi
fi

echo ""
echo "==> DONE"
echo "  Public witness URL: https://$APP_NAME.fly.dev"
echo "  Public key endpoint: https://$APP_NAME.fly.dev/pubkey"
echo ""
echo "  Next: post to /attest from your local Don't-Lie install:"
echo "    curl -X POST https://$APP_NAME.fly.dev/attest \\"
echo "      -H 'Content-Type: application/json' \\"
echo "      -d '{\"receipt_sha256\":\"<your-receipt-sha256>\",\"operator_key_id\":\"<your-key-id>\"}'"
