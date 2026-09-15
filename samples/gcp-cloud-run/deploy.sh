#!/usr/bin/env bash
#
# Deploy the secured ConversationRelay WebSocket to Cloud Run, from source.
# No Dockerfile: Cloud Run builds the image with buildpacks.
#
# Usage:
#   PROJECT_ID=my-project PUBLIC_HOST=relay.example.com ./deploy.sh
#
set -euo pipefail

: "${PROJECT_ID:?Set PROJECT_ID}"
: "${PUBLIC_HOST:?Set PUBLIC_HOST (host only, no scheme)}"

REGION="${REGION:-us-central1}"
SERVICE="${SERVICE:-twilio-relay}"

# --- Secrets ---------------------------------------------------------------
# Held in Secret Manager, not in the service YAML. Create them once:
#
#   printf '%s' "$TWILIO_AUTH_TOKEN" \
#     | gcloud secrets create twilio-auth-token --data-file=- --project "$PROJECT_ID"
#
#   openssl rand -base64 32 \
#     | gcloud secrets create relay-token-secret --data-file=- --project "$PROJECT_ID"
#
# During an auth-token rotation, add twilio-auth-token-secondary and wire it to
# TWILIO_AUTH_TOKEN_SECONDARY so in-flight calls keep validating.

gcloud run deploy "$SERVICE" \
  --source . \
  --project "$PROJECT_ID" \
  --region "$REGION" \
  --allow-unauthenticated \
  --port 8080 \
  --set-env-vars "PUBLIC_HOST=${PUBLIC_HOST}" \
  --set-secrets "TWILIO_AUTH_TOKEN=twilio-auth-token:latest,RELAY_TOKEN_SECRET=relay-token-secret:latest" \
  --session-affinity \
  --min-instances 1 \
  --concurrency 80 \
  --cpu 1 \
  --memory 512Mi \
  --timeout 3600
#
# --timeout 3600
#   THE setting people miss. A Cloud Run WebSocket lives no longer than the
#   request timeout, which defaults to FIVE MINUTES. Leave it alone and every
#   call past the five-minute mark dies mid-sentence, with nothing in your logs
#   that looks like an error. 3600s is the ceiling.
#
# --allow-unauthenticated
#   Correct here, and worth being clear about why: Twilio cannot present Google
#   IAM credentials, and Twilio publishes no fixed egress ranges to allowlist.
#   The service is deliberately open at the network layer and authenticated at
#   the application layer, by the signature and token checks in the upgrade
#   handler. That is the whole design, not a shortcut.
#
# --session-affinity
#   Best-effort only, never a guarantee. Any state that must survive a reconnect
#   belongs in Redis or Firestore, not in an instance's memory.
#
# --min-instances 1
#   Avoids a cold start on the upgrade request; Twilio will not wait long.
#
# Do NOT enable end-to-end HTTP/2 (--use-http2) on this service: it breaks the
# WebSocket upgrade.

echo
echo "Deployed. Point your Twilio number's voice webhook at:"
echo "  https://${PUBLIC_HOST}/voice"
echo
echo "Then confirm an unauthenticated socket is refused before the 101:"
echo "  npx wscat -c wss://${PUBLIC_HOST}/ws    # expect: 401"
