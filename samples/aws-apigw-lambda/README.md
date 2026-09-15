# ConversationRelay on API Gateway + Lambda

A `$connect` Lambda authorizer is the cleanest handshake enforcement point on any of the three clouds. It also comes with two hard limits you need to accept before choosing it.

## Why the authorizer is so well suited to this

API Gateway runs a `REQUEST` authorizer on `$connect` **before the WebSocket exists**, and hands it exactly what we need:

```json
{
  "headers":               { "X-Twilio-Signature": "..." },
  "queryStringParameters": { "t": "eyJhbGciOiJIUzI1NiJ9..." }
}
```

Return a `Deny` and the client gets a bare `401`. No connection, no `$default` invocation, nothing to clean up. Compare that to a plain WebSocket server, where you have to reach for `noServer: true` to get the same behaviour.

## THE TRAP: authorizer result caching

API Gateway caches authorizer decisions, keyed on the identity sources. Leave caching enabled and **a replayed token inside the cache window returns the cached `ALLOW` without invoking your authorizer at all.** Your single-use check silently never runs, and nothing in CloudWatch shows it was skipped.

```yaml
AuthorizerResultTtlInSeconds: 0   # non-negotiable for single-use tokens
```

If you take one thing from this sample, take that line.

## The two hard limits

From [API Gateway's WebSocket quotas](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-execution-service-websocket-limits-table.html), neither adjustable:

| Limit | Value |
|---|---|
| Idle connection timeout | **10 minutes** |
| Max connection duration | **2 hours** |
| Frame size | 32 KB |

If your calls can run past two hours, pick a different platform. The 10-minute idle timeout is survivable with pings, but note you cannot initiate a WebSocket ping from Lambda — you can only send application-level frames via `@connections`, and Twilio won't answer those as keepalives. In practice, ConversationRelay traffic during an active conversation keeps the connection busy; a long hold is the risk.

## The other cost: no memory between frames

Every frame is a separate invocation, so there is no process holding the conversation. Anything that must persist — including the authorizer's verified `CallSid` — goes in DynamoDB. That makes the `setup` cross-check more involved than in a stateful server:

1. `$connect` persists the verified `CallSid` from `requestContext.authorizer`. That context reaches the **first invocation only**.
2. `setup` compares the claimed `CallSid` against the stored value and marks the session verified.
3. Every later frame refuses to act until a session row exists **and** is marked verified — otherwise a peer could skip `setup` entirely and start prompting.

## Deploy

```bash
# Store the secrets first
aws secretsmanager create-secret --name twilio-auth-token \
  --secret-string "$TWILIO_AUTH_TOKEN"
aws secretsmanager create-secret --name relay-token-secret \
  --secret-string "$(openssl rand -base64 32)"

npm install
npm run build
sam deploy --guided
```

Point your Twilio number's voice webhook at the `VoiceWebhookUrl` output.

## Layout

| File | Role |
|---|---|
| `src/authorizer.ts` | `$connect` — signature, token, single-use `jti`, `Allow`/`Deny` |
| `src/voice.ts` | Voice webhook — validate, mint token, return TwiML |
| `src/default.ts` | `$connect` / `$default` / `$disconnect` handlers |
| `src/config.ts` | Validated config, cached per container |
| `template.yaml` | SAM — note `AuthorizerResultTtlInSeconds: 0` |

## A detail on signature reconstruction

The WebSocket API and the voice webhook's HTTP API get **different API Gateway domains**, so each signature is computed against its own URL — hence both `PUBLIC_HOST` and `VOICE_WEBHOOK_HOST`.

For an API Gateway WebSocket API, the stage is part of the path, so the signed string includes it:

```
wss://abc123.execute-api.us-east-1.amazonaws.com/prod?t=<token>
```

API Gateway also hands query parameters over already parsed, so `buildRequestTarget` reassembles them. If you add more query parameters, reconstruct them in the exact order your TwiML wrote them — the HMAC covers the raw string, so ordering matters.

## Not verified here

`sam validate` and `sam deploy` were not run — no AWS credentials or SAM CLI in the authoring environment. The template's YAML parses and the `AuthorizerResultTtlInSeconds: 0` assertion is tested, but validate it in your own account before deploying.
