# Securing WebSocket Connections on Twilio

Reference implementation for authenticating [ConversationRelay](https://www.twilio.com/docs/voice/twiml/connect/conversationrelay) and [Media Streams](https://www.twilio.com/docs/voice/media-streams) WebSocket connections, with the edge and WAF configuration that makes it work in production.

Companion code for the blog post: **[blog/securing-websocket-connections-on-twilio.md](./blog/securing-websocket-connections-on-twilio.md)**

## The problem

The `wss://` URL you write into your TwiML is on the public internet. Twilio connects to it from no fixed IP range, so there is nothing to allowlist, and it does not authenticate itself unless you make it. An unauthenticated relay endpoint is an anonymous channel into your LLM — your inference bill, your rate limits, and whatever context your agent can reach.

**And a WAF only ever inspects the HTTP upgrade request — never a WebSocket frame.** The handshake is your one and only enforcement point.

## The four layers

| Layer | Control | Stops |
|---|---|---|
| 1 | `wss://` with a CA-issued certificate | Eavesdropping, tampering |
| 2 | `X-Twilio-Signature` on the upgrade request | Anyone who isn't Twilio |
| 3 | Short-lived, single-use token bound to `CallSid` | Replay of a captured signature |
| 4 | WAF, load balancer, timeouts | Floods — and your own defaults breaking layers 1–3 |

## Layout

```
packages/auth/              Shared handshake authentication (the substance)
  src/signature.ts            X-Twilio-Signature, incl. the wss:// scheme gotcha
  src/token.ts                Mint/verify short-lived CallSid-bound JWTs
  src/jti-store.ts            Atomic single-use enforcement (memory/Redis/DynamoDB)
  src/guard.ts                Composed check, in the order it must happen
  src/call-check.ts           Optional REST cross-check that the call is live
  test/                       62 tests, incl. a regression test for the scheme gotcha

samples/gcp-cloud-run/      Express + ws, manual server.on('upgrade') handler
  smoke-test.mjs              End-to-end negative-path test, no cloud account needed
samples/aws-apigw-lambda/   API Gateway WebSocket + $connect Lambda authorizer

infra/aws/                  WAF rate limiting, managed-rule exclusions, ALB timeouts
infra/gcp/                  Cloud Armor, Cloud Run and backend service timeouts
infra/azure/                Front Door + WAF, and the caching trap

blog/                       The post and its diagrams (Mermaid source + SVG + PNG)
```

## Quick start

```bash
# 1. Shared auth package — run the tests first
cd packages/auth && npm install && npm test

# 2. Prove the security layers end to end, with no cloud account
cd ../../samples/gcp-cloud-run && npm install && node smoke-test.mjs
```

Expected:

```
--- Layer 2: signature validation ---
PASS  anonymous upgrade is refused
PASS  upgrade with a bogus signature is refused
PASS  signature computed over https:// is refused (the scheme gotcha)

--- Voice webhook ---
PASS  unsigned voice webhook is refused  (got 403)
PASS  signed voice webhook returns TwiML  (got 200)
PASS  TwiML contains a ConversationRelay url
PASS  relay url carries a token

--- Layer 3: token, binding, replay ---
PASS  correctly signed + tokened upgrade succeeds  (got 101)
PASS  replaying the same token is refused  (got 401)

--- setup frame: CallSid binding ---
PASS  mismatched CallSid in setup closes the socket  (close code 1008)

10/10 checks passed
```

## Deploying

**GCP Cloud Run** — no Dockerfile needed:

```bash
cd samples/gcp-cloud-run
PROJECT_ID=my-project PUBLIC_HOST=relay.example.com ./deploy.sh
```

**AWS API Gateway + Lambda:**

```bash
cd samples/aws-apigw-lambda
npm run build && sam deploy --guided
```

Then point your Twilio number's voice webhook at the deployed `/voice` URL and place a call.

## The five things that most often go wrong

1. **Signing the `https://` URL instead of the `wss://` one.** Twilio signs the TwiML `url` string verbatim. Webhook validation code copied over will reject every upgrade. Symptom: Twilio [error 64102](https://www.twilio.com/docs/api/errors/64102), silent caller.
2. **API Gateway authorizer caching.** With caching on, a replayed token returns a cached `ALLOW` *without invoking your authorizer*, so single-use silently never runs. Set `AuthorizerResultTtlInSeconds: 0`.
3. **Azure Front Door caching on the WebSocket route.** Front Door stops forwarding the `Upgrade` header and the handshake fails outright. Not slower — broken.
4. **Cloud Run's 5-minute default request timeout.** Calls die mid-sentence past the five-minute mark with nothing that looks like an error. Set `--timeout 3600`.
5. **Idle timeouts versus a caller on hold.** A quiet call is indistinguishable from a dead one. Raise the timeout *and* send pings every 20–30s.

## Verification status

| Check | Status |
|---|---|
| `packages/auth` unit tests | 62 passing |
| End-to-end smoke test (real 101 upgrade, replay, `CallSid` mismatch) | 10/10 passing |
| TypeScript `--noEmit`, all three packages | Clean |
| `npm audit`, all three packages | 0 vulnerabilities |
| Terraform HCL parse | 5/5 files parse |
| SAM template YAML parse + `AuthorizerResultTtlInSeconds: 0` asserted | Passing |
| Mermaid diagrams render | 3/3 |

Not verified — no cloud credentials or CLI available in this environment:

- `terraform validate` / `plan` / `apply` (HCL is parse-checked only, not schema-validated against providers)
- `sam validate` / `sam deploy`
- A live Twilio call end to end

Treat the `infra/` Terraform and `template.yaml` as reviewed reference material to `terraform validate` and `sam validate` in your own account before applying.

## License

MIT — see [LICENSE](./LICENSE).
