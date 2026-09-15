# ConversationRelay on Cloud Run

Express + `ws`, with the handshake authenticated **before** the WebSocket exists.

## Why the manual upgrade handler

The important line in `src/server.ts` is this one:

```ts
const wss = new WebSocketServer({ noServer: true, maxPayload: 256 * 1024 });
```

Write `new WebSocketServer({ server })` instead and the library attaches its own upgrade listener and completes the handshake for you. You'd be left with accept-then-close: the 101 is already sent, the session allocated, the socket on your event loop. `noServer: true` plus an explicit `server.on('upgrade')` handler lets you answer a bad request with a bare `401` and never allocate anything.

## Run it locally

```bash
npm install
export PUBLIC_HOST=localhost:8080
export TWILIO_AUTH_TOKEN=your_auth_token
export RELAY_TOKEN_SECRET=$(openssl rand -base64 32)
npm run dev
```

Prove the layers work — no cloud account, no Twilio account:

```bash
node smoke-test.mjs
```

Confirm an anonymous socket is refused:

```bash
npx wscat -c ws://localhost:8080/ws
# expected: error: Unexpected server response: 401
```

## Deploy

```bash
PROJECT_ID=my-project PUBLIC_HOST=relay.example.com ./deploy.sh
```

No Dockerfile: `gcloud run deploy --source .` builds the image with buildpacks.

## Configuration

| Variable | Required | Notes |
|---|---|---|
| `PUBLIC_HOST` | Yes | Host only, no scheme. Must match the `wss://` host in your TwiML. |
| `TWILIO_AUTH_TOKEN` | Yes | From Secret Manager in production. |
| `TWILIO_AUTH_TOKEN_SECONDARY` | No | Set during an auth-token rotation. |
| `RELAY_TOKEN_SECRET` | Yes | base64, ≥32 bytes. `openssl rand -base64 32`. |
| `REDIS_URL` | No | Without it, replay protection is **per-instance only**. |
| `VERIFY_CALL_EXISTS` | No | `true` adds a REST cross-check per connection. |
| `RELAY_TOKEN_TTL_SECONDS` | No | Default 90. |

`PUBLIC_HOST` is configured, never derived from the inbound `Host` header — that header is attacker-controlled and it's part of what Twilio signs.

## Cloud Run specifics that will bite you

**The request timeout is the connection lifetime.** A WebSocket here is a long-running HTTP request, so it cannot outlive the service timeout, which defaults to **five minutes** and caps at sixty. Miss it and calls die mid-sentence past the five-minute mark with nothing in your logs that resembles an error. `deploy.sh` sets `--timeout 3600`.

**Session affinity is best-effort.** Requests can still land on a different instance, which is exactly why single-use enforcement needs Memorystore rather than the in-memory store once you scale past one instance. The server logs a `replay_protection_degraded` warning at boot when `REDIS_URL` is unset — believe it.

**Don't enable end-to-end HTTP/2.** It breaks the upgrade.

**An open WebSocket keeps CPU allocated,** so you're billed for the life of every call.

## Failing closed

If Redis is unreachable, the upgrade handler denies with `503` rather than accepting the socket. Accepting connections because your replay store is down is the wrong way to degrade — it removes a control at exactly the moment someone might be causing the errors.
