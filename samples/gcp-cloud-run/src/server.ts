/**
 * ConversationRelay on Cloud Run, with the handshake authenticated before the
 * socket exists.
 *
 * The shape that matters is at the bottom: a manual `server.on('upgrade')`
 * handler. `new WebSocketServer({ server })` would attach its own listener and
 * complete the handshake for you, leaving you to accept-then-close on failure.
 * `{ noServer: true }` plus an explicit upgrade handler lets you answer a bad
 * request with a bare 401 and never allocate a session at all.
 */

import express from 'express';
import { createServer, type IncomingMessage } from 'node:http';
import type { Socket } from 'node:net';
import type { Duplex } from 'node:stream';
import { WebSocketServer } from 'ws';
import twilio from 'twilio';
import {
  authenticateUpgrade,
  buildRelayUrl,
  mintRelayToken,
  redactToken,
  InMemoryJtiStore,
  RedisJtiStore,
  type JtiStore,
} from '@twilio-samples/relay-auth';

import { assertConfig, config } from './config.js';
import { attachRelayHandlers } from './relay.js';

assertConfig();

const app = express();
app.set('trust proxy', true);
app.disable('x-powered-by');

const server = createServer(app);
const wss = new WebSocketServer({ noServer: true, maxPayload: 256 * 1024 });

const jtiStore: JtiStore = await createJtiStore();
let openSockets = 0;

// ---------------------------------------------------------------------------
// Voice webhook: validate, mint, hand back TwiML
// ---------------------------------------------------------------------------

app.post('/voice', express.urlencoded({ extended: false }), async (req, res) => {
  // Ordinary webhook validation. Note the https:// scheme here -- this really is
  // an HTTP request, so the usual rules apply. The wss:// exception is for the
  // upgrade request only.
  const url = config.httpsOrigin + req.originalUrl;
  const signature = req.header('X-Twilio-Signature') ?? '';
  const signatureOk = config.twilioAuthTokens.some(
    (token) => token && twilio.validateRequest(token, signature, url, req.body ?? {}),
  );

  if (!signatureOk) {
    console.warn(JSON.stringify({ event: 'voice_webhook_rejected', reason: 'invalid_signature' }));
    return res.status(403).type('text/plain').send('Forbidden');
  }

  const callSid = typeof req.body?.CallSid === 'string' ? req.body.CallSid : undefined;
  const accountSid = typeof req.body?.AccountSid === 'string' ? req.body.AccountSid : undefined;
  if (!callSid) return res.status(400).type('text/plain').send('Missing CallSid');

  // The CallSid is known here, so the token can be bound to this one call.
  const { token, jti, expiresAt } = await mintRelayToken({
    callSid,
    accountSid,
    secret: config.tokenSecret,
    ttlSeconds: config.tokenTtlSeconds,
  });

  console.info(
    JSON.stringify({ event: 'relay_token_minted', callSid, jti, expiresAt: expiresAt.toISOString() }),
  );

  const relayUrl = buildRelayUrl(config.wssOrigin + config.wsPath, token);

  const response = new twilio.twiml.VoiceResponse();
  const connect = response.connect();
  connect.conversationRelay({
    url: relayUrl,
    welcomeGreeting: 'Hello! How can I help you today?',
  });

  // The TwiML `url` string is exactly what Twilio will sign on the upgrade.
  res.type('text/xml').send(response.toString());
});

/** Health check. Must be plain HTTP -- Cloud Run probes do not speak WebSocket. */
app.get('/health', (_req, res) => res.status(200).json({ status: 'ok', openSockets }));

// ---------------------------------------------------------------------------
// The upgrade handler: the only enforcement point that exists
// ---------------------------------------------------------------------------

server.on('upgrade', (req: IncomingMessage, rawSocket: Duplex, head: Buffer) => {
  // Node types the upgrade socket as Duplex; at runtime it is always a net.Socket,
  // which is what gives us setTimeout for the handshake deadline.
  const socket = rawSocket as Socket;

  // Guard against a socket that connects and then says nothing, tying up a slot.
  socket.setTimeout(config.setupTimeoutMs);

  void (async () => {
    const requestTarget = req.url ?? '/';
    const safeTarget = redactToken(requestTarget);

    const deny = (reason: string, code = 401, status = '401 Unauthorized') => {
      // One identical response for every failure. Telling the caller whether the
      // signature or the token was wrong hands them a free oracle.
      console.warn(
        JSON.stringify({ event: 'upgrade_rejected', reason, target: safeTarget, code }),
      );
      socket.write(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`);
      socket.destroy();
    };

    if (new URL(requestTarget, config.httpsOrigin).pathname !== config.wsPath) {
      return deny('unknown_path', 404, '404 Not Found');
    }

    if (openSockets >= config.maxConcurrentSockets) {
      return deny('at_capacity', 503, '503 Service Unavailable');
    }

    let result;
    try {
      result = await authenticateUpgrade(
        { requestTarget, headers: req.headers },
        {
          publicOrigin: config.wssOrigin,
          twilioAuthTokens: config.twilioAuthTokens,
          tokenSecret: config.tokenSecret,
          jtiStore,
        },
      );
    } catch (err) {
      // A Redis outage must fail closed. Accepting sockets because the replay
      // store is unreachable is precisely the wrong way to degrade.
      console.error(JSON.stringify({ event: 'upgrade_error', message: String(err) }));
      return deny('guard_error', 503, '503 Service Unavailable');
    }

    if (!result.ok) return deny(result.reason);

    // Only now does a WebSocket come into existence.
    wss.handleUpgrade(req, socket, head, (ws) => {
      socket.setTimeout(0);
      openSockets += 1;
      ws.once('close', () => {
        openSockets -= 1;
      });
      attachRelayHandlers(ws, result.claims);
    });
  })();
});

server.listen(config.port, () => {
  console.info(
    JSON.stringify({
      event: 'listening',
      port: config.port,
      wsPath: config.wsPath,
      replayProtection: config.redisUrl ? 'redis' : 'in-memory (single instance only)',
    }),
  );
});

async function createJtiStore(): Promise<JtiStore> {
  if (!config.redisUrl) {
    // Cloud Run session affinity is best-effort, so two instances each keep
    // their own map and a replay can simply route to the other one. Fine for
    // `npm start` locally; not fine once you scale past one instance.
    console.warn(
      JSON.stringify({
        event: 'replay_protection_degraded',
        detail: 'REDIS_URL unset; single-use tokens are enforced per-instance only.',
      }),
    );
    return new InMemoryJtiStore();
  }

  // Lazy import so the sample runs with no Redis installed.
  const { createClient } = await import('redis');
  const client = createClient({ url: config.redisUrl });
  client.on('error', (err) => console.error(JSON.stringify({ event: 'redis_error', message: String(err) })));
  await client.connect();

  // node-redis v4 returns 'OK' or null for SET..NX, matching RedisLike.
  return new RedisJtiStore({
    set: (key, value, ...args) => {
      const [, ttl] = args as [string, number, string];
      return client.set(key, value, { EX: ttl, NX: true }) as Promise<string | null>;
    },
  });
}
