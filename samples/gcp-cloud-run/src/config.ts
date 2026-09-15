/**
 * Configuration, validated once at boot.
 *
 * Everything here is required, and the process refuses to start without it. A
 * server that boots with no auth token and quietly accepts every socket is the
 * exact failure this sample exists to prevent, so there are no defaults for
 * anything security-relevant.
 */

const REQUIRED = ['PUBLIC_HOST', 'TWILIO_AUTH_TOKEN', 'RELAY_TOKEN_SECRET'] as const;

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

/**
 * Host only, no scheme -- e.g. `relay.example.com`.
 *
 * Configured, never derived from the inbound `Host` header. The header is
 * attacker-controlled, and the host is part of the string Twilio signs: letting
 * a caller pick it means letting them pick which signature you will accept.
 */
const publicHost = required('PUBLIC_HOST').replace(/^[a-z]+:\/\//i, '').replace(/\/+$/, '');

/**
 * In production, load secrets from Secret Manager rather than plain env vars.
 * Cloud Run mounts them as env vars or files:
 *   gcloud run deploy --set-secrets=TWILIO_AUTH_TOKEN=twilio-auth-token:latest
 */
export const config = {
  port: Number(process.env.PORT ?? 8080),

  publicHost,
  /** Origin exactly as it appears in the TwiML `url` attribute. */
  wssOrigin: `wss://${publicHost}`,
  httpsOrigin: `https://${publicHost}`,
  wsPath: process.env.WS_PATH ?? '/ws',

  /**
   * Primary first, then secondary. Populate TWILIO_AUTH_TOKEN_SECONDARY for the
   * duration of an auth-token rotation: Twilio signs with whichever token is
   * current, and validating against only one will drop live calls mid-rotation.
   */
  twilioAuthTokens: [
    required('TWILIO_AUTH_TOKEN'),
    process.env.TWILIO_AUTH_TOKEN_SECONDARY,
  ] as const,

  /** >= 32 bytes. Generate with: openssl rand -base64 32 */
  tokenSecret: new Uint8Array(Buffer.from(required('RELAY_TOKEN_SECRET'), 'base64')),

  tokenTtlSeconds: Number(process.env.RELAY_TOKEN_TTL_SECONDS ?? 90),

  /** Optional Redis URL. Without it, replay protection is per-instance only. */
  redisUrl: process.env.REDIS_URL,

  /** Set to 'true' to cross-check each CallSid against the Twilio REST API. */
  verifyCallExists: process.env.VERIFY_CALL_EXISTS === 'true',
  twilioAccountSid: process.env.TWILIO_ACCOUNT_SID,

  /**
   * Cloud Run holds a WebSocket open only as long as the request timeout, which
   * defaults to five minutes. Any call longer than that dies mid-sentence
   * unless you raise it (`--timeout=3600`). Pings alone will not save you.
   */
  keepaliveIntervalMs: Number(process.env.KEEPALIVE_INTERVAL_MS ?? 25_000),
  /** Drop a socket that never sends its `setup` frame. */
  setupTimeoutMs: Number(process.env.SETUP_TIMEOUT_MS ?? 10_000),
  maxConcurrentSockets: Number(process.env.MAX_CONCURRENT_SOCKETS ?? 500),
} as const;

export function assertConfig(): void {
  for (const name of REQUIRED) required(name);
  if (config.tokenSecret.byteLength < 32) {
    throw new Error(
      'RELAY_TOKEN_SECRET must decode to at least 32 bytes. Generate with: openssl rand -base64 32',
    );
  }
}
