/**
 * Configuration for the Lambda handlers.
 *
 * Loaded lazily and cached per container so a cold start pays for it once.
 * In production, resolve TWILIO_AUTH_TOKEN and RELAY_TOKEN_SECRET from Secrets
 * Manager (or SSM SecureString) rather than plaintext Lambda environment
 * variables -- env vars are visible to anyone with `lambda:GetFunction`.
 */

export interface AppConfig {
  wssOrigin: string;
  wsPath: string;
  /**
   * Origin of the HTTP API hosting the voice webhook. Separate from wssOrigin:
   * the WebSocket API and the HTTP API get different API Gateway domains, and
   * each signature must be computed against its own URL.
   */
  voiceWebhookOrigin: string;
  twilioAuthTokens: readonly (string | undefined)[];
  tokenSecret: Uint8Array;
  tokenTtlSeconds: number;
  jtiTableName: string;
  sessionTableName: string;
  twilioAccountSid: string | undefined;
}

let cached: AppConfig | undefined;

function required(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required environment variable: ${name}`);
  return value;
}

export function loadConfig(): AppConfig {
  if (cached) return cached;

  // Hosts only, no scheme. Configured, never taken from the Host header --
  // that header is attacker-controlled and it is part of what Twilio signs.
  const host = required('PUBLIC_HOST').replace(/^[a-z]+:\/\//i, '').replace(/\/+$/, '');
  const webhookHost = (process.env.VOICE_WEBHOOK_HOST ?? host)
    .replace(/^[a-z]+:\/\//i, '')
    .replace(/\/+$/, '');
  const secret = new Uint8Array(Buffer.from(required('RELAY_TOKEN_SECRET'), 'base64'));

  if (secret.byteLength < 32) {
    throw new Error('RELAY_TOKEN_SECRET must decode to at least 32 bytes.');
  }

  cached = {
    /**
     * For an API Gateway WebSocket API the stage is part of the path, so this
     * whole string has to match the TwiML byte for byte -- including the stage:
     *   wss://abc123.execute-api.us-east-1.amazonaws.com/prod
     */
    wssOrigin: `wss://${host}`,
    /** Path portion of the WebSocket URL -- the stage name, e.g. `/prod`. */
    wsPath: process.env.WS_PATH ?? '',
    voiceWebhookOrigin: `https://${webhookHost}`,
    twilioAuthTokens: [required('TWILIO_AUTH_TOKEN'), process.env.TWILIO_AUTH_TOKEN_SECONDARY],
    tokenSecret: secret,
    tokenTtlSeconds: Number(process.env.RELAY_TOKEN_TTL_SECONDS ?? 90),
    jtiTableName: required('JTI_TABLE_NAME'),
    sessionTableName: required('SESSION_TABLE_NAME'),
    twilioAccountSid: process.env.TWILIO_ACCOUNT_SID,
  };

  return cached;
}
