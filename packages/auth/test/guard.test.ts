import { describe, expect, it } from 'vitest';
import { createHmac, randomBytes } from 'node:crypto';
import { authenticateUpgrade, redactToken, type GuardConfig } from '../src/guard.js';
import { InMemoryJtiStore } from '../src/jti-store.js';
import { buildRelayPathUrl, mintRelayToken } from '../src/token.js';

const AUTH_TOKEN = 'a'.repeat(32);
const ORIGIN = 'wss://relay.example.com';
const SECRET = new Uint8Array(randomBytes(32));
const CALL_SID = 'CA00000000000000000000000000000001';

function sign(url: string, token = AUTH_TOKEN): string {
  return createHmac('sha1', token).update(Buffer.from(url, 'utf-8')).digest('base64');
}

function config(overrides: Partial<GuardConfig> = {}): GuardConfig {
  return {
    publicOrigin: ORIGIN,
    twilioAuthTokens: [AUTH_TOKEN],
    tokenSecret: SECRET,
    ...overrides,
  };
}

async function upgradeRequest(opts: { token?: string; signWith?: string } = {}) {
  const token = opts.token ?? (await mintRelayToken({ callSid: CALL_SID, secret: SECRET })).token;
  const requestTarget = `/ws?t=${token}`;
  return {
    requestTarget,
    headers: { 'x-twilio-signature': sign(ORIGIN + requestTarget, opts.signWith) },
  };
}

describe('authenticateUpgrade', () => {
  it('accepts a request with a valid signature and token', async () => {
    const result = await authenticateUpgrade(await upgradeRequest(), config());
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.claims.callSid).toBe(CALL_SID);
  });

  it('rejects when the signature is absent', async () => {
    const req = await upgradeRequest();
    const result = await authenticateUpgrade({ ...req, headers: {} }, config());
    expect(result).toEqual({ ok: false, reason: 'invalid_signature' });
  });

  it('rejects when the signature is from the wrong auth token', async () => {
    const req = await upgradeRequest({ signWith: 'z'.repeat(32) });
    expect(await authenticateUpgrade(req, config())).toEqual({
      ok: false,
      reason: 'invalid_signature',
    });
  });

  /**
   * A valid signature on its own is not enough. This is the scenario signature
   * validation cannot cover by itself: the signature over a static URL is
   * replayable, so a captured one plus no token must still be refused.
   */
  it('rejects a validly signed request that carries no token', async () => {
    const requestTarget = '/ws';
    const result = await authenticateUpgrade(
      { requestTarget, headers: { 'x-twilio-signature': sign(ORIGIN + requestTarget) } },
      config(),
    );
    expect(result).toEqual({ ok: false, reason: 'missing_token' });
  });

  it('checks the signature before the token', async () => {
    // Bad signature AND a bad token: the reported reason must be the signature,
    // proving the cheap local check runs first and short-circuits.
    const result = await authenticateUpgrade(
      { requestTarget: '/ws?t=not-a-jwt', headers: { 'x-twilio-signature': 'wrong' } },
      config(),
    );
    expect(result).toEqual({ ok: false, reason: 'invalid_signature' });
  });

  it('rejects a replayed handshake when a store is configured', async () => {
    const cfg = config({ jtiStore: new InMemoryJtiStore() });
    const req = await upgradeRequest();

    expect((await authenticateUpgrade(req, cfg)).ok).toBe(true);
    expect(await authenticateUpgrade(req, cfg)).toEqual({ ok: false, reason: 'replayed' });
  });

  it('reads the token from pre-parsed query params when provided', async () => {
    const { token } = await mintRelayToken({ callSid: CALL_SID, secret: SECRET });
    const requestTarget = `/ws?t=${token}`;
    const result = await authenticateUpgrade(
      {
        requestTarget,
        headers: { 'x-twilio-signature': sign(ORIGIN + requestTarget) },
        query: { t: token },
      },
      config(),
    );
    expect(result.ok).toBe(true);
  });

  it('rejects a token bound to a call but signed for another origin', async () => {
    const req = await upgradeRequest();
    // Same request, verifier configured for a different host: the HMAC covers
    // the origin, so this must fail.
    expect(await authenticateUpgrade(req, config({ publicOrigin: 'wss://other.example.com' }))).toEqual(
      { ok: false, reason: 'invalid_signature' },
    );
  });
});

/**
 * Media Streams cannot use a query string at all -- Twilio documents that
 * `<Stream>` does not support one and fails the handshake with error 31920. The
 * token therefore has to ride in a path segment, and it must still be refused
 * before the 101.
 */
describe('path-based tokens (Media Streams)', () => {
  const pathConfig = (overrides: Partial<GuardConfig> = {}): GuardConfig =>
    config({ tokenLocation: 'path', pathPrefix: '/stream', ...overrides });

  async function pathRequest(token?: string) {
    const t = token ?? (await mintRelayToken({ callSid: CALL_SID, secret: SECRET })).token;
    const requestTarget = `/stream/${t}`;
    return {
      requestTarget,
      headers: { 'x-twilio-signature': sign(ORIGIN + requestTarget) },
    };
  }

  it('accepts a token in the path segment', async () => {
    const result = await authenticateUpgrade(await pathRequest(), pathConfig());
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.claims.callSid).toBe(CALL_SID);
  });

  it('rejects a request with no token segment', async () => {
    const requestTarget = '/stream';
    const result = await authenticateUpgrade(
      { requestTarget, headers: { 'x-twilio-signature': sign(ORIGIN + requestTarget) } },
      pathConfig(),
    );
    expect(result).toEqual({ ok: false, reason: 'missing_token' });
  });

  it('rejects a nested path rather than treating the first segment as the token', async () => {
    const { token } = await mintRelayToken({ callSid: CALL_SID, secret: SECRET });
    const requestTarget = `/stream/${token}/extra`;
    const result = await authenticateUpgrade(
      { requestTarget, headers: { 'x-twilio-signature': sign(ORIGIN + requestTarget) } },
      pathConfig(),
    );
    expect(result).toEqual({ ok: false, reason: 'missing_token' });
  });

  it('ignores a query string in path mode', async () => {
    const { token } = await mintRelayToken({ callSid: CALL_SID, secret: SECRET });
    const requestTarget = `/stream/${token}?ignored=1`;
    const result = await authenticateUpgrade(
      { requestTarget, headers: { 'x-twilio-signature': sign(ORIGIN + requestTarget) } },
      pathConfig(),
    );
    expect(result.ok).toBe(true);
  });

  it('does not accept a query-string token when configured for path mode', async () => {
    const { token } = await mintRelayToken({ callSid: CALL_SID, secret: SECRET });
    const requestTarget = `/stream?t=${token}`;
    const result = await authenticateUpgrade(
      { requestTarget, headers: { 'x-twilio-signature': sign(ORIGIN + requestTarget) } },
      pathConfig(),
    );
    expect(result).toEqual({ ok: false, reason: 'missing_token' });
  });

  it('enforces single use in path mode too', async () => {
    const cfg = pathConfig({ jtiStore: new InMemoryJtiStore() });
    const req = await pathRequest();
    expect((await authenticateUpgrade(req, cfg)).ok).toBe(true);
    expect(await authenticateUpgrade(req, cfg)).toEqual({ ok: false, reason: 'replayed' });
  });

  it('throws if pathPrefix was not configured', async () => {
    await expect(
      authenticateUpgrade(await pathRequest(), config({ tokenLocation: 'path' })),
    ).rejects.toThrow(/pathPrefix/);
  });
});

describe('buildRelayPathUrl', () => {
  it('appends the token as a path segment', () => {
    expect(buildRelayPathUrl('wss://relay.example.com/stream', 'abc.def.ghi')).toBe(
      'wss://relay.example.com/stream/abc.def.ghi',
    );
  });

  it('does not double up a trailing slash', () => {
    expect(buildRelayPathUrl('wss://relay.example.com/stream/', 'tok')).toBe(
      'wss://relay.example.com/stream/tok',
    );
  });
});

describe('redactToken', () => {
  it('redacts the token in a full URL', () => {
    expect(redactToken('wss://relay.example.com/ws?t=eyJhbGciOiJIUzI1NiJ9.abc.def')).toBe(
      'wss://relay.example.com/ws?t=[REDACTED]',
    );
  });

  it('redacts the token but keeps other parameters', () => {
    expect(redactToken('/ws?tenant=acme&t=secret.jwt.value&x=1')).toBe(
      '/ws?tenant=acme&t=[REDACTED]&x=1',
    );
  });

  it('leaves a target with no token untouched', () => {
    expect(redactToken('/ws')).toBe('/ws');
  });

  it('does not maul a similarly named parameter', () => {
    expect(redactToken('/ws?tenant=acme')).toBe('/ws?tenant=acme');
  });

  it('redacts a path-segment token when given the prefix', () => {
    expect(redactToken('/stream/eyJhbGciOiJIUzI1NiJ9.abc.def', '/stream')).toBe(
      '/stream/[REDACTED]',
    );
  });

  it('redacts a path-segment token in a full URL', () => {
    expect(redactToken('wss://relay.example.com/stream/a.b.c', '/stream')).toBe(
      'wss://relay.example.com/stream/[REDACTED]',
    );
  });
});
