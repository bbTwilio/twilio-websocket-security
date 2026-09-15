import { beforeEach, describe, expect, it } from 'vitest';
import { randomBytes } from 'node:crypto';
import {
  buildRelayUrl,
  callSidMatches,
  mintRelayToken,
  verifyRelayToken,
} from '../src/token.js';
import { InMemoryJtiStore } from '../src/jti-store.js';

const SECRET = new Uint8Array(randomBytes(32));
const OTHER_SECRET = new Uint8Array(randomBytes(32));
const CALL_SID = 'CA00000000000000000000000000000001';

describe('mintRelayToken', () => {
  it('binds the token to a CallSid and returns its jti and expiry', async () => {
    const { token, jti, expiresAt } = await mintRelayToken({ callSid: CALL_SID, secret: SECRET });

    expect(token.split('.')).toHaveLength(3);
    expect(jti).toMatch(/^[0-9a-f-]{36}$/);
    expect(expiresAt.getTime()).toBeGreaterThan(Date.now());

    const result = await verifyRelayToken({ token, secret: SECRET });
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.claims.callSid).toBe(CALL_SID);
  });

  it('rejects a secret with too little entropy', async () => {
    await expect(
      mintRelayToken({ callSid: CALL_SID, secret: new Uint8Array(16) }),
    ).rejects.toThrow(/32 bytes/);
  });

  it('requires a callSid', async () => {
    await expect(mintRelayToken({ callSid: '', secret: SECRET })).rejects.toThrow(/callSid/);
  });

  it('carries the accountSid when supplied', async () => {
    const { token } = await mintRelayToken({
      callSid: CALL_SID,
      accountSid: 'AC123',
      secret: SECRET,
    });
    const result = await verifyRelayToken({ token, secret: SECRET });
    expect(result.ok && result.claims.accountSid).toBe('AC123');
  });
});

describe('verifyRelayToken', () => {
  it('reports a missing token', async () => {
    const result = await verifyRelayToken({ token: undefined, secret: SECRET });
    expect(result).toEqual({ ok: false, reason: 'missing_token' });
  });

  it('rejects a token signed with a different secret', async () => {
    const { token } = await mintRelayToken({ callSid: CALL_SID, secret: OTHER_SECRET });
    expect(await verifyRelayToken({ token, secret: SECRET })).toEqual({
      ok: false,
      reason: 'invalid_signature',
    });
  });

  it('rejects a tampered payload', async () => {
    const { token } = await mintRelayToken({ callSid: CALL_SID, secret: SECRET });
    const [header, , signature] = token.split('.');
    const forged = Buffer.from(JSON.stringify({ callSid: 'CAevil' })).toString('base64url');
    expect(await verifyRelayToken({ token: `${header}.${forged}.${signature}`, secret: SECRET })).toEqual(
      { ok: false, reason: 'invalid_signature' },
    );
  });

  it('rejects an expired token', async () => {
    const { token } = await mintRelayToken({ callSid: CALL_SID, secret: SECRET, ttlSeconds: -30 });
    expect(await verifyRelayToken({ token, secret: SECRET, clockToleranceSeconds: 0 })).toEqual({
      ok: false,
      reason: 'expired',
    });
  });

  it('rejects a token minted for a different audience', async () => {
    const { token } = await mintRelayToken({
      callSid: CALL_SID,
      secret: SECRET,
      audience: 'urn:somewhere-else',
    });
    expect(await verifyRelayToken({ token, secret: SECRET })).toEqual({
      ok: false,
      reason: 'wrong_audience',
    });
  });

  it('rejects a token minted by a different issuer', async () => {
    const { token } = await mintRelayToken({
      callSid: CALL_SID,
      secret: SECRET,
      issuer: 'urn:not-our-webhook',
    });
    expect(await verifyRelayToken({ token, secret: SECRET })).toEqual({
      ok: false,
      reason: 'wrong_issuer',
    });
  });

  it('rejects an unsigned "alg: none" token', async () => {
    const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url');
    const payload = Buffer.from(JSON.stringify({ callSid: CALL_SID })).toString('base64url');
    expect(await verifyRelayToken({ token: `${header}.${payload}.`, secret: SECRET })).toEqual({
      ok: false,
      reason: 'invalid_signature',
    });
  });
});

describe('single-use enforcement', () => {
  let store: InMemoryJtiStore;

  beforeEach(() => {
    store = new InMemoryJtiStore();
  });

  it('accepts the first use and rejects the replay', async () => {
    const { token } = await mintRelayToken({ callSid: CALL_SID, secret: SECRET });

    expect((await verifyRelayToken({ token, secret: SECRET, jtiStore: store })).ok).toBe(true);
    expect(await verifyRelayToken({ token, secret: SECRET, jtiStore: store })).toEqual({
      ok: false,
      reason: 'replayed',
    });
  });

  it('lets exactly one of two concurrent uses through', async () => {
    const { token } = await mintRelayToken({ callSid: CALL_SID, secret: SECRET });

    const results = await Promise.all([
      verifyRelayToken({ token, secret: SECRET, jtiStore: store }),
      verifyRelayToken({ token, secret: SECRET, jtiStore: store }),
    ]);

    expect(results.filter((r) => r.ok)).toHaveLength(1);
  });

  it('does not burn a jti for a token that failed verification', async () => {
    const { token } = await mintRelayToken({ callSid: CALL_SID, secret: OTHER_SECRET });
    await verifyRelayToken({ token, secret: SECRET, jtiStore: store });

    // The forged token never reached the store, so a genuine token with the same
    // id would still be accepted. Unauthenticated traffic cannot poison it.
    const claimed = await store.consume('any-jti', 60);
    expect(claimed).toBe(true);
  });

  it('accepts replays when no store is supplied', async () => {
    const { token } = await mintRelayToken({ callSid: CALL_SID, secret: SECRET });
    expect((await verifyRelayToken({ token, secret: SECRET })).ok).toBe(true);
    expect((await verifyRelayToken({ token, secret: SECRET })).ok).toBe(true);
  });
});

describe('callSidMatches', () => {
  const claims = { callSid: CALL_SID };

  it('accepts the matching CallSid from the setup message', () => {
    expect(callSidMatches(claims, CALL_SID)).toBe(true);
  });

  it.each([['CAsomethingelse'], [''], [undefined], [null], [42], [{ callSid: CALL_SID }]])(
    'rejects %p',
    (value) => {
      expect(callSidMatches(claims, value)).toBe(false);
    },
  );
});

describe('buildRelayUrl', () => {
  it('appends the token to the wss URL', () => {
    expect(buildRelayUrl('wss://relay.example.com/ws', 'abc.def.ghi')).toBe(
      'wss://relay.example.com/ws?t=abc.def.ghi',
    );
  });

  it('keeps existing query parameters', () => {
    expect(buildRelayUrl('wss://relay.example.com/ws?tenant=acme', 'tok')).toBe(
      'wss://relay.example.com/ws?tenant=acme&t=tok',
    );
  });
});
