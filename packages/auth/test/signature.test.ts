import { describe, expect, it } from 'vitest';
import { createHmac } from 'node:crypto';
import {
  buildSignedUrl,
  validateTwilioUpgrade,
  validateUpgradeRequest,
} from '../src/signature.js';

const AUTH_TOKEN = 'a'.repeat(32);
const OTHER_TOKEN = 'b'.repeat(32);
const ORIGIN = 'wss://relay.example.com';

/** Reimplements Twilio's algorithm so the tests assert against the real thing. */
function sign(url: string, token = AUTH_TOKEN): string {
  return createHmac('sha1', token).update(Buffer.from(url, 'utf-8')).digest('base64');
}

describe('buildSignedUrl', () => {
  it('joins origin and request target', () => {
    expect(buildSignedUrl({ publicOrigin: ORIGIN, requestTarget: '/ws' })).toBe(
      'wss://relay.example.com/ws',
    );
  });

  it('preserves the query string byte for byte', () => {
    const target = '/ws?t=eyJhbGciOiJIUzI1NiJ9.abc-_123&x=a%20b';
    expect(buildSignedUrl({ publicOrigin: ORIGIN, requestTarget: target })).toBe(ORIGIN + target);
  });

  it('tolerates a trailing slash on the origin', () => {
    expect(buildSignedUrl({ publicOrigin: `${ORIGIN}/`, requestTarget: '/ws' })).toBe(
      'wss://relay.example.com/ws',
    );
  });

  it('rejects an https:// origin outright', () => {
    expect(() =>
      buildSignedUrl({ publicOrigin: 'https://relay.example.com', requestTarget: '/ws' }),
    ).toThrow(/wss:\/\//);
  });
});

describe('validateTwilioUpgrade', () => {
  it('accepts a signature over the wss:// URL', () => {
    const url = `${ORIGIN}/ws?t=token123`;
    expect(
      validateTwilioUpgrade({ signature: sign(url), signedUrl: url, authTokens: [AUTH_TOKEN] }),
    ).toBe(true);
  });

  /**
   * This is the regression test for the mistake that costs people an afternoon:
   * Twilio signs the wss:// string from the TwiML, so a signature computed over
   * the https:// equivalent does not validate. Keeping it as a test means the
   * scheme handling cannot quietly regress.
   */
  it('does NOT accept a signature computed over the https:// equivalent', () => {
    const wssUrl = `${ORIGIN}/ws`;
    const httpsUrl = 'https://relay.example.com/ws';

    expect(sign(httpsUrl)).not.toBe(sign(wssUrl));
    expect(
      validateTwilioUpgrade({
        signature: sign(httpsUrl),
        signedUrl: wssUrl,
        authTokens: [AUTH_TOKEN],
      }),
    ).toBe(false);
  });

  it('rejects a tampered query string', () => {
    const signed = `${ORIGIN}/ws?t=good`;
    expect(
      validateTwilioUpgrade({
        signature: sign(signed),
        signedUrl: `${ORIGIN}/ws?t=evil`,
        authTokens: [AUTH_TOKEN],
      }),
    ).toBe(false);
  });

  it.each([undefined, '', [] as unknown as string[]])('rejects a missing signature (%p)', (sig) => {
    expect(
      validateTwilioUpgrade({
        signature: sig as string | undefined,
        signedUrl: `${ORIGIN}/ws`,
        authTokens: [AUTH_TOKEN],
      }),
    ).toBe(false);
  });

  it('rejects a signature made with a different auth token', () => {
    const url = `${ORIGIN}/ws`;
    expect(
      validateTwilioUpgrade({
        signature: sign(url, OTHER_TOKEN),
        signedUrl: url,
        authTokens: [AUTH_TOKEN],
      }),
    ).toBe(false);
  });

  it('accepts either token during a rotation window', () => {
    const url = `${ORIGIN}/ws`;
    for (const token of [AUTH_TOKEN, OTHER_TOKEN]) {
      expect(
        validateTwilioUpgrade({
          signature: sign(url, token),
          signedUrl: url,
          authTokens: [AUTH_TOKEN, OTHER_TOKEN],
        }),
      ).toBe(true);
    }
  });

  it('ignores undefined entries in the token list', () => {
    const url = `${ORIGIN}/ws`;
    expect(
      validateTwilioUpgrade({
        signature: sign(url),
        signedUrl: url,
        authTokens: [AUTH_TOKEN, undefined],
      }),
    ).toBe(true);
  });

  it('throws when no auth token is configured at all', () => {
    expect(() =>
      validateTwilioUpgrade({ signature: 'x', signedUrl: `${ORIGIN}/ws`, authTokens: [undefined] }),
    ).toThrow(/auth token/i);
  });
});

describe('validateUpgradeRequest', () => {
  it('rebuilds and validates in one step', () => {
    const target = '/ws?t=abc';
    expect(
      validateUpgradeRequest({
        publicOrigin: ORIGIN,
        requestTarget: target,
        signature: sign(ORIGIN + target),
        authTokens: [AUTH_TOKEN],
      }),
    ).toBe(true);
  });
});
