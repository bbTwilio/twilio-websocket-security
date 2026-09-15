/**
 * Short-lived, single-use connection tokens for Twilio WebSocket handshakes.
 *
 * Why this exists on top of signature validation: the `X-Twilio-Signature` on an
 * upgrade request is an HMAC over a *static* string (your `wss://` URL). It is
 * therefore identical on every call, and anyone who captures it once -- from a
 * proxy log, an APM trace, a screenshot in a support ticket -- can replay it
 * forever. A token that expires in ninety seconds, is bound to one CallSid, and
 * can only be redeemed once closes that hole.
 *
 * The token is minted in the voice webhook (where Twilio has just told you the
 * CallSid) and travels in the query string of the `wss://` URL you hand back in
 * TwiML. The query string matters: it arrives on the upgrade request, so you can
 * refuse the handshake outright. Anything you send as a TwiML `<Parameter>`
 * instead only reaches you in the `setup` message, which is *after* you have
 * already completed the handshake and allocated a session.
 */

import { SignJWT, jwtVerify, type JWTPayload } from 'jose';
import { randomUUID } from 'node:crypto';
import type { JtiStore } from './jti-store.js';

export const DEFAULT_TTL_SECONDS = 90;
export const DEFAULT_ISSUER = 'urn:twilio-relay:voice-webhook';
export const DEFAULT_AUDIENCE = 'urn:twilio-relay:websocket';

/** Query-string parameter carrying the token. Kept short to limit log bloat. */
export const TOKEN_QUERY_PARAM = 't';

export interface RelayTokenClaims extends JWTPayload {
  /** Call this token is bound to. Cross-checked against the `setup` message. */
  callSid: string;
  /** Account the call belongs to, so a token cannot cross subaccounts. */
  accountSid?: string;
}

export interface MintOptions {
  callSid: string;
  accountSid?: string;
  /**
   * HMAC key, >= 32 bytes of entropy. Independent of your Twilio auth token:
   * this one is yours, so you can rotate it without touching Twilio, and a
   * leaked auth token does not let anyone mint connection tokens.
   */
  secret: Uint8Array;
  ttlSeconds?: number;
  issuer?: string;
  audience?: string;
}

export interface MintResult {
  token: string;
  jti: string;
  expiresAt: Date;
}

/** Signs a connection token. Call this from your voice webhook. */
export async function mintRelayToken({
  callSid,
  accountSid,
  secret,
  ttlSeconds = DEFAULT_TTL_SECONDS,
  issuer = DEFAULT_ISSUER,
  audience = DEFAULT_AUDIENCE,
}: MintOptions): Promise<MintResult> {
  assertSecret(secret);
  if (!callSid) throw new Error('callSid is required to mint a relay token.');

  const now = Math.floor(Date.now() / 1000);
  const exp = now + ttlSeconds;
  const jti = randomUUID();

  const token = await new SignJWT({ callSid, ...(accountSid ? { accountSid } : {}) })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt(now)
    .setNotBefore(now)
    .setExpirationTime(exp)
    .setJti(jti)
    .sign(secret);

  return { token, jti, expiresAt: new Date(exp * 1000) };
}

/**
 * Appends the token as a query parameter. Use the result verbatim in your TwiML.
 *
 * Fine for `<ConversationRelay>`. Do NOT use it for `<Stream>`: Twilio documents
 * that Media Streams does not support query strings on the `url` attribute and
 * will fail the handshake with error 31920. Use {@link buildRelayPathUrl} there.
 */
export function buildRelayUrl(baseWssUrl: string, token: string): string {
  const url = new URL(baseWssUrl);
  url.searchParams.set(TOKEN_QUERY_PARAM, token);
  return url.toString();
}

/**
 * Puts the token in a path segment instead: `wss://host/stream/<token>`.
 *
 * Required for Media Streams, and a reasonable single pattern for both products.
 * The token still arrives on the upgrade request, so you keep the ability to
 * refuse the handshake outright, and it is still covered by the signature
 * because Twilio signs the entire URL.
 */
export function buildRelayPathUrl(baseWssUrl: string, token: string): string {
  const trimmed = baseWssUrl.replace(/\/+$/, '');
  return `${trimmed}/${token}`;
}

export type VerifyFailureReason =
  | 'missing_token'
  | 'invalid_signature'
  | 'expired'
  | 'wrong_issuer'
  | 'wrong_audience'
  | 'missing_call_sid'
  | 'replayed';

export type VerifyResult =
  | { ok: true; claims: RelayTokenClaims }
  /** `reason` is for your logs only. Never return it to the caller. */
  | { ok: false; reason: VerifyFailureReason };

export interface VerifyOptions {
  token: string | undefined | null;
  secret: Uint8Array;
  issuer?: string;
  audience?: string;
  /**
   * Marks the token's `jti` as spent. Omit to accept replays within the TTL
   * window -- acceptable only if you have deliberately decided a 90-second
   * replay window is tolerable.
   */
  jtiStore?: JtiStore;
  /** Small allowance for clock skew between the minting and verifying hosts. */
  clockToleranceSeconds?: number;
}

/**
 * Verifies a connection token. Run this only *after* the Twilio signature
 * check has passed.
 *
 * Ordering is deliberate. The `jti` is burned last, once the token is known to
 * be authentic, so that unauthenticated traffic cannot drive writes into your
 * replay store -- otherwise an attacker floods the store instead of your app.
 */
export async function verifyRelayToken({
  token,
  secret,
  issuer = DEFAULT_ISSUER,
  audience = DEFAULT_AUDIENCE,
  jtiStore,
  clockToleranceSeconds = 5,
}: VerifyOptions): Promise<VerifyResult> {
  assertSecret(secret);
  if (!token) return { ok: false, reason: 'missing_token' };

  let claims: RelayTokenClaims;
  try {
    // jose verifies the HMAC in constant time and enforces exp/nbf/iss/aud.
    const { payload } = await jwtVerify<RelayTokenClaims>(token, secret, {
      issuer,
      audience,
      algorithms: ['HS256'],
      clockTolerance: clockToleranceSeconds,
    });
    claims = payload;
  } catch (err) {
    return { ok: false, reason: classifyJoseError(err) };
  }

  if (typeof claims.callSid !== 'string' || claims.callSid.length === 0) {
    return { ok: false, reason: 'missing_call_sid' };
  }

  if (jtiStore) {
    if (typeof claims.jti !== 'string' || claims.jti.length === 0) {
      return { ok: false, reason: 'replayed' };
    }
    // Keep the record a little past exp so a replay cannot slip through in the
    // gap between expiry and eviction.
    const ttl = Math.max(1, secondsUntil(claims.exp) + clockToleranceSeconds + 60);
    const firstUse = await jtiStore.consume(claims.jti, ttl);
    if (!firstUse) return { ok: false, reason: 'replayed' };
  }

  return { ok: true, claims };
}

/**
 * Confirms the `setup` message describes the call the token was minted for.
 *
 * This is the check that makes CallSid binding mean anything. Without it a
 * token issued for one call could be used to open a socket and then drive a
 * conversation attributed to another.
 */
export function callSidMatches(claims: RelayTokenClaims, setupCallSid: unknown): boolean {
  return typeof setupCallSid === 'string' && setupCallSid.length > 0 && setupCallSid === claims.callSid;
}

function classifyJoseError(err: unknown): VerifyFailureReason {
  const code = (err as { code?: string })?.code;
  switch (code) {
    case 'ERR_JWT_EXPIRED':
      return 'expired';
    case 'ERR_JWT_CLAIM_VALIDATION_FAILED': {
      const claim = (err as { claim?: string }).claim;
      if (claim === 'iss') return 'wrong_issuer';
      if (claim === 'aud') return 'wrong_audience';
      return 'invalid_signature';
    }
    default:
      return 'invalid_signature';
  }
}

function secondsUntil(exp: number | undefined): number {
  if (typeof exp !== 'number') return DEFAULT_TTL_SECONDS;
  return Math.max(0, exp - Math.floor(Date.now() / 1000));
}

function assertSecret(secret: Uint8Array): void {
  if (!(secret instanceof Uint8Array) || secret.byteLength < 32) {
    throw new Error('Relay token secret must be at least 32 bytes of entropy.');
  }
}
