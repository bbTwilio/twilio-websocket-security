/**
 * The whole handshake check, in the order it has to happen.
 *
 * Order is not cosmetic:
 *
 *   1. Signature first. It is a cheap local HMAC with no I/O, and it is the
 *      check that says "Twilio sent this". Everything after it assumes that.
 *   2. Token second. Proves *this* handshake belongs to a call your own webhook
 *      set up moments ago, which the signature alone cannot tell you.
 *   3. `jti` burn last, inside step 2. Only authenticated requests get to write
 *      to the replay store, so nobody can flood it with garbage.
 *
 * Whatever fails, the caller gets an identical bare `401`. The reason code comes
 * back for your logs, never for the client: telling an attacker whether their
 * signature or their token was the problem hands them a free oracle.
 */

import {
  TWILIO_SIGNATURE_HEADER,
  buildSignedUrl,
  validateTwilioUpgrade,
} from './signature.js';
import {
  TOKEN_QUERY_PARAM,
  verifyRelayToken,
  type RelayTokenClaims,
  type VerifyFailureReason,
} from './token.js';
import type { JtiStore } from './jti-store.js';

export type GuardFailureReason = 'invalid_signature' | VerifyFailureReason;

export type GuardResult =
  | { ok: true; claims: RelayTokenClaims }
  | { ok: false; reason: GuardFailureReason };

/**
 * Where the connection token travels.
 *
 * `'query'` -- `wss://host/ws?t=JWT`. The natural choice for ConversationRelay.
 *
 * `'path'` -- `wss://host/ws/JWT`. Required for **Media Streams**, because
 * Twilio documents that `<Stream>` does not support query strings at all and
 * will fail the handshake with error 31920 if you use one. A path segment keeps
 * the token on the upgrade request, so you still get to refuse the handshake
 * rather than accept-then-close. It is also a perfectly good option for
 * ConversationRelay if you would rather use one pattern for both products.
 *
 * Either way the token is covered by `X-Twilio-Signature`, because Twilio signs
 * the whole URL.
 */
export type TokenLocation = 'query' | 'path';

export interface GuardConfig {
  /** `wss://` origin exactly as written in your TwiML. */
  publicOrigin: string;
  /** Primary first, then the secondary while rotating. */
  twilioAuthTokens: readonly (string | undefined)[];
  /** HMAC key for connection tokens, >= 32 bytes. */
  tokenSecret: Uint8Array;
  jtiStore?: JtiStore;
  issuer?: string;
  audience?: string;
  clockToleranceSeconds?: number;
  /** Defaults to `'query'`. Use `'path'` for Media Streams. */
  tokenLocation?: TokenLocation;
  /**
   * Required when `tokenLocation` is `'path'`: the path prefix that precedes the
   * token segment, e.g. `/stream` for `wss://host/stream/<token>`.
   */
  pathPrefix?: string;
}

export interface UpgradeRequestLike {
  /** Path plus query string as received, e.g. `/ws?t=...`. */
  requestTarget: string;
  /** Inbound headers, lower-cased keys. */
  headers: Record<string, string | string[] | undefined>;
  /** Parsed query parameters. Supply when your platform has already parsed them. */
  query?: Record<string, string | string[] | undefined>;
}

export async function authenticateUpgrade(
  req: UpgradeRequestLike,
  config: GuardConfig,
): Promise<GuardResult> {
  const signedUrl = buildSignedUrl({
    publicOrigin: config.publicOrigin,
    requestTarget: req.requestTarget,
  });

  const signatureOk = validateTwilioUpgrade({
    signature: req.headers[TWILIO_SIGNATURE_HEADER],
    signedUrl,
    authTokens: config.twilioAuthTokens,
  });
  if (!signatureOk) return { ok: false, reason: 'invalid_signature' };

  const result = await verifyRelayToken({
    token: extractToken(req, config),
    secret: config.tokenSecret,
    issuer: config.issuer,
    audience: config.audience,
    jtiStore: config.jtiStore,
    clockToleranceSeconds: config.clockToleranceSeconds,
  });

  return result.ok ? { ok: true, claims: result.claims } : { ok: false, reason: result.reason };
}

function extractToken(req: UpgradeRequestLike, config: GuardConfig): string | undefined {
  if ((config.tokenLocation ?? 'query') === 'path') {
    return extractTokenFromPath(req.requestTarget, config.pathPrefix);
  }

  const fromQuery = req.query?.[TOKEN_QUERY_PARAM];
  if (typeof fromQuery === 'string') return fromQuery;
  if (Array.isArray(fromQuery)) return fromQuery[0];

  const qIndex = req.requestTarget.indexOf('?');
  if (qIndex === -1) return undefined;
  return new URLSearchParams(req.requestTarget.slice(qIndex + 1)).get(TOKEN_QUERY_PARAM) ?? undefined;
}

/** Pulls the token from `<pathPrefix>/<token>`, ignoring any query string. */
function extractTokenFromPath(requestTarget: string, pathPrefix?: string): string | undefined {
  if (!pathPrefix) {
    throw new Error("pathPrefix is required when tokenLocation is 'path'.");
  }

  const qIndex = requestTarget.indexOf('?');
  const path = qIndex === -1 ? requestTarget : requestTarget.slice(0, qIndex);

  const prefix = pathPrefix.endsWith('/') ? pathPrefix : `${pathPrefix}/`;
  if (!path.startsWith(prefix)) return undefined;

  // Exactly one segment after the prefix, so a nested path cannot smuggle
  // something past the check.
  const segment = path.slice(prefix.length);
  if (segment.length === 0 || segment.includes('/')) return undefined;
  return segment;
}

/**
 * Strips the token from a URL or path before it reaches a log line.
 *
 * Query strings are recorded in full by ALB access logs, CloudFront logs, Cloud
 * Logging and Front Door diagnostics. A token in a log file that outlives its
 * ninety-second TTL is only a mild problem; the same token in a log file your
 * whole org can read is a worse one. Redact at the edge as well -- this helper
 * only covers logging you control.
 */
export function redactToken(target: string, pathPrefix?: string): string {
  let out = target.replace(
    new RegExp(`([?&]${TOKEN_QUERY_PARAM}=)[^&\\s]+`, 'gi'),
    `$1[REDACTED]`,
  );

  if (pathPrefix) {
    const prefix = pathPrefix.endsWith('/') ? pathPrefix : `${pathPrefix}/`;
    out = out.replace(
      new RegExp(`(${escapeRegExp(prefix)})[^/?\\s]+`),
      `$1[REDACTED]`,
    );
  }

  return out;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
