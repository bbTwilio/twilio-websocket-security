/**
 * Validates the `X-Twilio-Signature` header that Twilio sends on the WebSocket
 * opening handshake for ConversationRelay and Media Streams.
 *
 * The one thing that trips everybody up: Twilio signs the URL *exactly as you
 * wrote it in the TwiML `url` attribute*. For a WebSocket that means the string
 * starts with `wss://`, not `https://`. Webhook validation code that normalises
 * to `https://` will fail here every single time, and the failure mode is
 * miserable to debug -- your handler returns 403, Twilio reports error 64102
 * ("Unable to connect to websocket URL"), and the caller just hears silence.
 */

// `twilio` is CommonJS, so it has no ESM named exports -- `validateRequest`
// lives on the default export only. A bundler's interop may let a named import
// slide in tests and then fail under plain `node`, so import the default.
import twilio from 'twilio';

const { validateRequest } = twilio;

/** Header Twilio sets on the upgrade request. Lower-cased, as Node delivers it. */
export const TWILIO_SIGNATURE_HEADER = 'x-twilio-signature';

export interface SignedUrlParts {
  /**
   * The `wss://` origin exactly as it appears in your TwiML, with no trailing
   * slash -- e.g. `wss://relay.example.com`.
   *
   * Configure this explicitly. Do NOT build it from the inbound `Host` header:
   * that header is attacker-controlled, and letting a caller choose the string
   * you sign means letting them choose which signature you will accept.
   */
  publicOrigin: string;
  /** Path plus query string as received, e.g. `/ws?t=eyJhbGci...`. */
  requestTarget: string;
}

/**
 * Rebuilds the URL Twilio signed.
 *
 * Twilio signs a byte-for-byte copy of the TwiML `url` value, so this must
 * reproduce that string precisely: same scheme, same host, same path, same
 * query string, same escaping. Do not decode or re-encode the query -- a
 * round-trip through `decodeURIComponent` is enough to break the HMAC.
 */
export function buildSignedUrl({ publicOrigin, requestTarget }: SignedUrlParts): string {
  const origin = publicOrigin.replace(/\/+$/, '');

  if (!/^wss:\/\//i.test(origin)) {
    throw new Error(
      `publicOrigin must start with "wss://" (received "${origin}"). ` +
        'Twilio signs the wss:// URL from your TwiML, not an https:// equivalent.',
    );
  }

  return origin + (requestTarget.startsWith('/') ? requestTarget : `/${requestTarget}`);
}

export interface ValidateUpgradeInput {
  /** Value of the `X-Twilio-Signature` header. */
  signature: string | string[] | undefined;
  /** Result of {@link buildSignedUrl}. */
  signedUrl: string;
  /**
   * Auth tokens to try, in order. Pass both the primary and the secondary
   * token while you are rotating: Twilio signs with whichever is current, and
   * a one-token check will reject in-flight calls mid-rotation.
   */
  authTokens: readonly (string | undefined)[];
}

/**
 * Returns true when the signature was produced by a holder of one of the
 * supplied auth tokens.
 *
 * `validateRequest` is Twilio's own helper: HMAC-SHA1 over the URL, keyed with
 * the auth token, compared with `crypto.timingSafeEqual`. Prefer it over a
 * hand-rolled HMAC -- the parameter set Twilio signs can change without notice.
 *
 * The params argument is `{}` on purpose. There is no form body on an upgrade
 * request, and any query string is already baked into `signedUrl`. Passing the
 * query as params too would fold it into the HMAC twice and never match.
 */
export function validateTwilioUpgrade({
  signature,
  signedUrl,
  authTokens,
}: ValidateUpgradeInput): boolean {
  if (typeof signature !== 'string' || signature.length === 0) return false;

  const tokens = authTokens.filter((t): t is string => typeof t === 'string' && t.length > 0);
  if (tokens.length === 0) {
    throw new Error('No Twilio auth token configured; cannot validate signatures.');
  }

  // Evaluate every token rather than short-circuiting, so acceptance does not
  // leak which token matched via response timing.
  let ok = false;
  for (const token of tokens) {
    if (validateRequest(token, signature, signedUrl, {})) ok = true;
  }
  return ok;
}

/** Convenience wrapper: rebuild the URL and validate in one call. */
export function validateUpgradeRequest(
  input: SignedUrlParts & Omit<ValidateUpgradeInput, 'signedUrl'>,
): boolean {
  return validateTwilioUpgrade({
    signature: input.signature,
    signedUrl: buildSignedUrl(input),
    authTokens: input.authTokens,
  });
}
