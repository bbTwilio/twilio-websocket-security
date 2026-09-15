/**
 * Optional fourth layer: ask Twilio whether the call actually exists.
 *
 * Signature and token both prove things about the *handshake*. Neither proves
 * that the `setup` frame you received afterwards is telling the truth about
 * which call it belongs to. Fetching the Call resource closes that gap: the
 * CallSid has to exist, be live, and belong to your account.
 *
 * It costs a REST round trip on every connection, so it earns its place in
 * regulated or high-value flows and is usually overkill elsewhere. Decide
 * deliberately rather than switching it on by reflex.
 */

export interface CallCheckClient {
  calls(sid: string): {
    fetch(): Promise<{ status: string; accountSid: string }>;
  };
}

export type CallCheckOutcome =
  | { ok: true }
  | { ok: false; reason: 'not_found' | 'not_live' | 'wrong_account' | 'lookup_failed' };

/** Call statuses that mean a media path can legitimately be open. */
const LIVE_STATUSES = new Set(['queued', 'ringing', 'in-progress']);

export interface CallCheckOptions {
  client: CallCheckClient;
  callSid: string;
  /** Reject calls belonging to any other account or subaccount. */
  expectedAccountSid?: string;
  /**
   * What to do when Twilio itself is unreachable or rate-limiting.
   *
   * `'closed'` is the safer default but means a Twilio API blip drops live
   * calls. `'open'` keeps calls up at the cost of losing this check exactly
   * when an attacker might be causing the errors. Pick per workload; do not
   * leave it to chance.
   */
  onLookupError?: 'closed' | 'open';
}

export async function verifyCallIsLive({
  client,
  callSid,
  expectedAccountSid,
  onLookupError = 'closed',
}: CallCheckOptions): Promise<CallCheckOutcome> {
  try {
    const call = await client.calls(callSid).fetch();

    if (expectedAccountSid && call.accountSid !== expectedAccountSid) {
      return { ok: false, reason: 'wrong_account' };
    }
    if (!LIVE_STATUSES.has(call.status)) {
      return { ok: false, reason: 'not_live' };
    }
    return { ok: true };
  } catch (err) {
    const status = (err as { status?: number })?.status;
    if (status === 404) return { ok: false, reason: 'not_found' };
    // 429 and 5xx land here. Respect Twilio's rate limits: do not retry inline
    // on the connection path, and cache nothing but negatives.
    return onLookupError === 'open' ? { ok: true } : { ok: false, reason: 'lookup_failed' };
  }
}
