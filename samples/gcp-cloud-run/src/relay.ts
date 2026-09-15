/**
 * ConversationRelay message handling, once the handshake has been authenticated.
 *
 * Two things here are security-relevant rather than functional:
 *
 *   - The `setup` frame's `callSid` is compared against the token's claim. This
 *     is what makes CallSid binding worth anything: without it, a token minted
 *     for one call could open a socket and then drive a conversation attributed
 *     to another.
 *   - `voicePrompt` is treated as untrusted input, because it is: an attacker who
 *     reaches your bot can say anything into it, and a WAF cannot see a single
 *     frame of it.
 */

import type { WebSocket } from 'ws';
import twilio from 'twilio';
import { callSidMatches, verifyCallIsLive, type RelayTokenClaims } from '@twilio-samples/relay-auth';

import { config } from './config.js';

/** WebSocket close codes. 1008 = policy violation. */
const CLOSE_POLICY_VIOLATION = 1008;

const twilioClient =
  config.verifyCallExists && config.twilioAccountSid
    ? twilio(config.twilioAccountSid, config.twilioAuthTokens[0])
    : undefined;

export function attachRelayHandlers(ws: WebSocket, claims: RelayTokenClaims): void {
  const { callSid } = claims;
  let setupSeen = false;

  // Nothing has been verified about the *session* yet, only the handshake. Give
  // the peer a bounded window to identify itself with a `setup` frame.
  const setupTimer = setTimeout(() => {
    if (!setupSeen) {
      log('setup_timeout', { callSid });
      ws.close(CLOSE_POLICY_VIOLATION, 'setup timeout');
    }
  }, config.setupTimeoutMs);

  /**
   * Application-level keepalive. Edge proxies close idle connections -- Front
   * Door at five minutes, API Gateway at ten -- and a caller sitting on hold
   * sends nothing at all, so a quiet call looks identical to a dead one.
   */
  let alive = true;
  const heartbeat = setInterval(() => {
    if (!alive) {
      log('heartbeat_timeout', { callSid });
      return ws.terminate();
    }
    alive = false;
    ws.ping();
  }, config.keepaliveIntervalMs);

  ws.on('pong', () => {
    alive = true;
  });

  ws.on('message', (data) => {
    let event: Record<string, unknown>;
    try {
      event = JSON.parse(data.toString());
    } catch {
      log('malformed_frame', { callSid });
      return ws.close(CLOSE_POLICY_VIOLATION, 'malformed frame');
    }

    switch (event.type) {
      case 'setup':
        return void handleSetup(event);
      case 'prompt':
        return handlePrompt(event);
      case 'interrupt':
        return log('interrupt', { callSid });
      case 'dtmf':
        return log('dtmf', { callSid });
      case 'error':
        return log('relay_error', { callSid, description: event.description });
      default:
        return log('unknown_frame', { callSid, frameType: event.type });
    }
  });

  ws.on('close', (code) => {
    clearTimeout(setupTimer);
    clearInterval(heartbeat);
    log('socket_closed', { callSid, code });
  });

  ws.on('error', (err) => log('socket_error', { callSid, message: String(err) }));

  async function handleSetup(event: Record<string, unknown>): Promise<void> {
    setupSeen = true;
    clearTimeout(setupTimer);

    // The check that gives CallSid binding its teeth.
    if (!callSidMatches(claims, event.callSid)) {
      log('call_sid_mismatch', { callSid, claimed: event.callSid });
      return ws.close(CLOSE_POLICY_VIOLATION, 'call mismatch');
    }

    // Optional extra layer: confirm with Twilio that the call is real and live.
    if (twilioClient) {
      const outcome = await verifyCallIsLive({
        client: twilioClient,
        callSid,
        expectedAccountSid: config.twilioAccountSid,
      });
      if (!outcome.ok) {
        log('call_check_failed', { callSid, reason: outcome.reason });
        return ws.close(CLOSE_POLICY_VIOLATION, 'call not verified');
      }
    }

    log('session_established', { callSid, from: event.from, to: event.to });
  }

  function handlePrompt(event: Record<string, unknown>): void {
    const voicePrompt = typeof event.voicePrompt === 'string' ? event.voicePrompt : '';

    // Refuse to do anything before `setup` has established who this is.
    if (!setupSeen) {
      log('prompt_before_setup', { callSid });
      return ws.close(CLOSE_POLICY_VIOLATION, 'prompt before setup');
    }

    // `voicePrompt` is transcribed caller speech: untrusted, unauthenticated,
    // and invisible to every WAF between you and Twilio. Pass it to an LLM as
    // user-role content inside a structured prompt -- never concatenated into
    // your system instructions -- and filter what comes back, because whatever
    // the model returns is spoken to the caller verbatim.
    //
    // Transcripts are also personal data. Think before you log them.
    log('prompt_received', { callSid, characters: voicePrompt.length });

    ws.send(
      JSON.stringify({
        type: 'text',
        token: 'Thanks, I heard you. This sample only demonstrates the security layers.',
        last: true,
      }),
    );
  }
}

function log(event: string, fields: Record<string, unknown>): void {
  console.info(JSON.stringify({ event, ...fields }));
}
