/**
 * Voice webhook: validate the Twilio signature, mint a connection token, and
 * return TwiML pointing at the WebSocket API.
 *
 * This is a normal HTTP webhook, so normal webhook rules apply -- including the
 * `https://` scheme when rebuilding the signed URL. The `wss://` exception is
 * for the upgrade request only, and mixing the two up is the single most common
 * way this breaks.
 */

import twilio from 'twilio';
import { buildRelayUrl, mintRelayToken } from '@twilio-samples/relay-auth';

import { loadConfig } from './config.js';

interface ApiGatewayProxyEvent {
  body: string | null;
  isBase64Encoded?: boolean;
  headers: Record<string, string | undefined>;
  requestContext?: { path?: string; domainName?: string };
  rawPath?: string;
  path?: string;
}

interface ApiGatewayProxyResult {
  statusCode: number;
  headers?: Record<string, string>;
  body: string;
}

export const handler = async (event: ApiGatewayProxyEvent): Promise<ApiGatewayProxyResult> => {
  const config = loadConfig();

  const raw = event.isBase64Encoded && event.body
    ? Buffer.from(event.body, 'base64').toString('utf-8')
    : event.body ?? '';
  const params = Object.fromEntries(new URLSearchParams(raw));

  const headers = Object.fromEntries(
    Object.entries(event.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]),
  );
  const signature = headers['x-twilio-signature'] ?? '';

  // Must match the URL configured on the Twilio number exactly.
  const webhookPath = event.rawPath ?? event.path ?? event.requestContext?.path ?? '/voice';
  const signedUrl = `${config.voiceWebhookOrigin}${webhookPath}`;

  const signatureOk = config.twilioAuthTokens.some(
    (token) => token && twilio.validateRequest(token, signature, signedUrl, params),
  );

  if (!signatureOk) {
    console.warn(JSON.stringify({ event: 'voice_webhook_rejected', reason: 'invalid_signature' }));
    return { statusCode: 403, headers: { 'Content-Type': 'text/plain' }, body: 'Forbidden' };
  }

  const callSid = params.CallSid;
  if (!callSid) {
    return { statusCode: 400, headers: { 'Content-Type': 'text/plain' }, body: 'Missing CallSid' };
  }

  // Twilio has just told us the CallSid, so bind the token to this one call.
  const { token, jti, expiresAt } = await mintRelayToken({
    callSid,
    accountSid: params.AccountSid,
    secret: config.tokenSecret,
    ttlSeconds: config.tokenTtlSeconds,
  });

  console.info(
    JSON.stringify({ event: 'relay_token_minted', callSid, jti, expiresAt: expiresAt.toISOString() }),
  );

  const relayUrl = buildRelayUrl(config.wssOrigin + config.wsPath, token);

  const response = new twilio.twiml.VoiceResponse();
  const connect = response.connect();
  connect.conversationRelay({
    url: relayUrl,
    welcomeGreeting: 'Hello! How can I help you today?',
  });

  return {
    statusCode: 200,
    headers: { 'Content-Type': 'text/xml' },
    body: response.toString(),
  };
};
