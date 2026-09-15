/**
 * `$default` route: every frame Twilio sends arrives here as its own invocation.
 *
 * That is the real cost of the serverless shape. There is no process holding the
 * conversation in memory, so anything that has to persist between frames -- the
 * verified CallSid included -- goes in DynamoDB. The security consequence is
 * that the `setup` cross-check has to be written carefully:
 *
 *   - The authorizer's verified CallSid reaches the FIRST invocation only, in
 *     `requestContext.authorizer`. Persist it on `$connect`.
 *   - On `setup`, compare the claimed CallSid against that stored value.
 *   - On every later frame, refuse to act until a session row exists and is
 *     marked verified. Otherwise a peer could skip `setup` and start prompting.
 */

import {
  ApiGatewayManagementApiClient,
  PostToConnectionCommand,
  DeleteConnectionCommand,
} from '@aws-sdk/client-apigatewaymanagementapi';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  PutCommand,
  UpdateCommand,
  DeleteCommand,
} from '@aws-sdk/lib-dynamodb';
import { callSidMatches } from '@twilio-samples/relay-auth';

import { loadConfig } from './config.js';

interface WebSocketEvent {
  body?: string | null;
  requestContext: {
    connectionId: string;
    domainName: string;
    stage: string;
    routeKey: string;
    authorizer?: { callSid?: string; accountSid?: string };
  };
}

const config = loadConfig();
const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));

/** Session rows are short-lived; DynamoDB TTL reaps them. */
const SESSION_TTL_SECONDS = 4 * 60 * 60;

// ---------------------------------------------------------------------------
// $connect -- persist the authorizer's verdict
// ---------------------------------------------------------------------------

export const connectHandler = async (event: WebSocketEvent) => {
  const { connectionId, authorizer } = event.requestContext;
  const callSid = authorizer?.callSid;

  // The authorizer already denied anything without a valid token, so this is
  // belt-and-braces -- but a missing context here means the authorizer was
  // misconfigured, which is worth failing loudly rather than shrugging at.
  if (!callSid) {
    console.error(JSON.stringify({ event: 'connect_missing_authorizer_context', connectionId }));
    return { statusCode: 401, body: 'Unauthorized' };
  }

  await ddb.send(
    new PutCommand({
      TableName: config.sessionTableName,
      Item: {
        connectionId,
        callSid,
        accountSid: authorizer?.accountSid,
        setupVerified: false,
        expiresAt: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS,
      },
    }),
  );

  console.info(JSON.stringify({ event: 'connected', connectionId, callSid }));
  return { statusCode: 200, body: 'Connected' };
};

// ---------------------------------------------------------------------------
// $default -- the relay protocol
// ---------------------------------------------------------------------------

export const handler = async (event: WebSocketEvent) => {
  const { connectionId, domainName, stage } = event.requestContext;

  const session = await getSession(connectionId);
  if (!session) {
    console.warn(JSON.stringify({ event: 'frame_without_session', connectionId }));
    await disconnect(domainName, stage, connectionId);
    return { statusCode: 403, body: 'Forbidden' };
  }

  let frame: Record<string, unknown>;
  try {
    frame = JSON.parse(event.body ?? '');
  } catch {
    console.warn(JSON.stringify({ event: 'malformed_frame', connectionId }));
    await disconnect(domainName, stage, connectionId);
    return { statusCode: 400, body: 'Bad Request' };
  }

  switch (frame.type) {
    case 'setup': {
      // The check that makes CallSid binding mean something.
      if (!callSidMatches({ callSid: session.callSid }, frame.callSid)) {
        console.warn(
          JSON.stringify({
            event: 'call_sid_mismatch',
            connectionId,
            expected: session.callSid,
            claimed: frame.callSid,
          }),
        );
        await disconnect(domainName, stage, connectionId);
        return { statusCode: 403, body: 'Forbidden' };
      }

      await ddb.send(
        new UpdateCommand({
          TableName: config.sessionTableName,
          Key: { connectionId },
          UpdateExpression: 'SET setupVerified = :v',
          ExpressionAttributeValues: { ':v': true },
        }),
      );

      console.info(JSON.stringify({ event: 'session_established', connectionId, callSid: session.callSid }));
      return { statusCode: 200, body: 'OK' };
    }

    case 'prompt': {
      // Refuse to talk to a peer that never identified itself.
      if (!session.setupVerified) {
        console.warn(JSON.stringify({ event: 'prompt_before_setup', connectionId }));
        await disconnect(domainName, stage, connectionId);
        return { statusCode: 403, body: 'Forbidden' };
      }

      const voicePrompt = typeof frame.voicePrompt === 'string' ? frame.voicePrompt : '';
      console.info(
        JSON.stringify({ event: 'prompt_received', connectionId, characters: voicePrompt.length }),
      );

      // `voicePrompt` is transcribed caller speech: untrusted input that no WAF
      // between you and Twilio can inspect. Give it to an LLM as user-role
      // content inside a structured prompt, never spliced into your system
      // instructions, and filter the output -- it is spoken to the caller as-is.
      await send(domainName, stage, connectionId, {
        type: 'text',
        token: 'Thanks, I heard you. This sample only demonstrates the security layers.',
        last: true,
      });
      return { statusCode: 200, body: 'OK' };
    }

    default:
      console.info(JSON.stringify({ event: 'frame', connectionId, frameType: frame.type }));
      return { statusCode: 200, body: 'OK' };
  }
};

// ---------------------------------------------------------------------------
// $disconnect
// ---------------------------------------------------------------------------

export const disconnectHandler = async (event: WebSocketEvent) => {
  const { connectionId } = event.requestContext;
  await ddb.send(
    new DeleteCommand({ TableName: config.sessionTableName, Key: { connectionId } }),
  );
  console.info(JSON.stringify({ event: 'disconnected', connectionId }));
  return { statusCode: 200, body: 'Disconnected' };
};

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

interface Session {
  callSid: string;
  setupVerified: boolean;
}

async function getSession(connectionId: string): Promise<Session | undefined> {
  const { Item } = await ddb.send(
    new GetCommand({ TableName: config.sessionTableName, Key: { connectionId } }),
  );
  if (!Item || typeof Item.callSid !== 'string') return undefined;
  return { callSid: Item.callSid, setupVerified: Item.setupVerified === true };
}

function managementClient(domainName: string, stage: string) {
  return new ApiGatewayManagementApiClient({ endpoint: `https://${domainName}/${stage}` });
}

async function send(
  domainName: string,
  stage: string,
  connectionId: string,
  payload: unknown,
): Promise<void> {
  await managementClient(domainName, stage).send(
    new PostToConnectionCommand({
      ConnectionId: connectionId,
      Data: Buffer.from(JSON.stringify(payload)),
    }),
  );
}

async function disconnect(domainName: string, stage: string, connectionId: string): Promise<void> {
  try {
    await managementClient(domainName, stage).send(
      new DeleteConnectionCommand({ ConnectionId: connectionId }),
    );
  } catch (err) {
    // Already gone is fine; anything else is worth a log line but not a throw.
    console.warn(JSON.stringify({ event: 'disconnect_failed', connectionId, message: String(err) }));
  }
}
