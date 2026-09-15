/**
 * Lambda REQUEST authorizer for the `$connect` route.
 *
 * This is the cleanest enforcement point on any of the three clouds. API Gateway
 * runs it before the WebSocket exists; deny and the client gets a bare 401 with
 * no connection, no `$default` invocation, and nothing to clean up.
 *
 * The authorizer receives both of the things we need:
 *   - `event.headers['X-Twilio-Signature']`  -> the signature
 *   - `event.queryStringParameters.t`        -> the connection token
 *
 * ---------------------------------------------------------------------------
 * THE TRAP: authorizer result caching
 * ---------------------------------------------------------------------------
 * API Gateway can cache an authorizer's decision, keyed on its identity
 * sources. If caching is on and the token is an identity source, then replaying
 * a token inside the cache window returns the cached ALLOW *without invoking
 * this function at all*. Your single-use check never runs, and nothing in your
 * logs shows it was skipped.
 *
 * `template.yaml` therefore sets `AuthorizerResultTtlInSeconds: 0`. If you take
 * one thing from this file, take that.
 */

import {
  authenticateUpgrade,
  redactToken,
  DynamoJtiStore,
  type GuardConfig,
} from '@twilio-samples/relay-auth';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, PutCommand } from '@aws-sdk/lib-dynamodb';

import { loadConfig } from './config.js';

interface WebSocketAuthorizerEvent {
  methodArn: string;
  headers?: Record<string, string | undefined>;
  queryStringParameters?: Record<string, string | undefined>;
  requestContext: { connectionId?: string; stage?: string };
}

interface PolicyDocument {
  principalId: string;
  policyDocument: {
    Version: string;
    Statement: Array<{ Action: string; Effect: 'Allow' | 'Deny'; Resource: string }>;
  };
  /** Passed through to `$connect` / `$default` via `requestContext.authorizer`. */
  context?: Record<string, string>;
}

const config = loadConfig();

const jtiStore = new DynamoJtiStore({
  client: DynamoDBDocumentClient.from(new DynamoDBClient({})),
  tableName: config.jtiTableName,
  PutCommand,
});

export const handler = async (event: WebSocketAuthorizerEvent): Promise<PolicyDocument> => {
  // API Gateway lower-cases nothing for you, so normalise before lookup.
  const headers = lowerCaseKeys(event.headers ?? {});
  const query = event.queryStringParameters ?? {};

  const requestTarget = buildRequestTarget(config.wsPath, query);

  const guard: GuardConfig = {
    publicOrigin: config.wssOrigin,
    twilioAuthTokens: config.twilioAuthTokens,
    tokenSecret: config.tokenSecret,
    jtiStore,
  };

  let result;
  try {
    result = await authenticateUpgrade({ requestTarget, headers, query }, guard);
  } catch (err) {
    // A DynamoDB failure must deny. Failing open here would mean losing replay
    // protection at exactly the moment someone might be causing the errors.
    console.error(
      JSON.stringify({ event: 'authorizer_error', message: String(err), target: redactToken(requestTarget) }),
    );
    return deny(event.methodArn);
  }

  if (!result.ok) {
    // The reason is for CloudWatch. The caller only ever sees 401.
    console.warn(
      JSON.stringify({
        event: 'connect_denied',
        reason: result.reason,
        target: redactToken(requestTarget),
      }),
    );
    return deny(event.methodArn);
  }

  console.info(JSON.stringify({ event: 'connect_allowed', callSid: result.claims.callSid }));

  // Hand the verified CallSid downstream so `$default` can compare it against
  // the `setup` frame without having to trust anything the client sent.
  return allow(event.methodArn, result.claims.callSid, {
    callSid: result.claims.callSid,
    ...(result.claims.accountSid ? { accountSid: result.claims.accountSid } : {}),
  });
};

/**
 * Rebuilds the path-and-query string Twilio signed.
 *
 * API Gateway hands query parameters over already parsed, so this reassembles
 * them. Key order is preserved from the parsed object, which matches the order
 * Twilio sent for the single-parameter URL this sample produces. If you add more
 * query parameters, reconstruct them in the exact order your TwiML wrote them --
 * the HMAC covers the raw string, so ordering is significant.
 */
function buildRequestTarget(path: string, query: Record<string, string | undefined>): string {
  const entries = Object.entries(query).filter(([, v]) => v !== undefined) as [string, string][];
  if (entries.length === 0) return path;
  const qs = entries.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('&');
  return `${path}?${qs}`;
}

function lowerCaseKeys(
  headers: Record<string, string | undefined>,
): Record<string, string | undefined> {
  return Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));
}

function allow(resource: string, principalId: string, context: Record<string, string>): PolicyDocument {
  return policy(principalId, 'Allow', resource, context);
}

function deny(resource: string): PolicyDocument {
  return policy('unauthorized', 'Deny', resource);
}

function policy(
  principalId: string,
  Effect: 'Allow' | 'Deny',
  Resource: string,
  context?: Record<string, string>,
): PolicyDocument {
  return {
    principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [{ Action: 'execute-api:Invoke', Effect, Resource }],
    },
    ...(context ? { context } : {}),
  };
}
