export {
  TWILIO_SIGNATURE_HEADER,
  buildSignedUrl,
  validateTwilioUpgrade,
  validateUpgradeRequest,
  type SignedUrlParts,
  type ValidateUpgradeInput,
} from './signature.js';

export {
  DEFAULT_AUDIENCE,
  DEFAULT_ISSUER,
  DEFAULT_TTL_SECONDS,
  TOKEN_QUERY_PARAM,
  buildRelayPathUrl,
  buildRelayUrl,
  callSidMatches,
  mintRelayToken,
  verifyRelayToken,
  type MintOptions,
  type MintResult,
  type RelayTokenClaims,
  type VerifyFailureReason,
  type VerifyOptions,
  type VerifyResult,
} from './token.js';

export {
  DynamoJtiStore,
  InMemoryJtiStore,
  RedisJtiStore,
  type ConditionalPutInput,
  type DynamoJtiStoreOptions,
  type DynamoLike,
  type JtiStore,
  type RedisLike,
} from './jti-store.js';

export {
  authenticateUpgrade,
  redactToken,
  type GuardConfig,
  type GuardFailureReason,
  type GuardResult,
  type TokenLocation,
  type UpgradeRequestLike,
} from './guard.js';

export {
  verifyCallIsLive,
  type CallCheckClient,
  type CallCheckOptions,
  type CallCheckOutcome,
} from './call-check.js';
