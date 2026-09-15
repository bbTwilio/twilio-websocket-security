/**
 * Replay protection for connection tokens.
 *
 * A token is single-use, which needs one atomic "claim this id, tell me if I am
 * first" operation. Every implementation below is a compare-and-set, never a
 * read-then-write: two upgrade requests carrying the same token can land on two
 * instances at the same moment, and a read-then-write would let both through.
 */

export interface JtiStore {
  /**
   * Atomically records `jti`. Returns true only for the first caller.
   *
   * @param jti Token id to claim.
   * @param ttlSeconds How long to remember it -- a little longer than the
   *   token's own lifetime, so the record cannot expire before the token does.
   */
  consume(jti: string, ttlSeconds: number): Promise<boolean>;
}

/**
 * Process-local store. Fine for local development and unit tests.
 *
 * Not fine for production: it protects one process only. Two Lambda executions
 * or two Cloud Run instances each keep their own map, so a replay simply routes
 * to the other one and succeeds. Use Redis or DynamoDB when you deploy.
 */
export class InMemoryJtiStore implements JtiStore {
  private readonly seen = new Map<string, number>();

  async consume(jti: string, ttlSeconds: number): Promise<boolean> {
    const now = Date.now();
    for (const [key, expiresAt] of this.seen) {
      if (expiresAt <= now) this.seen.delete(key);
    }
    if (this.seen.has(jti)) return false;
    this.seen.set(jti, now + ttlSeconds * 1000);
    return true;
  }

  /** Test helper. */
  clear(): void {
    this.seen.clear();
  }
}

/** Minimal surface we need from a Redis client (node-redis or ioredis). */
export interface RedisLike {
  set(
    key: string,
    value: string,
    ...args: unknown[]
  ): Promise<string | null>;
}

/**
 * Redis-backed store. `SET key value NX EX ttl` is a single round trip and is
 * atomic, so exactly one concurrent caller sees `OK`.
 */
export class RedisJtiStore implements JtiStore {
  constructor(
    private readonly redis: RedisLike,
    private readonly prefix = 'relay:jti:',
  ) {}

  async consume(jti: string, ttlSeconds: number): Promise<boolean> {
    // ioredis argument style; node-redis v4 accepts `{ NX: true, EX: ttl }`.
    const result = await this.redis.set(this.prefix + jti, '1', 'EX', ttlSeconds, 'NX');
    return result === 'OK';
  }
}

/** Minimal surface we need from `@aws-sdk/lib-dynamodb`'s DocumentClient. */
export interface DynamoLike {
  send(command: unknown): Promise<unknown>;
}

/**
 * The subset of `PutCommandInput` this store actually builds.
 *
 * Deliberately narrow: `Item` values are `string | number` rather than
 * `unknown`, which is what makes the real `PutCommand` class assignable to the
 * constructor type below without a cast at the call site.
 */
export interface ConditionalPutInput {
  TableName: string;
  Item: Record<string, string | number>;
  ConditionExpression: string;
  ExpressionAttributeNames: Record<string, string>;
}

export interface DynamoJtiStoreOptions {
  client: DynamoLike;
  tableName: string;
  /** Partition key name. Table must have TTL enabled on `expiresAt`. */
  keyName?: string;
  /**
   * `PutCommand` constructor from `@aws-sdk/lib-dynamodb`, injected so this
   * package carries no AWS dependency of its own.
   */
  PutCommand: new (input: ConditionalPutInput) => unknown;
}

/**
 * DynamoDB-backed store, for the API Gateway + Lambda sample.
 *
 * A conditional put on `attribute_not_exists` is atomic. The condition failing
 * *is* the replay signal, so treat that specific error as "not first" and let
 * every other error propagate -- a table outage must fail closed, not open.
 */
export class DynamoJtiStore implements JtiStore {
  private readonly keyName: string;

  constructor(private readonly opts: DynamoJtiStoreOptions) {
    this.keyName = opts.keyName ?? 'jti';
  }

  async consume(jti: string, ttlSeconds: number): Promise<boolean> {
    const { client, tableName, PutCommand } = this.opts;
    try {
      await client.send(
        new PutCommand({
          TableName: tableName,
          Item: {
            [this.keyName]: jti,
            expiresAt: Math.floor(Date.now() / 1000) + ttlSeconds,
          },
          ConditionExpression: `attribute_not_exists(#k)`,
          ExpressionAttributeNames: { '#k': this.keyName },
        }),
      );
      return true;
    } catch (err) {
      if ((err as { name?: string })?.name === 'ConditionalCheckFailedException') return false;
      throw err;
    }
  }
}
