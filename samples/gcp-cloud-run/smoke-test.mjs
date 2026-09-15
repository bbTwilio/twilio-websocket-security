/**
 * End-to-end smoke test for the security layers.
 *
 * Boots the server, then drives the paths that matter: an anonymous socket must
 * be refused, a properly minted one must connect, and the same token must not
 * work twice. Run with the server NOT already running:
 *
 *   node smoke-test.mjs
 *
 * Exits non-zero if any expectation fails.
 */
import { spawn } from 'node:child_process';
import { createHmac, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import http from 'node:http';
import WebSocket from 'ws';

const AUTH_TOKEN = 'test_auth_token_' + 'x'.repeat(16);
const SECRET_B64 = randomBytes(32).toString('base64');
const PORT = 8099;
const HOST = `127.0.0.1:${PORT}`;
// The server signs against wss://$PUBLIC_HOST, so PUBLIC_HOST must match.
const PUBLIC_HOST = HOST;

const results = [];
function check(name, passed, detail = '') {
  results.push({ name, passed, detail });
  console.log(`${passed ? 'PASS' : 'FAIL'}  ${name}${detail ? `  (${detail})` : ''}`);
}

function sign(url, params = {}) {
  const data = Object.keys(params)
    .sort()
    .reduce((acc, k) => acc + k + params[k], url);
  return createHmac('sha1', AUTH_TOKEN).update(Buffer.from(data, 'utf-8')).digest('base64');
}

const server = spawn(process.execPath, ['--import', 'tsx', 'src/server.ts'], {
  env: {
    ...process.env,
    PORT: String(PORT),
    PUBLIC_HOST,
    TWILIO_AUTH_TOKEN: AUTH_TOKEN,
    RELAY_TOKEN_SECRET: SECRET_B64,
  },
  stdio: ['ignore', 'pipe', 'pipe'],
});
server.stdout.on('data', (d) => process.stdout.write(`  [server] ${d}`));
server.stderr.on('data', (d) => process.stderr.write(`  [server] ${d}`));

/** Raw upgrade attempt so we can observe the HTTP status instead of a thrown error. */
function attemptUpgrade(path, signature) {
  return new Promise((resolve) => {
    const headers = {
      Connection: 'Upgrade',
      Upgrade: 'websocket',
      'Sec-WebSocket-Key': randomBytes(16).toString('base64'),
      'Sec-WebSocket-Version': '13',
    };
    if (signature) headers['X-Twilio-Signature'] = signature;

    const req = http.request({ host: '127.0.0.1', port: PORT, path, headers });
    req.on('upgrade', (res, socket) => {
      socket.destroy();
      resolve({ status: 101 });
    });
    req.on('response', (res) => {
      res.resume();
      resolve({ status: res.statusCode });
    });
    req.on('error', (err) => resolve({ status: 0, error: String(err) }));
    req.end();
  });
}

function postVoice(body) {
  return new Promise((resolve, reject) => {
    const payload = new URLSearchParams(body).toString();
    const url = `https://${PUBLIC_HOST}/voice`;
    const req = http.request(
      {
        host: '127.0.0.1',
        port: PORT,
        path: '/voice',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(payload),
          'X-Twilio-Signature': sign(url, body),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (d) => (data += d));
        res.on('end', () => resolve({ status: res.statusCode, body: data }));
      },
    );
    req.on('error', reject);
    req.end(payload);
  });
}

async function waitForBoot() {
  for (let i = 0; i < 60; i++) {
    try {
      const res = await new Promise((resolve, reject) => {
        const r = http.get({ host: '127.0.0.1', port: PORT, path: '/health' }, resolve);
        r.on('error', reject);
      });
      res.resume();
      if (res.statusCode === 200) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('server did not become healthy');
}

try {
  await waitForBoot();
  console.log('\n--- Layer 2: signature validation ---');

  check('anonymous upgrade is refused', (await attemptUpgrade('/ws')).status === 401);
  check(
    'upgrade with a bogus signature is refused',
    (await attemptUpgrade('/ws?t=abc', 'not-a-real-signature')).status === 401,
  );

  // The gotcha, proven: a signature over the https:// form of the same URL fails.
  const target = '/ws?t=whatever';
  const httpsSigned = createHmac('sha1', AUTH_TOKEN)
    .update(Buffer.from(`https://${PUBLIC_HOST}${target}`, 'utf-8'))
    .digest('base64');
  check(
    'signature computed over https:// is refused (the scheme gotcha)',
    (await attemptUpgrade(target, httpsSigned)).status === 401,
  );

  console.log('\n--- Voice webhook ---');
  const unsigned = await new Promise((resolve) => {
    const payload = new URLSearchParams({ CallSid: 'CAtest' }).toString();
    const req = http.request(
      {
        host: '127.0.0.1',
        port: PORT,
        path: '/voice',
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          'Content-Length': Buffer.byteLength(payload),
        },
      },
      (res) => {
        res.resume();
        resolve(res.statusCode);
      },
    );
    req.end(payload);
  });
  check('unsigned voice webhook is refused', unsigned === 403, `got ${unsigned}`);

  const callSid = 'CA' + '1'.repeat(32);
  const voice = await postVoice({ CallSid: callSid, AccountSid: 'AC' + '2'.repeat(32) });
  check('signed voice webhook returns TwiML', voice.status === 200, `got ${voice.status}`);

  const urlMatch = voice.body.match(/url="([^"]+)"/);
  check('TwiML contains a ConversationRelay url', Boolean(urlMatch));
  const relayUrl = urlMatch?.[1].replace(/&amp;/g, '&');
  check('relay url carries a token', /[?&]t=[\w-]+\.[\w-]+\.[\w-]+/.test(relayUrl ?? ''));

  console.log('\n--- Layer 3: token, binding, replay ---');
  const relayTarget = relayUrl.slice(`wss://${PUBLIC_HOST}`.length);
  const goodSig = sign(relayUrl);

  const first = await attemptUpgrade(relayTarget, goodSig);
  check('correctly signed + tokened upgrade succeeds', first.status === 101, `got ${first.status}`);

  const replay = await attemptUpgrade(relayTarget, goodSig);
  check('replaying the same token is refused', replay.status === 401, `got ${replay.status}`);

  console.log('\n--- setup frame: CallSid binding ---');
  const fresh = await postVoice({ CallSid: callSid });
  const freshUrl = fresh.body.match(/url="([^"]+)"/)[1].replace(/&amp;/g, '&');
  const freshTarget = freshUrl.slice(`wss://${PUBLIC_HOST}`.length);

  const ws = new WebSocket(`ws://${HOST}${freshTarget}`, {
    headers: { 'X-Twilio-Signature': sign(freshUrl) },
  });
  await once(ws, 'open');
  // Claim a different call than the token was minted for.
  ws.send(JSON.stringify({ type: 'setup', callSid: 'CA' + '9'.repeat(32) }));
  const [code] = await once(ws, 'close');
  check('mismatched CallSid in setup closes the socket', code === 1008, `close code ${code}`);
} catch (err) {
  check('smoke test ran to completion', false, String(err));
} finally {
  server.kill();
}

const failed = results.filter((r) => !r.passed);
console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
process.exit(failed.length === 0 ? 0 : 1);
