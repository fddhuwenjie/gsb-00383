const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const path = require('path');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');

// Isolated temp DB so this flow does not touch dev data/auth.db.
const tmpDb = path.join(os.tmpdir(), `token-events-${process.pid}.db`);
const { createApp, loadConfig } = require('../src/server');
const app = createApp(loadConfig({ dbPath: tmpDb }));
const { getDb } = require('../src/db');

let server;
let baseUrl;

function request(method, urlPath, data, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlPath, baseUrl);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method,
      headers: { ...headers }
    };

    if (data && (method === 'POST' || method === 'PUT')) {
      if (typeof data === 'object' && !Buffer.isBuffer(data)) {
        if (headers['Content-Type'] === 'application/json') {
          data = JSON.stringify(data);
        } else {
          data = new URLSearchParams(data).toString();
          options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }
      }
      options.headers['Content-Length'] = Buffer.byteLength(data);
    }

    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => {
        try { body = JSON.parse(body); } catch (e) {}
        resolve({ status: res.statusCode, headers: res.headers, body });
      });
    });
    req.on('error', reject);
    if (data && (method === 'POST' || method === 'PUT')) req.write(data);
    req.end();
  });
}

function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('hex');
}
function generateCodeChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

const REDIRECT_URI = 'http://localhost:8080/callback';
const SCOPE = 'openid profile';
let client;
let basicAuth;

async function obtainAuthorizationCode(verifier) {
  const challenge = generateCodeChallenge(verifier);
  const consentResp = await request('POST', '/authorize/consent', {
    client_id: client.client_id,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: SCOPE,
    state: 'xyz',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    username: 'alice',
    action: 'allow'
  });
  const location = consentResp.headers.location;
  const match = location && location.match(/code=([^&]+)/);
  return match ? decodeURIComponent(match[1]) : null;
}

async function exchangeCodeForTokens() {
  const verifier = generateCodeVerifier();
  const code = await obtainAuthorizationCode(verifier);
  const resp = await request('POST', '/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier
  }, { Authorization: basicAuth });
  return resp.body;
}

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, () => {
      baseUrl = `http://localhost:${server.address().port}`;
      resolve();
    });
  });

  const reg = await request('POST', '/register', {
    client_name: 'Token Events Client',
    client_type: 'confidential',
    redirect_uris: [REDIRECT_URI],
    grant_types: ['authorization_code', 'refresh_token']
  }, { 'Content-Type': 'application/json' });
  client = reg.body;
  basicAuth = 'Basic ' + Buffer.from(client.client_id + ':' + client.client_secret).toString('base64');
});

test.after(() => {
  if (server) server.close();
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(tmpDb + suffix); } catch (e) {}
  }
});

// --- Event writing -----------------------------------------------------------

test('the three event types are written on the corresponding operations', async () => {
  // 1) successful code consumption
  const tokens = await exchangeCodeForTokens();
  assert.ok(tokens.refresh_token);

  // 2) successful refresh token rotation
  const rotated = await request('POST', '/token', {
    grant_type: 'refresh_token',
    refresh_token: tokens.refresh_token
  }, { Authorization: basicAuth });
  assert.strictEqual(rotated.status, 200);

  // 3) invalid token rejection
  const bad = await request('POST', '/token', {
    grant_type: 'refresh_token',
    refresh_token: 'refresh_not_real'
  }, { Authorization: basicAuth });
  assert.strictEqual(bad.status, 400);

  const resp = await request('GET', '/token-events', null, { Authorization: basicAuth });
  assert.strictEqual(resp.status, 200);
  const types = resp.body.events.map(e => e.event_type);
  assert.ok(types.includes('authorization_code_consumed'));
  assert.ok(types.includes('refresh_token_rotated'));
  assert.ok(types.includes('invalid_token_rejected'));

  // Every event carries only id, event_type, created_at.
  for (const ev of resp.body.events) {
    assert.deepStrictEqual(Object.keys(ev).sort(), ['created_at', 'event_type', 'id']);
    assert.strictEqual(typeof ev.id, 'number');
    assert.strictEqual(typeof ev.created_at, 'number');
  }

  // Results are ordered by time (non-decreasing).
  for (let i = 1; i < resp.body.events.length; i++) {
    assert.ok(resp.body.events[i].created_at >= resp.body.events[i - 1].created_at);
  }
});

// --- Filtering by event type -------------------------------------------------

test('the query endpoint filters by event_type', async () => {
  const all = await request('GET', '/token-events', null, { Authorization: basicAuth });
  const filtered = await request('GET', '/token-events?event_type=invalid_token_rejected', null, {
    Authorization: basicAuth
  });
  assert.strictEqual(filtered.status, 200);
  assert.ok(filtered.body.events.length > 0);
  assert.ok(filtered.body.events.every(e => e.event_type === 'invalid_token_rejected'));
  assert.ok(filtered.body.events.length <= all.body.events.length);
});

test('an unknown event_type filter is rejected', async () => {
  const resp = await request('GET', '/token-events?event_type=nope', null, { Authorization: basicAuth });
  assert.strictEqual(resp.status, 400);
  assert.strictEqual(resp.body.error, 'invalid_request');
});

test('the query endpoint requires client authentication', async () => {
  const resp = await request('GET', '/token-events');
  assert.strictEqual(resp.status, 401);
  assert.strictEqual(resp.body.error, 'invalid_client');
});

// --- Sensitive values are never persisted ------------------------------------

test('token_events stores no code, token, or key material', async () => {
  // Drive one more full flow so the table has fresh rows with known secrets.
  const verifier = generateCodeVerifier();
  const code = await obtainAuthorizationCode(verifier);
  const tokenResp = await request('POST', '/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier
  }, { Authorization: basicAuth });
  const accessToken = tokenResp.body.access_token;
  const refreshToken = tokenResp.body.refresh_token;

  const db = getDb();

  // Schema: only id, event_type, created_at columns exist.
  const columns = db.prepare('PRAGMA table_info(token_events)').all().map(c => c.name).sort();
  assert.deepStrictEqual(columns, ['created_at', 'event_type', 'id']);

  // No stored event_type value contains any secret substring, and every row's
  // event_type is one of the known enum values.
  const rows = db.prepare('SELECT id, event_type, created_at FROM token_events').all();
  const known = ['authorization_code_consumed', 'refresh_token_rotated', 'invalid_token_rejected'];
  const secrets = [code, accessToken, refreshToken].filter(Boolean);
  for (const row of rows) {
    assert.ok(known.includes(row.event_type), `unexpected event_type: ${row.event_type}`);
    for (const secret of secrets) {
      assert.ok(!row.event_type.includes(secret), 'event_type must not contain a secret');
    }
  }

  // Dump the entire table as text and assert no secret appears anywhere.
  const dump = JSON.stringify(rows);
  for (const secret of secrets) {
    assert.ok(!dump.includes(secret), 'token_events dump must not contain any secret value');
  }
});
