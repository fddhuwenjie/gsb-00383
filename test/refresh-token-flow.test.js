const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const path = require('path');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');

// Isolated temp DB so this flow does not touch dev data/auth.db.
const tmpDb = path.join(os.tmpdir(), `refresh-token-flow-${process.pid}.db`);
const { createApp, loadConfig } = require('../src/server');
const app = createApp(loadConfig({ dbPath: tmpDb }));

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

// Run the full code flow once to obtain a valid initial refresh token.
async function obtainInitialTokens() {
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
    client_name: 'Refresh Flow Client',
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

test('normal issuance: code exchange returns a usable refresh token', async () => {
  const tokens = await obtainInitialTokens();
  assert.ok(tokens.access_token, 'access_token present');
  assert.ok(tokens.refresh_token, 'refresh_token present');
  assert.match(tokens.refresh_token, /^refresh_/);
  assert.strictEqual(tokens.token_type, 'Bearer');
  assert.strictEqual(tokens.scope, SCOPE);

  // The freshly issued refresh token is active per introspection.
  const introspect = await request('POST', '/introspect', {
    token: tokens.refresh_token,
    token_type_hint: 'refresh_token'
  }, { Authorization: basicAuth });
  assert.strictEqual(introspect.body.active, true);
});

test('successful rotation: new pair issued and old refresh token invalidated', async () => {
  const initial = await obtainInitialTokens();

  const refreshResp = await request('POST', '/token', {
    grant_type: 'refresh_token',
    refresh_token: initial.refresh_token
  }, { Authorization: basicAuth });

  assert.strictEqual(refreshResp.status, 200);
  assert.ok(refreshResp.body.access_token, 'new access_token present');
  assert.ok(refreshResp.body.refresh_token, 'new refresh_token present');
  assert.notStrictEqual(refreshResp.body.refresh_token, initial.refresh_token, 'refresh token rotated');
  assert.strictEqual(refreshResp.body.token_type, 'Bearer');
  assert.strictEqual(refreshResp.body.scope, SCOPE);

  // Old refresh token must be revoked after rotation.
  const oldIntrospect = await request('POST', '/introspect', {
    token: initial.refresh_token,
    token_type_hint: 'refresh_token'
  }, { Authorization: basicAuth });
  assert.strictEqual(oldIntrospect.body.active, false, 'old refresh token revoked');

  // New refresh token is active.
  const newIntrospect = await request('POST', '/introspect', {
    token: refreshResp.body.refresh_token,
    token_type_hint: 'refresh_token'
  }, { Authorization: basicAuth });
  assert.strictEqual(newIntrospect.body.active, true, 'new refresh token active');
});

test('reusing an already-rotated refresh token returns invalid_grant', async () => {
  const initial = await obtainInitialTokens();

  const first = await request('POST', '/token', {
    grant_type: 'refresh_token',
    refresh_token: initial.refresh_token
  }, { Authorization: basicAuth });
  assert.strictEqual(first.status, 200, 'first rotation succeeds');

  const replay = await request('POST', '/token', {
    grant_type: 'refresh_token',
    refresh_token: initial.refresh_token
  }, { Authorization: basicAuth });
  assert.strictEqual(replay.status, 400, 'reuse rejected');
  assert.strictEqual(replay.body.error, 'invalid_grant');
  assert.strictEqual(replay.body.error_description, 'Refresh token has been revoked');
});

test('an entirely invalid refresh token returns invalid_grant', async () => {
  const resp = await request('POST', '/token', {
    grant_type: 'refresh_token',
    refresh_token: 'refresh_not_a_real_token'
  }, { Authorization: basicAuth });
  assert.strictEqual(resp.status, 400);
  assert.strictEqual(resp.body.error, 'invalid_grant');
  assert.strictEqual(resp.body.error_description, 'Invalid refresh token');
});
