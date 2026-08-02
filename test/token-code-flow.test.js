const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const path = require('path');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');

// Isolated temp DB so the integration flow does not touch dev data/auth.db.
const tmpDb = path.join(os.tmpdir(), `token-code-flow-${process.pid}.db`);
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
let client;
let basicAuth;

// Register a confidential client and obtain a fresh authorization code by
// driving the real authorize -> login -> consent flow over HTTP.
async function obtainAuthorizationCode(verifier) {
  const challenge = generateCodeChallenge(verifier);
  const consentResp = await request('POST', '/authorize/consent', {
    client_id: client.client_id,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: 'openid profile',
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

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, () => {
      const { port } = server.address();
      baseUrl = `http://localhost:${port}`;
      resolve();
    });
  });

  const reg = await request('POST', '/register', {
    client_name: 'Integration Test Client',
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

test('valid authorization code is exchanged for tokens', async () => {
  const verifier = generateCodeVerifier();
  const code = await obtainAuthorizationCode(verifier);
  assert.ok(code, 'expected an authorization code from the consent redirect');

  const resp = await request('POST', '/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier
  }, { Authorization: basicAuth });

  assert.strictEqual(resp.status, 200);
  assert.ok(resp.body.access_token, 'access_token present');
  assert.ok(resp.body.refresh_token, 'refresh_token present');
  assert.strictEqual(resp.body.token_type, 'Bearer');
  assert.strictEqual(resp.body.scope, 'openid profile');
});

test('invalid authorization code is rejected with invalid_grant', async () => {
  const resp = await request('POST', '/token', {
    grant_type: 'authorization_code',
    code: 'totally-invalid-code',
    redirect_uri: REDIRECT_URI,
    code_verifier: generateCodeVerifier()
  }, { Authorization: basicAuth });

  assert.strictEqual(resp.status, 400);
  assert.strictEqual(resp.body.error, 'invalid_grant');
  assert.strictEqual(resp.body.error_description, 'Invalid authorization code');
});

test('the same authorization code cannot be used twice', async () => {
  const verifier = generateCodeVerifier();
  const code = await obtainAuthorizationCode(verifier);
  assert.ok(code);

  const first = await request('POST', '/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier
  }, { Authorization: basicAuth });
  assert.strictEqual(first.status, 200, 'first exchange succeeds');

  const second = await request('POST', '/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier
  }, { Authorization: basicAuth });
  assert.strictEqual(second.status, 400, 'replay is rejected');
  assert.strictEqual(second.body.error, 'invalid_grant');
  assert.strictEqual(second.body.error_description, 'Authorization code has already been used');
});
