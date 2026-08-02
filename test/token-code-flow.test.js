const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const crypto = require('crypto');

process.env.DB_PATH = ':memory:';

const { createConfig } = require('../src/config');
const config = createConfig();

const app = require('../src/server');

let server;
let baseUrl;

function request(method, path, data, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, baseUrl);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method,
      headers
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
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          body = JSON.parse(body);
        } catch (e) {}
        resolve({ status: res.statusCode, headers: res.headers, body });
      });
    });
    req.on('error', reject);
    if (data && (method === 'POST' || method === 'PUT')) req.write(data);
    req.end();
  });
}

test.before(async () => {
  await new Promise((resolve) => {
    server = app.listen(0, () => {
      baseUrl = `http://localhost:${server.address().port}`;
      resolve();
    });
  });
});

test.after(() => server.close());

async function registerClient() {
  const res = await request('POST', '/register', {
    client_name: 'Integration Test Client',
    client_type: 'confidential',
    redirect_uris: ['http://localhost:8080/callback'],
    grant_types: ['authorization_code', 'refresh_token']
  }, { 'Content-Type': 'application/json' });
  assert.strictEqual(res.status, 201);
  return res.body;
}

async function obtainCode(client) {
  const verifier = crypto.randomBytes(32).toString('hex');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');

  const consent = await request('POST', '/authorize/consent', {
    client_id: client.client_id,
    redirect_uri: 'http://localhost:8080/callback',
    response_type: 'code',
    scope: 'openid profile email',
    state: 'integration-state',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    username: 'alice',
    action: 'allow'
  });

  assert.strictEqual(consent.status, 302);
  const location = consent.headers.location;
  const code = new URL(location).searchParams.get('code');
  assert.ok(code);
  return { code, verifier };
}

function exchangeCode(client, code, verifier) {
  const basicAuth = 'Basic ' + Buffer.from(client.client_id + ':' + client.client_secret).toString('base64');
  return request('POST', '/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: 'http://localhost:8080/callback',
    code_verifier: verifier
  }, { Authorization: basicAuth });
}

test('集成：code 正常换取 token', async () => {
  const client = await registerClient();
  const { code, verifier } = await obtainCode(client);

  const tokenRes = await exchangeCode(client, code, verifier);
  assert.strictEqual(tokenRes.status, 200);
  assert.ok(tokenRes.body.access_token);
  assert.ok(tokenRes.body.refresh_token);
  assert.strictEqual(tokenRes.body.token_type, 'Bearer');
  assert.strictEqual(tokenRes.body.expires_in, config.accessTokenTTL);
  assert.strictEqual(tokenRes.body.scope, 'openid profile email');
});

test('集成：无效 code 被拒绝', async () => {
  const client = await registerClient();

  const tokenRes = await exchangeCode(client, 'not-a-real-code', 'whatever');
  assert.strictEqual(tokenRes.status, 400);
  assert.strictEqual(tokenRes.body.error, 'invalid_grant');
  assert.strictEqual(tokenRes.body.error_description, 'Invalid authorization code');
});

test('集成：同一 code 不能重复使用', async () => {
  const client = await registerClient();
  const { code, verifier } = await obtainCode(client);

  const first = await exchangeCode(client, code, verifier);
  assert.strictEqual(first.status, 200);
  assert.ok(first.body.access_token);

  const replay = await exchangeCode(client, code, verifier);
  assert.strictEqual(replay.status, 400);
  assert.strictEqual(replay.body.error, 'invalid_grant');
  assert.strictEqual(replay.body.error_description, 'Authorization code has already been used');
});
