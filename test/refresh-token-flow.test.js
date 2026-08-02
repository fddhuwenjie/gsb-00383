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

function basicAuth(client) {
  return 'Basic ' + Buffer.from(client.client_id + ':' + client.client_secret).toString('base64');
}

async function issueRefreshToken() {
  const reg = await request('POST', '/register', {
    client_name: 'Refresh Flow Test Client',
    client_type: 'confidential',
    redirect_uris: ['http://localhost:8080/callback'],
    grant_types: ['authorization_code', 'refresh_token']
  }, { 'Content-Type': 'application/json' });
  assert.strictEqual(reg.status, 201);
  const client = reg.body;

  const verifier = crypto.randomBytes(32).toString('hex');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  const consent = await request('POST', '/authorize/consent', {
    client_id: client.client_id,
    redirect_uri: 'http://localhost:8080/callback',
    response_type: 'code',
    scope: 'openid profile email',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    username: 'alice',
    action: 'allow'
  });
  assert.strictEqual(consent.status, 302);
  const code = new URL(consent.headers.location).searchParams.get('code');

  const tokenRes = await request('POST', '/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: 'http://localhost:8080/callback',
    code_verifier: verifier
  }, { Authorization: basicAuth(client) });
  assert.strictEqual(tokenRes.status, 200);

  return { client, tokens: tokenRes.body };
}

function refresh(client, refreshToken) {
  return request('POST', '/token', {
    grant_type: 'refresh_token',
    refresh_token: refreshToken
  }, { Authorization: basicAuth(client) });
}

test('集成：refresh token 正常签发', async () => {
  const { tokens } = await issueRefreshToken();

  assert.ok(tokens.refresh_token);
  assert.ok(tokens.refresh_token.startsWith('refresh_'));
  assert.ok(tokens.access_token);
  assert.strictEqual(tokens.token_type, 'Bearer');
  assert.strictEqual(tokens.expires_in, config.accessTokenTTL);
  assert.strictEqual(tokens.scope, 'openid profile email');
});

test('集成：refresh token 成功轮换', async () => {
  const { client, tokens } = await issueRefreshToken();

  const rotated = await refresh(client, tokens.refresh_token);
  assert.strictEqual(rotated.status, 200);
  assert.ok(rotated.body.access_token);
  assert.ok(rotated.body.refresh_token);
  assert.notStrictEqual(rotated.body.refresh_token, tokens.refresh_token);
  assert.strictEqual(rotated.body.token_type, 'Bearer');
  assert.strictEqual(rotated.body.expires_in, config.accessTokenTTL);
  assert.strictEqual(rotated.body.scope, 'openid profile email');
});

test('集成：轮换后旧 refresh token 再次使用被拒绝', async () => {
  const { client, tokens } = await issueRefreshToken();

  const rotated = await refresh(client, tokens.refresh_token);
  assert.strictEqual(rotated.status, 200);

  const replay = await refresh(client, tokens.refresh_token);
  assert.strictEqual(replay.status, 400);
  assert.strictEqual(replay.body.error, 'invalid_grant');
  assert.strictEqual(replay.body.error_description, 'Refresh token has been revoked');
});
