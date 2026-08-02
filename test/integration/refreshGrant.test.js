const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const {
  startTestServer,
  seedConfidentialClient,
  pkcePair,
  REDIRECT_URI
} = require('../helpers/setup');

let baseUrl;
let client;
let basicAuth;
let stopServer;

test.before(async () => {
  const ctx = await startTestServer();
  baseUrl = ctx.baseUrl;
  stopServer = ctx.close;
  client = seedConfidentialClient();
  basicAuth = 'Basic ' + Buffer.from(client.client_id + ':' + client.client_secret).toString('base64');
});

test.after(async () => {
  if (stopServer) await stopServer();
});

function request(method, path, data, headers = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(path, baseUrl);
    const options = {
      hostname: u.hostname,
      port: u.port,
      path: u.pathname + u.search,
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
        let parsed = body;
        try {
          parsed = JSON.parse(body);
        } catch (e) {}
        resolve({ status: res.statusCode, headers: res.headers, body: parsed });
      });
    });

    req.on('error', reject);

    if (data && (method === 'POST' || method === 'PUT')) {
      req.write(data);
    }
    req.end();
  });
}

async function obtainTokens() {
  const { verifier, challenge } = pkcePair();
  const scope = 'openid profile email';
  const state = 'refresh-integration-state';

  await request('GET', '/authorize?' + new URLSearchParams({
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: REDIRECT_URI,
    scope,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256'
  }).toString());

  await request('POST', '/authorize', {
    client_id: client.client_id,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    username: 'alice',
    password: 'password123'
  });

  const consentResp = await request('POST', '/authorize/consent', {
    client_id: client.client_id,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    username: 'alice',
    action: 'allow'
  });

  const code = new URL(consentResp.headers.location, baseUrl).searchParams.get('code');
  assert.ok(code, 'authorization code should be present');

  const tokenResp = await request('POST', '/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier
  }, { Authorization: basicAuth });

  assert.equal(tokenResp.status, 200, () => `token exchange failed: ${JSON.stringify(tokenResp.body)}`);
  return tokenResp.body;
}

function refresh(refreshToken, extraHeaders = {}) {
  return request('POST', '/token', {
    grant_type: 'refresh_token',
    refresh_token: refreshToken
  }, { Authorization: basicAuth, ...extraHeaders });
}

function introspect(token) {
  return request('POST', '/introspect', {
    token,
    token_type_hint: 'refresh_token'
  }, { Authorization: basicAuth });
}

test('refresh integration: a refresh token is normally issued alongside the access token', async () => {
  const tokens = await obtainTokens();

  assert.equal(typeof tokens.access_token, 'string');
  assert.ok(tokens.access_token.length > 0, 'access_token should not be empty');
  assert.equal(tokens.token_type, 'Bearer');
  assert.equal(tokens.scope, 'openid profile email');

  assert.equal(typeof tokens.refresh_token, 'string', 'refresh_token should be returned');
  assert.ok(tokens.refresh_token.startsWith('refresh_'), 'refresh_token should use the refresh_ prefix');
  assert.notEqual(tokens.refresh_token, tokens.access_token, 'refresh and access tokens must differ');

  const introspection = await introspect(tokens.refresh_token);
  assert.equal(introspection.status, 200);
  assert.equal(introspection.body.active, true, 'freshly issued refresh token should be active');
});

test('refresh integration: successful rotation issues new tokens and invalidates the old refresh token', async () => {
  const tokens = await obtainTokens();
  const oldRefreshToken = tokens.refresh_token;

  const rotated = await refresh(oldRefreshToken);

  assert.equal(rotated.status, 200, () => `rotation failed: ${JSON.stringify(rotated.body)}`);
  assert.equal(typeof rotated.body.access_token, 'string');
  assert.equal(rotated.body.token_type, 'Bearer');
  assert.equal(rotated.body.scope, 'openid profile email');
  assert.equal(typeof rotated.body.refresh_token, 'string');
  assert.notEqual(rotated.body.refresh_token, oldRefreshToken, 'a new refresh token must be issued');

  const oldIntrospection = await introspect(oldRefreshToken);
  assert.equal(oldIntrospection.body.active, false, 'old refresh token must be inactive after rotation');

  const newIntrospection = await introspect(rotated.body.refresh_token);
  assert.equal(newIntrospection.body.active, true, 'new refresh token should be active');
});

test('refresh integration: reusing an already rotated refresh token is rejected', async () => {
  const tokens = await obtainTokens();
  const oldRefreshToken = tokens.refresh_token;

  const rotated = await refresh(oldRefreshToken);
  assert.equal(rotated.status, 200, () => `first rotation should succeed: ${JSON.stringify(rotated.body)}`);

  const replay = await refresh(oldRefreshToken);

  assert.equal(replay.status, 400);
  assert.equal(replay.body.error, 'invalid_grant');
  assert.equal(replay.body.error_description, 'Refresh token has been revoked');
  assert.equal(replay.body.access_token, undefined, 'no access token must be issued on replay');
  assert.equal(replay.body.refresh_token, undefined, 'no refresh token must be issued on replay');
});
