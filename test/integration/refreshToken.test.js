const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const {
  createTestConfig,
  startTestApp,
  stopTestApp,
  request,
  basicAuthHeader
} = require('../helpers/testApp');

const REDIRECT_URI = 'http://localhost:8080/callback';
const SCOPE = 'openid profile email';

function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('hex');
}

function generateCodeChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

async function registerConfidentialClient(server) {
  const res = await request(server, 'POST', '/register', {
    client_name: 'Refresh Integration Client',
    client_type: 'confidential',
    redirect_uris: [REDIRECT_URI],
    grant_types: ['authorization_code', 'refresh_token'],
    allowed_scopes: ['openid', 'profile', 'email']
  }, { 'Content-Type': 'application/json' });

  assert.equal(res.status, 201, `client registration failed: ${JSON.stringify(res.body)}`);
  return res.body;
}

async function obtainAuthorizationCode(server, client, codeChallenge) {
  const state = 'state-' + crypto.randomBytes(6).toString('hex');

  await request(server, 'POST', '/authorize', new URLSearchParams({
    client_id: client.client_id,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: SCOPE,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    username: 'alice',
    password: 'password123'
  }).toString(), { 'Content-Type': 'application/x-www-form-urlencoded' });

  const consent = await request(server, 'POST', '/authorize/consent', new URLSearchParams({
    client_id: client.client_id,
    redirect_uri: REDIRECT_URI,
    response_type: 'code',
    scope: SCOPE,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    username: 'alice',
    action: 'allow'
  }).toString(), { 'Content-Type': 'application/x-www-form-urlencoded' });

  assert.equal(consent.status, 302, `consent failed: status=${consent.status}`);
  const location = new URL(consent.headers.location, REDIRECT_URI);
  const code = location.searchParams.get('code');
  assert.ok(code, 'expected code in redirect location');
  return code;
}

async function exchangeCodeForTokens(server, client) {
  const verifier = generateCodeVerifier();
  const challenge = generateCodeChallenge(verifier);
  const code = await obtainAuthorizationCode(server, client, challenge);

  const tokenRes = await request(server, 'POST', '/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier
  }, { Authorization: basicAuthHeader(client) });

  assert.equal(tokenRes.status, 200, `code exchange failed: ${JSON.stringify(tokenRes.body)}`);
  return tokenRes.body;
}

test('refresh token is issued alongside access token on code exchange', async (t) => {
  const config = createTestConfig();
  const { server } = await startTestApp(config);
  t.after(() => stopTestApp(server));

  const client = await registerConfidentialClient(server);
  const tokens = await exchangeCodeForTokens(server, client);

  assert.equal(typeof tokens.access_token, 'string');
  assert.ok(tokens.access_token.split('.').length === 3, 'access token must be a JWT');
  assert.equal(typeof tokens.refresh_token, 'string');
  assert.ok(tokens.refresh_token.startsWith('refresh_'));
  assert.equal(tokens.token_type, 'Bearer');
  assert.equal(tokens.expires_in, 3600);
  assert.equal(tokens.scope, SCOPE);
});

test('valid refresh token is rotated into a new token pair and the old one is invalidated', async (t) => {
  const config = createTestConfig();
  const { server } = await startTestApp(config);
  t.after(() => stopTestApp(server));

  const client = await registerConfidentialClient(server);
  const firstTokens = await exchangeCodeForTokens(server, client);

  const rotationRes = await request(server, 'POST', '/token', {
    grant_type: 'refresh_token',
    refresh_token: firstTokens.refresh_token
  }, { Authorization: basicAuthHeader(client) });

  assert.equal(rotationRes.status, 200, `rotation failed: ${JSON.stringify(rotationRes.body)}`);
  assert.equal(rotationRes.body.token_type, 'Bearer');
  assert.equal(rotationRes.body.scope, SCOPE);
  assert.equal(typeof rotationRes.body.access_token, 'string');
  assert.equal(typeof rotationRes.body.refresh_token, 'string');
  assert.notEqual(rotationRes.body.access_token, firstTokens.access_token, 'access token must rotate');
  assert.notEqual(rotationRes.body.refresh_token, firstTokens.refresh_token, 'refresh token must rotate');

  const introspectOld = await request(server, 'POST', '/introspect', {
    token: firstTokens.refresh_token,
    token_type_hint: 'refresh_token'
  }, { Authorization: basicAuthHeader(client) });

  assert.equal(introspectOld.status, 200);
  assert.equal(introspectOld.body.active, false, 'old refresh token must be revoked after rotation');

  const introspectNew = await request(server, 'POST', '/introspect', {
    token: rotationRes.body.refresh_token,
    token_type_hint: 'refresh_token'
  }, { Authorization: basicAuthHeader(client) });

  assert.equal(introspectNew.status, 200);
  assert.equal(introspectNew.body.active, true, 'new refresh token must be active');
});

test('a previously used refresh token cannot be reused to obtain new tokens', async (t) => {
  const config = createTestConfig();
  const { server } = await startTestApp(config);
  t.after(() => stopTestApp(server));

  const client = await registerConfidentialClient(server);
  const firstTokens = await exchangeCodeForTokens(server, client);

  const firstRotation = await request(server, 'POST', '/token', {
    grant_type: 'refresh_token',
    refresh_token: firstTokens.refresh_token
  }, { Authorization: basicAuthHeader(client) });
  assert.equal(firstRotation.status, 200);

  const replay = await request(server, 'POST', '/token', {
    grant_type: 'refresh_token',
    refresh_token: firstTokens.refresh_token
  }, { Authorization: basicAuthHeader(client) });

  assert.equal(replay.status, 400);
  assert.equal(replay.body.error, 'invalid_grant');
  assert.match(replay.body.error_description, /revoked|already/i);
});

test('unknown/invalid refresh token is rejected with invalid_grant', async (t) => {
  const config = createTestConfig();
  const { server } = await startTestApp(config);
  t.after(() => stopTestApp(server));

  const client = await registerConfidentialClient(server);

  const res = await request(server, 'POST', '/token', {
    grant_type: 'refresh_token',
    refresh_token: 'refresh_does_not_exist_value'
  }, { Authorization: basicAuthHeader(client) });

  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'invalid_grant');
  assert.match(res.body.error_description, /Invalid refresh token/);
});

test('refresh token issued to another client is rejected', async (t) => {
  const config = createTestConfig();
  const { server } = await startTestApp(config);
  t.after(() => stopTestApp(server));

  const clientA = await registerConfidentialClient(server);
  const clientB = await registerConfidentialClient(server);
  const tokens = await exchangeCodeForTokens(server, clientA);

  const res = await request(server, 'POST', '/token', {
    grant_type: 'refresh_token',
    refresh_token: tokens.refresh_token
  }, { Authorization: basicAuthHeader(clientB) });

  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'invalid_grant');
});
