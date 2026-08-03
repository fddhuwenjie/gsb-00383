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
    client_name: 'Integration Confidential Client',
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
  assert.equal(location.searchParams.get('state'), state);
  return code;
}

test('integration setup: starts server and registers confidential client', async (t) => {
  const config = createTestConfig();
  const { server } = await startTestApp(config);
  t.after(() => stopTestApp(server));

  const client = await registerConfidentialClient(server);
  assert.ok(client.client_id);
  assert.ok(client.client_secret);
});

test('valid authorization code can be exchanged for access and refresh tokens', async (t) => {
  const config = createTestConfig();
  const { server } = await startTestApp(config);
  t.after(() => stopTestApp(server));

  const client = await registerConfidentialClient(server);
  const verifier = generateCodeVerifier();
  const challenge = generateCodeChallenge(verifier);
  const code = await obtainAuthorizationCode(server, client, challenge);

  const tokenRes = await request(server, 'POST', '/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier
  }, { Authorization: basicAuthHeader(client) });

  assert.equal(tokenRes.status, 200, `token exchange failed: ${JSON.stringify(tokenRes.body)}`);
  assert.equal(tokenRes.body.token_type, 'Bearer');
  assert.equal(tokenRes.body.scope, SCOPE);
  assert.equal(typeof tokenRes.body.access_token, 'string');
  assert.ok(tokenRes.body.access_token.split('.').length === 3, 'access token should be a JWT');
  assert.equal(typeof tokenRes.body.refresh_token, 'string');
  assert.equal(tokenRes.body.expires_in, 3600);

  const parts = tokenRes.body.access_token.split('.');
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  assert.equal(payload.client_id, client.client_id);
  assert.equal(payload.scope, SCOPE);
  assert.ok(payload.sub, 'JWT must contain sub claim');
  assert.equal(payload.name, 'Alice Smith');
  assert.equal(payload.email, 'alice@example.com');
  assert.equal(payload.iss, config.issuer);
});

test('invalid/unknown authorization code is rejected with invalid_grant', async (t) => {
  const config = createTestConfig();
  const { server } = await startTestApp(config);
  t.after(() => stopTestApp(server));

  const client = await registerConfidentialClient(server);
  const verifier = generateCodeVerifier();

  const tokenRes = await request(server, 'POST', '/token', {
    grant_type: 'authorization_code',
    code: '00000000-0000-0000-0000-000000000000',
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier
  }, { Authorization: basicAuthHeader(client) });

  assert.equal(tokenRes.status, 400);
  assert.equal(tokenRes.body.error, 'invalid_grant');
  assert.match(tokenRes.body.error_description, /Invalid authorization code/);
});

test('same authorization code cannot be used more than once', async (t) => {
  const config = createTestConfig();
  const { server } = await startTestApp(config);
  t.after(() => stopTestApp(server));

  const client = await registerConfidentialClient(server);
  const verifier = generateCodeVerifier();
  const challenge = generateCodeChallenge(verifier);
  const code = await obtainAuthorizationCode(server, client, challenge);

  const first = await request(server, 'POST', '/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier
  }, { Authorization: basicAuthHeader(client) });

  assert.equal(first.status, 200, `first exchange failed: ${JSON.stringify(first.body)}`);
  assert.ok(first.body.access_token);

  const replay = await request(server, 'POST', '/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier
  }, { Authorization: basicAuthHeader(client) });

  assert.equal(replay.status, 400);
  assert.equal(replay.body.error, 'invalid_grant');
  assert.match(replay.body.error_description, /already been used/);
});

test('authorization code is rejected when PKCE verifier is wrong', async (t) => {
  const config = createTestConfig();
  const { server } = await startTestApp(config);
  t.after(() => stopTestApp(server));

  const client = await registerConfidentialClient(server);
  const verifier = generateCodeVerifier();
  const challenge = generateCodeChallenge(verifier);
  const code = await obtainAuthorizationCode(server, client, challenge);

  const wrongVerifier = generateCodeVerifier();
  const res = await request(server, 'POST', '/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: wrongVerifier
  }, { Authorization: basicAuthHeader(client) });

  assert.equal(res.status, 400);
  assert.equal(res.body.error, 'invalid_grant');
  assert.match(res.body.error_description, /PKCE verification failed/);
});
