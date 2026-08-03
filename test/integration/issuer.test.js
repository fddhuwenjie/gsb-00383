const test = require('node:test');
const assert = require('node:assert/strict');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { buildConfig, defaults } = require('../../src/config');
const { createApp } = require('../../src/server');
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
    client_name: 'Issuer Test Client',
    client_type: 'confidential',
    redirect_uris: [REDIRECT_URI],
    grant_types: ['authorization_code', 'refresh_token'],
    allowed_scopes: ['openid', 'profile', 'email']
  }, { 'Content-Type': 'application/json' });
  assert.equal(res.status, 201);
  return res.body;
}

async function obtainAuthorizationCode(server, client, challenge) {
  const state = 's-' + crypto.randomBytes(4).toString('hex');
  await request(server, 'POST', '/authorize', new URLSearchParams({
    client_id: client.client_id, redirect_uri: REDIRECT_URI, response_type: 'code',
    scope: SCOPE, state, code_challenge: challenge, code_challenge_method: 'S256',
    username: 'alice', password: 'password123'
  }).toString(), { 'Content-Type': 'application/x-www-form-urlencoded' });

  const consent = await request(server, 'POST', '/authorize/consent', new URLSearchParams({
    client_id: client.client_id, redirect_uri: REDIRECT_URI, response_type: 'code',
    scope: SCOPE, state, code_challenge: challenge, code_challenge_method: 'S256',
    username: 'alice', action: 'allow'
  }).toString(), { 'Content-Type': 'application/x-www-form-urlencoded' });

  assert.equal(consent.status, 302);
  return new URL(consent.headers.location, REDIRECT_URI).searchParams.get('code');
}

test('discovery issuer and signed JWT issuer equal the actual listening address', async (t) => {
  const config = createTestConfig();
  const { server } = await startTestApp(config);
  t.after(() => stopTestApp(server));

  const disc = await request(server, 'GET', '/.well-known/openid-configuration');
  assert.equal(disc.status, 200);
  assert.equal(disc.body.issuer, config.issuer);
  assert.equal(disc.body.authorization_endpoint, `${config.issuer}/authorize`);

  const client = await registerConfidentialClient(server);
  const verifier = generateCodeVerifier();
  const challenge = generateCodeChallenge(verifier);
  const code = await obtainAuthorizationCode(server, client, challenge);

  const tokenRes = await request(server, 'POST', '/token', {
    grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, code_verifier: verifier
  }, { Authorization: basicAuthHeader(client) });
  assert.equal(tokenRes.status, 200);

  const parts = tokenRes.body.access_token.split('.');
  const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  assert.equal(payload.iss, config.issuer);
});

test('a token signed by another issuer is rejected when verified against a different issuer', async (t) => {
  const configA = createTestConfig({ issuer: 'http://issuer-a.example' });
  const appA = await startTestApp(configA);
  t.after(() => stopTestApp(appA.server));

  const configB = createTestConfig({ issuer: 'http://issuer-b.example' });
  const appB = await startTestApp(configB);
  t.after(() => stopTestApp(appB.server));

  const clientA = await registerConfidentialClient(appA.server);
  const verifier = generateCodeVerifier();
  const challenge = generateCodeChallenge(verifier);
  const code = await obtainAuthorizationCode(appA.server, clientA, challenge);

  const tokenRes = await request(appA.server, 'POST', '/token', {
    grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, code_verifier: verifier
  }, { Authorization: basicAuthHeader(clientA) });
  assert.equal(tokenRes.status, 200);
  const accessToken = tokenRes.body.access_token;

  const payload = JSON.parse(Buffer.from(accessToken.split('.')[1], 'base64url').toString());
  assert.equal(payload.iss, 'http://issuer-a.example');

  const userInfo = await request(appB.server, 'GET', '/userinfo', null, {
    Authorization: 'Bearer ' + accessToken
  });
  assert.equal(userInfo.status, 401);
  assert.equal(userInfo.body.error, 'invalid_token');
  assert.match(userInfo.body.error_description, /iss/i);
});

test('createApp throws when issuer is not configured', async (t) => {
  const cfg = buildConfig({
    ...defaults,
    port: 0,
    host: '127.0.0.1',
    dbPath: path.join(os.tmpdir(), 'never-created-' + crypto.randomBytes(4).toString('hex') + '.db'),
    issuer: null
  });
  assert.throws(() => createApp(cfg), /issuer/);
});
