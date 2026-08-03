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
const ADMIN_KEY = 'test-admin-key-' + crypto.randomBytes(8).toString('hex');

function verifierChallenge() {
  const verifier = crypto.randomBytes(32).toString('hex');
  return { verifier, challenge: crypto.createHash('sha256').update(verifier).digest('base64url') };
}

async function registerClient(server) {
  const res = await request(server, 'POST', '/register', {
    client_name: 'Admin Events Client',
    client_type: 'confidential',
    redirect_uris: [REDIRECT_URI],
    grant_types: ['authorization_code', 'refresh_token'],
    allowed_scopes: ['openid', 'profile', 'email']
  }, { 'Content-Type': 'application/json' });
  assert.equal(res.status, 201);
  return res.body;
}

async function getCode(server, client, challenge) {
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

  return new URL(consent.headers.location, REDIRECT_URI).searchParams.get('code');
}

test('admin events endpoint requires authentication', async (t) => {
  const config = createTestConfig({ adminApiKey: ADMIN_KEY });
  const { server } = await startTestApp(config);
  t.after(() => stopTestApp(server));

  const noAuth = await request(server, 'GET', '/admin/events');
  assert.equal(noAuth.status, 401);
  assert.equal(noAuth.body.error, 'invalid_token');

  const wrongAuth = await request(server, 'GET', '/admin/events', null, {
    Authorization: 'Bearer wrong-key'
  });
  assert.equal(wrongAuth.status, 401);
});

test('admin events endpoint is disabled when ADMIN_API_KEY is not configured', async (t) => {
  const config = createTestConfig({ adminApiKey: null });
  const { server } = await startTestApp(config);
  t.after(() => stopTestApp(server));

  const res = await request(server, 'GET', '/admin/events', null, {
    Authorization: 'Bearer anything'
  });
  assert.equal(res.status, 503);
  assert.equal(res.body.error, 'admin_disabled');
});

test('admin events lists events and supports event_type filter', async (t) => {
  const config = createTestConfig({ adminApiKey: ADMIN_KEY });
  const { server } = await startTestApp(config);
  t.after(() => stopTestApp(server));

  const client = await registerClient(server);
  const { verifier, challenge } = verifierChallenge();
  const code = await getCode(server, client, challenge);

  const tokenRes = await request(server, 'POST', '/token', {
    grant_type: 'authorization_code', code, redirect_uri: REDIRECT_URI, code_verifier: verifier
  }, { Authorization: basicAuthHeader(client) });
  assert.equal(tokenRes.status, 200);
  const refreshToken = tokenRes.body.refresh_token;

  const rotation = await request(server, 'POST', '/token', {
    grant_type: 'refresh_token', refresh_token: refreshToken
  }, { Authorization: basicAuthHeader(client) });
  assert.equal(rotation.status, 200);

  const rejected = await request(server, 'POST', '/token', {
    grant_type: 'refresh_token', refresh_token: 'refresh_does_not_exist'
  }, { Authorization: basicAuthHeader(client) });
  assert.equal(rejected.status, 400);

  const adminHeaders = { Authorization: 'Bearer ' + ADMIN_KEY };

  const all = await request(server, 'GET', '/admin/events', null, adminHeaders);
  assert.equal(all.status, 200);
  assert.ok(Array.isArray(all.body.events));
  assert.ok(all.body.events.length >= 3);

  const consumed = await request(
    server, 'GET', '/admin/events?event_type=authorization_code_consumed', null, adminHeaders
  );
  assert.equal(consumed.status, 200);
  assert.ok(consumed.body.events.length >= 1);
  assert.ok(consumed.body.events.every(e => e.event_type === 'authorization_code_consumed'));

  const rotated = await request(
    server, 'GET', '/admin/events?event_type=refresh_token_rotated', null, adminHeaders
  );
  assert.equal(rotated.body.events.length >= 1, true);
  assert.ok(rotated.body.events.every(e => e.event_type === 'refresh_token_rotated'));

  const rejectedEvents = await request(
    server, 'GET', '/admin/events?event_type=invalid_token_rejected', null, adminHeaders
  );
  assert.ok(rejectedEvents.body.events.length >= 1);
  assert.ok(rejectedEvents.body.events.every(e => e.event_type === 'invalid_token_rejected'));

  for (const event of all.body.events) {
    assert.deepEqual(Object.keys(event).sort(), ['event_type', 'id', 'occurred_at']);
    assert.equal(typeof event.id, 'number');
    assert.equal(typeof event.occurred_at, 'number');
  }

  const serialized = JSON.stringify(all.body.events);
  assert.ok(!serialized.includes(code), 'authorization code leaked to admin events');
  assert.ok(!serialized.includes(refreshToken), 'refresh token leaked to admin events');
  assert.ok(!serialized.includes(tokenRes.body.access_token), 'access token leaked to admin events');
  assert.ok(!serialized.includes(challenge), 'PKCE challenge leaked to admin events');
});

test('admin events rejects unknown event_type and non-numeric limit', async (t) => {
  const config = createTestConfig({ adminApiKey: ADMIN_KEY });
  const { server } = await startTestApp(config);
  t.after(() => stopTestApp(server));

  const headers = { Authorization: 'Bearer ' + ADMIN_KEY };
  const badType = await request(server, 'GET', '/admin/events?event_type=unknown', null, headers);
  assert.equal(badType.status, 400);
  assert.equal(badType.body.error, 'invalid_request');

  const badLimit = await request(server, 'GET', '/admin/events?limit=abc', null, headers);
  assert.equal(badLimit.status, 400);
});
