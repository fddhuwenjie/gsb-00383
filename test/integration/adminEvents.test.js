const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const {
  startTestServer,
  seedConfidentialClient,
  grantService,
  TOKEN_EVENT_TYPES: SERVICE_TYPES
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

function request(method, path, headers = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(path, baseUrl);
    const options = {
      hostname: u.hostname,
      port: u.port,
      path: u.pathname + u.search,
      method,
      headers
    };
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
    req.end();
  });
}

test('admin events: requires client authentication', async () => {
  const resp = await request('GET', '/admin/events');
  assert.equal(resp.status, 401);
  assert.equal(resp.body.error, 'invalid_client');
});

test('admin events: rejects an invalid event_type filter', async () => {
  const resp = await request('GET', '/admin/events?event_type=not_a_real_type', {
    Authorization: basicAuth
  });
  assert.equal(resp.status, 400);
  assert.equal(resp.body.error, 'invalid_request');
});

test('admin events: returns events filtered by type in newest-first order', async () => {
  grantService.consumeAuthorizationCode({
    code: 'integration-invalid-code-' + Date.now(),
    clientId: client.client_id,
    redirectUri: 'http://localhost:8080/callback',
    codeVerifier: 'whatever'
  });

  const resp = await request('GET', '/admin/events?event_type=invalid_token_rejected', {
    Authorization: basicAuth
  });

  assert.equal(resp.status, 200);
  assert.ok(Array.isArray(resp.body.events), 'response should contain an events array');
  assert.ok(resp.body.events.length >= 1);
  assert.ok(resp.body.events.every(e => e.event_type === SERVICE_TYPES.INVALID_TOKEN_REJECTED));

  for (const event of resp.body.events) {
    assert.equal(typeof event.id, 'number');
    assert.equal(typeof event.created_at, 'number');
    assert.equal(typeof event.event_type, 'string');
    const keys = Object.keys(event).sort();
    assert.deepEqual(keys, ['created_at', 'event_type', 'id']);
  }

  for (let i = 1; i < resp.body.events.length; i++) {
    assert.ok(resp.body.events[i - 1].created_at >= resp.body.events[i].created_at);
  }
});

test('admin events: returns all known event types unfiltered', async () => {
  const types = new Set();
  const resp = await request('GET', '/admin/events', { Authorization: basicAuth });
  assert.equal(resp.status, 200);
  assert.ok(Array.isArray(resp.body.events));
  for (const event of resp.body.events) {
    types.add(event.event_type);
    const keys = Object.keys(event).sort();
    assert.deepEqual(keys, ['created_at', 'event_type', 'id']);
  }
  assert.ok(types.has(SERVICE_TYPES.INVALID_TOKEN_REJECTED));
});
