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

async function obtainAuthorizationCode(challenge) {
  const scope = 'openid profile email';
  const state = 'integration-state';

  const loginPage = await request('GET', '/authorize?' + new URLSearchParams({
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: REDIRECT_URI,
    scope,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256'
  }).toString());
  assert.equal(loginPage.status, 200);

  const loginResp = await request('POST', '/authorize', {
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
  assert.equal(loginResp.status, 200);

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
  assert.equal(consentResp.status, 302);

  const location = consentResp.headers.location;
  assert.ok(location, 'consent should redirect with a Location header');
  const code = new URL(location, baseUrl).searchParams.get('code');
  const returnedState = new URL(location, baseUrl).searchParams.get('state');
  assert.ok(code, 'redirect should contain a code');
  assert.equal(returnedState, state, 'state should be echoed back');
  return code;
}

function exchangeCode(code, verifier, extraHeaders = {}) {
  return request('POST', '/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: verifier
  }, { Authorization: basicAuth, ...extraHeaders });
}

test('integration: a valid authorization code can be exchanged for tokens', async () => {
  const { verifier, challenge } = pkcePair();
  const code = await obtainAuthorizationCode(challenge);

  const resp = await exchangeCode(code, verifier);

  assert.equal(resp.status, 200, () => `expected 200 but got ${resp.status}: ${JSON.stringify(resp.body)}`);
  assert.equal(typeof resp.body.access_token, 'string', 'access_token should be a string');
  assert.ok(resp.body.access_token.length > 0, 'access_token should not be empty');
  assert.equal(resp.body.token_type, 'Bearer');
  assert.equal(typeof resp.body.expires_in, 'number');
  assert.equal(resp.body.scope, 'openid profile email');
  assert.equal(typeof resp.body.refresh_token, 'string', 'refresh_token should be returned');
  assert.ok(resp.body.refresh_token.startsWith('refresh_'));
});

test('integration: an unknown authorization code is rejected with invalid_grant', async () => {
  const { verifier } = pkcePair();

  const resp = await exchangeCode('nonexistent-authorization-code', verifier);

  assert.equal(resp.status, 400);
  assert.equal(resp.body.error, 'invalid_grant');
  assert.equal(resp.body.error_description, 'Invalid authorization code');
  assert.equal(resp.body.access_token, undefined, 'no access token should be issued');
});

test('integration: the same authorization code cannot be used more than once', async () => {
  const { verifier, challenge } = pkcePair();
  const code = await obtainAuthorizationCode(challenge);

  const first = await exchangeCode(code, verifier);
  assert.equal(first.status, 200, () => `first exchange should succeed, got ${first.status}: ${JSON.stringify(first.body)}`);
  assert.ok(first.body.access_token);

  const replay = await exchangeCode(code, verifier);
  assert.equal(replay.status, 400);
  assert.equal(replay.body.error, 'invalid_grant');
  assert.equal(replay.body.error_description, 'Authorization code has already been used');
  assert.equal(replay.body.access_token, undefined, 'replay must not issue a new access token');
});
