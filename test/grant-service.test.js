const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');

// Use an isolated temp database so unit tests never touch the dev data/auth.db.
const tmpDb = path.join(os.tmpdir(), `grant-service-unit-${process.pid}.db`);
const { loadConfig, configureModules } = require('../src/server');
configureModules(loadConfig({ dbPath: tmpDb }));

const { initDatabase, getDb } = require('../src/db');
const { generateCodeChallenge } = require('../src/pkce');
const {
  issueAuthorizationCode,
  findAuthorizationCode,
  consumeAuthorizationCode
} = require('../src/grantService');

initDatabase();

// A user row is required because authorization_codes.user_id references users(id).
const testUserId = getDb()
  .prepare('SELECT id FROM users WHERE username = ?')
  .get('alice').id;

const CLIENT_ID = 'client_unit_test';
const REDIRECT_URI = 'http://localhost:8080/callback';
const SCOPE = 'openid profile';

function freshCode() {
  const verifier = crypto.randomBytes(32).toString('hex');
  const challenge = generateCodeChallenge(verifier);
  const code = issueAuthorizationCode(
    CLIENT_ID,
    testUserId,
    REDIRECT_URI,
    SCOPE,
    challenge,
    'S256',
    600
  );
  return { code, verifier, challenge };
}

test.after(() => {
  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(tmpDb + suffix); } catch (e) {}
  }
});

test('issueAuthorizationCode persists a retrievable code', () => {
  const { code } = freshCode();
  const record = findAuthorizationCode(code);
  assert.ok(record, 'code should be found');
  assert.strictEqual(record.client_id, CLIENT_ID);
  assert.strictEqual(record.redirect_uri, REDIRECT_URI);
  assert.strictEqual(record.used, 0);
});

test('findAuthorizationCode returns null for unknown code', () => {
  assert.strictEqual(findAuthorizationCode('does-not-exist'), null);
});

test('consumeAuthorizationCode succeeds and marks the code used', () => {
  const { code, verifier } = freshCode();
  const result = consumeAuthorizationCode({
    code,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    codeVerifier: verifier
  });
  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.authCode.code, code);
  assert.strictEqual(findAuthorizationCode(code).used, 1);
});

test('consumeAuthorizationCode rejects an unknown code with invalid_grant', () => {
  const result = consumeAuthorizationCode({
    code: 'no-such-code',
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    codeVerifier: 'whatever'
  });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.status, 400);
  assert.strictEqual(result.error, 'invalid_grant');
  assert.strictEqual(result.error_description, 'Invalid authorization code');
});

test('consumeAuthorizationCode rejects reuse of the same code', () => {
  const { code, verifier } = freshCode();
  const first = consumeAuthorizationCode({
    code,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    codeVerifier: verifier
  });
  assert.strictEqual(first.ok, true);

  const second = consumeAuthorizationCode({
    code,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    codeVerifier: verifier
  });
  assert.strictEqual(second.ok, false);
  assert.strictEqual(second.error, 'invalid_grant');
  assert.strictEqual(second.error_description, 'Authorization code has already been used');
});

test('consumeAuthorizationCode rejects a client mismatch', () => {
  const { code, verifier } = freshCode();
  const result = consumeAuthorizationCode({
    code,
    clientId: 'some_other_client',
    redirectUri: REDIRECT_URI,
    codeVerifier: verifier
  });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.error, 'invalid_grant');
  assert.strictEqual(result.error_description, 'Authorization code was not issued to this client');
});

test('consumeAuthorizationCode rejects a redirect_uri mismatch', () => {
  const { code, verifier } = freshCode();
  const result = consumeAuthorizationCode({
    code,
    clientId: CLIENT_ID,
    redirectUri: 'http://localhost:8080/other',
    codeVerifier: verifier
  });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.error, 'invalid_grant');
  assert.strictEqual(result.error_description, 'redirect_uri does not match');
});

test('consumeAuthorizationCode rejects a bad PKCE verifier', () => {
  const { code } = freshCode();
  const result = consumeAuthorizationCode({
    code,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    codeVerifier: 'wrong-verifier'
  });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.error, 'invalid_grant');
  assert.strictEqual(result.error_description, 'PKCE verification failed');
});

test('consumeAuthorizationCode rejects an expired code', () => {
  const verifier = crypto.randomBytes(32).toString('hex');
  const challenge = generateCodeChallenge(verifier);
  // ttl = -10 => already expired
  const code = issueAuthorizationCode(
    CLIENT_ID, testUserId, REDIRECT_URI, SCOPE, challenge, 'S256', -10
  );
  const result = consumeAuthorizationCode({
    code,
    clientId: CLIENT_ID,
    redirectUri: REDIRECT_URI,
    codeVerifier: verifier
  });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.error, 'invalid_grant');
  assert.strictEqual(result.error_description, 'Authorization code has expired');
});
