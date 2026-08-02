const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

const { createConfig } = require('../src/config');
const config = createConfig({ DB_PATH: ':memory:' });

require('../src/db').initDatabase(config);
require('../src/data').initData(config);
require('../src/services/grantService').initGrantService(config);

const {
  issueAuthorizationCode,
  findAuthorizationCode,
  consumeAuthorizationCode
} = require('../src/services/grantService');
const { getUserByUsername } = require('../src/data');

const client = {
  client_id: 'test-client',
  allowed_scopes: ['openid', 'profile', 'email']
};

function pkcePair() {
  const verifier = crypto.randomBytes(32).toString('hex');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

function makeCode(overrides = {}) {
  const user = getUserByUsername('alice');
  const { verifier, challenge } = pkcePair();
  const code = issueAuthorizationCode({
    clientId: overrides.clientId || client.client_id,
    userId: user.id,
    redirectUri: overrides.redirectUri || 'http://localhost:8080/callback',
    scope: overrides.scope || 'openid profile',
    codeChallenge: challenge,
    codeChallengeMethod: 'S256'
  });
  return { code, verifier };
}

test('issueAuthorizationCode 创建的记录可查询且字段正确', () => {
  const { code } = makeCode();
  assert.ok(code);

  const row = findAuthorizationCode(code);
  assert.ok(row);
  assert.strictEqual(row.client_id, client.client_id);
  assert.strictEqual(row.redirect_uri, 'http://localhost:8080/callback');
  assert.strictEqual(row.scope, 'openid profile');
  assert.strictEqual(row.code_challenge_method, 'S256');
  assert.strictEqual(row.used, 0);
  assert.ok(row.expires_at > Math.floor(Date.now() / 1000));
});

test('findAuthorizationCode 查询不存在的 code 返回 null', () => {
  assert.strictEqual(findAuthorizationCode('no-such-code'), null);
});

test('consumeAuthorizationCode 正常消费返回 authCode 与 user', () => {
  const { code, verifier } = makeCode();
  const result = consumeAuthorizationCode({
    code,
    redirectUri: 'http://localhost:8080/callback',
    codeVerifier: verifier,
    client
  });

  assert.strictEqual(result.ok, true);
  assert.strictEqual(result.authCode.code, code);
  assert.strictEqual(result.user.username, 'alice');
  assert.strictEqual(findAuthorizationCode(code).used, 1);
});

test('consumeAuthorizationCode 拒绝不存在的 code', () => {
  const result = consumeAuthorizationCode({
    code: 'no-such-code',
    redirectUri: 'http://localhost:8080/callback',
    codeVerifier: 'whatever',
    client
  });

  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.status, 400);
  assert.strictEqual(result.error, 'invalid_grant');
  assert.strictEqual(result.error_description, 'Invalid authorization code');
});

test('consumeAuthorizationCode 同一 code 不能重复消费', () => {
  const { code, verifier } = makeCode();
  const first = consumeAuthorizationCode({
    code,
    redirectUri: 'http://localhost:8080/callback',
    codeVerifier: verifier,
    client
  });
  assert.strictEqual(first.ok, true);

  const second = consumeAuthorizationCode({
    code,
    redirectUri: 'http://localhost:8080/callback',
    codeVerifier: verifier,
    client
  });
  assert.strictEqual(second.ok, false);
  assert.strictEqual(second.error, 'invalid_grant');
  assert.strictEqual(second.error_description, 'Authorization code has already been used');
});

test('consumeAuthorizationCode 拒绝过期 code', () => {
  const { code, verifier } = makeCode();
  const db = require('../src/db').getDb();
  db.prepare('UPDATE authorization_codes SET expires_at = ? WHERE code = ?')
    .run(Math.floor(Date.now() / 1000) - 10, code);

  const result = consumeAuthorizationCode({
    code,
    redirectUri: 'http://localhost:8080/callback',
    codeVerifier: verifier,
    client
  });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.error, 'invalid_grant');
  assert.strictEqual(result.error_description, 'Authorization code has expired');
});

test('consumeAuthorizationCode 拒绝其他 client 消费', () => {
  const { code, verifier } = makeCode();
  const result = consumeAuthorizationCode({
    code,
    redirectUri: 'http://localhost:8080/callback',
    codeVerifier: verifier,
    client: { client_id: 'other-client', allowed_scopes: client.allowed_scopes }
  });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.error, 'invalid_grant');
  assert.strictEqual(result.error_description, 'Authorization code was not issued to this client');
});

test('consumeAuthorizationCode 拒绝 redirect_uri 不匹配', () => {
  const { code, verifier } = makeCode();
  const result = consumeAuthorizationCode({
    code,
    redirectUri: 'http://localhost:8080/other',
    codeVerifier: verifier,
    client
  });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.error, 'invalid_grant');
  assert.strictEqual(result.error_description, 'redirect_uri does not match');
});

test('consumeAuthorizationCode 拒绝错误的 code_verifier', () => {
  const { code } = makeCode();
  const result = consumeAuthorizationCode({
    code,
    redirectUri: 'http://localhost:8080/callback',
    codeVerifier: 'wrong-verifier',
    client
  });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.error, 'invalid_grant');
  assert.strictEqual(result.error_description, 'PKCE verification failed');
});

test('consumeAuthorizationCode 拒绝超出 client allowed_scopes 的 scope', () => {
  const { code, verifier } = makeCode({ scope: 'openid admin' });
  const result = consumeAuthorizationCode({
    code,
    redirectUri: 'http://localhost:8080/callback',
    codeVerifier: verifier,
    client
  });
  assert.strictEqual(result.ok, false);
  assert.strictEqual(result.error, 'invalid_scope');
});
