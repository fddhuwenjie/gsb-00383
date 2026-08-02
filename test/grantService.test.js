const test = require('node:test');
const assert = require('node:assert/strict');

const {
  config,
  grantService,
  seedConfidentialClient,
  seedPublicClient,
  getDefaultUser,
  pkcePair,
  REDIRECT_URI,
  data,
  getDb
} = require('./helpers/setup');

const {
  issueAuthorizationCode,
  fetchAuthorizationCode,
  consumeAuthorizationCode,
  issueTokenPair,
  consumeRefreshToken
} = grantService;

const client = seedConfidentialClient();
const otherClient = seedPublicClient();
const user = getDefaultUser();

function issueCode(overrides = {}) {
  const { verifier, challenge } = pkcePair();
  const code = issueAuthorizationCode({
    clientId: client.client_id,
    userId: user.id,
    redirectUri: REDIRECT_URI,
    scope: 'openid profile email',
    codeChallenge: challenge,
    codeChallengeMethod: 'S256',
    ...overrides
  });
  return { code, verifier, challenge };
}

test('issueAuthorizationCode creates a code that can be fetched', () => {
  const { code } = issueCode();
  const fetched = fetchAuthorizationCode(code);

  assert.ok(fetched, 'fetched code should exist');
  assert.equal(fetched.code, code);
  assert.equal(fetched.client_id, client.client_id);
  assert.equal(fetched.user_id, user.id);
  assert.equal(fetched.redirect_uri, REDIRECT_URI);
  assert.equal(fetched.scope, 'openid profile email');
  assert.equal(fetched.used, 0);
  const expectedExpiry = Math.floor(Date.now() / 1000) + config.authorizationCodeTTL;
  assert.ok(Math.abs(fetched.expires_at - expectedExpiry) <= 1);
});

test('issueAuthorizationCode respects a custom ttl', () => {
  const { code } = issueCode({ ttl: 123 });
  const fetched = fetchAuthorizationCode(code);
  const expectedExpiry = Math.floor(Date.now() / 1000) + 123;
  assert.ok(Math.abs(fetched.expires_at - expectedExpiry) <= 1);
});

test('consumeAuthorizationCode succeeds with valid parameters and marks code used', () => {
  const { code, verifier } = issueCode();

  const result = consumeAuthorizationCode({
    code,
    clientId: client.client_id,
    redirectUri: REDIRECT_URI,
    codeVerifier: verifier
  });

  assert.equal(result.ok, true);
  assert.ok(result.authCode, 'authCode should be returned');
  assert.equal(result.authCode.code, code);
  assert.equal(result.authCode.user_id, user.id);

  const after = fetchAuthorizationCode(code);
  assert.equal(after.used, 1, 'code should be marked as used after consumption');
});

test('consumeAuthorizationCode rejects a non-existent code', () => {
  const result = consumeAuthorizationCode({
    code: 'does-not-exist',
    clientId: client.client_id,
    redirectUri: REDIRECT_URI,
    codeVerifier: pkcePair().verifier
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, 400);
  assert.equal(result.error, 'invalid_grant');
  assert.equal(result.error_description, 'Invalid authorization code');
});

test('consumeAuthorizationCode rejects a code that has already been used (replay)', () => {
  const { code, verifier } = issueCode();

  const first = consumeAuthorizationCode({
    code,
    clientId: client.client_id,
    redirectUri: REDIRECT_URI,
    codeVerifier: verifier
  });
  assert.equal(first.ok, true);

  const replay = consumeAuthorizationCode({
    code,
    clientId: client.client_id,
    redirectUri: REDIRECT_URI,
    codeVerifier: verifier
  });

  assert.equal(replay.ok, false);
  assert.equal(replay.status, 400);
  assert.equal(replay.error, 'invalid_grant');
  assert.equal(replay.error_description, 'Authorization code has already been used');
});

test('consumeAuthorizationCode rejects an expired code', () => {
  const { code, verifier } = issueCode({ ttl: -1 });

  const result = consumeAuthorizationCode({
    code,
    clientId: client.client_id,
    redirectUri: REDIRECT_URI,
    codeVerifier: verifier
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, 400);
  assert.equal(result.error, 'invalid_grant');
  assert.equal(result.error_description, 'Authorization code has expired');
});

test('consumeAuthorizationCode rejects a code presented by a different client', () => {
  const { code, verifier } = issueCode();

  const result = consumeAuthorizationCode({
    code,
    clientId: otherClient.client_id,
    redirectUri: REDIRECT_URI,
    codeVerifier: verifier
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, 400);
  assert.equal(result.error, 'invalid_grant');
  assert.equal(result.error_description, 'Authorization code was not issued to this client');

  assert.equal(fetchAuthorizationCode(code).used, 0, 'rejected code must remain unused');
});

test('consumeAuthorizationCode rejects a mismatching redirect_uri', () => {
  const { code, verifier } = issueCode();

  const result = consumeAuthorizationCode({
    code,
    clientId: client.client_id,
    redirectUri: 'http://localhost:8080/other',
    codeVerifier: verifier
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, 400);
  assert.equal(result.error, 'invalid_grant');
  assert.equal(result.error_description, 'redirect_uri does not match');

  assert.equal(fetchAuthorizationCode(code).used, 0, 'rejected code must remain unused');
});

test('consumeAuthorizationCode rejects an incorrect code_verifier (PKCE failure)', () => {
  const { code } = issueCode();

  const result = consumeAuthorizationCode({
    code,
    clientId: client.client_id,
    redirectUri: REDIRECT_URI,
    codeVerifier: pkcePair().verifier
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, 400);
  assert.equal(result.error, 'invalid_grant');
  assert.equal(result.error_description, 'PKCE verification failed');

  assert.equal(fetchAuthorizationCode(code).used, 0, 'rejected code must remain unused');
});

test('consumeAuthorizationCode rejects an unsupported code challenge method', () => {
  const { code, verifier } = issueCode({ codeChallengeMethod: 'plain' });

  const result = consumeAuthorizationCode({
    code,
    clientId: client.client_id,
    redirectUri: REDIRECT_URI,
    codeVerifier: verifier
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, 400);
  assert.equal(result.error, 'invalid_grant');
  assert.equal(result.error_description, 'Unsupported code challenge method');

  assert.equal(fetchAuthorizationCode(code).used, 0, 'rejected code must remain unused');
});

test('issueTokenPair stores an access token linked to a newly issued refresh token', () => {
  const accessToken = 'access-token-value-' + Math.random().toString(16).slice(2);
  const scope = 'openid profile';

  const pair = issueTokenPair({
    clientId: client.client_id,
    userId: user.id,
    scope,
    accessToken
  });

  assert.ok(pair.refreshTokenValue.startsWith('refresh_'), 'refresh token should have the refresh_ prefix');
  assert.equal(typeof pair.accessExpiresAt, 'number');
  assert.equal(typeof pair.refreshExpiresAt, 'number');

  const storedAccess = data.getToken(accessToken);
  assert.ok(storedAccess, 'access token should be persisted');
  assert.equal(storedAccess.token_type, 'access_token');
  assert.equal(storedAccess.client_id, client.client_id);
  assert.equal(storedAccess.user_id, user.id);
  assert.equal(storedAccess.scope, scope);
  assert.equal(storedAccess.associated_refresh, pair.refreshTokenValue);

  const storedRefresh = data.getToken(pair.refreshTokenValue);
  assert.ok(storedRefresh, 'refresh token should be persisted');
  assert.equal(storedRefresh.token_type, 'refresh_token');
  assert.equal(storedRefresh.client_id, client.client_id);
  assert.equal(storedRefresh.user_id, user.id);
  assert.equal(storedRefresh.scope, scope);
  assert.equal(storedRefresh.revoked, 0);
});

function issuePair(scope = 'openid profile email') {
  const accessToken = 'access-token-' + Math.random().toString(16).slice(2);
  const pair = issueTokenPair({
    clientId: client.client_id,
    userId: user.id,
    scope,
    accessToken
  });
  return pair;
}

test('consumeRefreshToken succeeds and revokes the old refresh token', () => {
  const pair = issuePair();

  const result = consumeRefreshToken({
    refreshTokenValue: pair.refreshTokenValue,
    clientId: client.client_id,
    requestedScope: null,
    clientAllowedScopes: client.allowed_scopes
  });

  assert.equal(result.ok, true);
  assert.equal(result.newScope, 'openid profile email');
  assert.equal(result.userId, user.id);
  assert.ok(result.oldRefreshToken);

  const after = data.getToken(pair.refreshTokenValue);
  assert.equal(after.revoked, 1, 'old refresh token must be revoked after consumption');
});

test('consumeRefreshToken rejects a non-existent token', () => {
  const result = consumeRefreshToken({
    refreshTokenValue: 'refresh_does_not_exist',
    clientId: client.client_id,
    requestedScope: null,
    clientAllowedScopes: client.allowed_scopes
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, 400);
  assert.equal(result.error, 'invalid_grant');
  assert.equal(result.error_description, 'Invalid refresh token');
});

test('consumeRefreshToken rejects an already used (revoked) refresh token', () => {
  const pair = issuePair();

  const first = consumeRefreshToken({
    refreshTokenValue: pair.refreshTokenValue,
    clientId: client.client_id,
    requestedScope: null,
    clientAllowedScopes: client.allowed_scopes
  });
  assert.equal(first.ok, true);

  const replay = consumeRefreshToken({
    refreshTokenValue: pair.refreshTokenValue,
    clientId: client.client_id,
    requestedScope: null,
    clientAllowedScopes: client.allowed_scopes
  });

  assert.equal(replay.ok, false);
  assert.equal(replay.status, 400);
  assert.equal(replay.error, 'invalid_grant');
  assert.equal(replay.error_description, 'Refresh token has been revoked');
});

test('consumeRefreshToken rejects an expired refresh token', () => {
  const pair = issuePair();
  const now = Math.floor(Date.now() / 1000);
  getDb().prepare('UPDATE tokens SET expires_at = ? WHERE token_value = ?')
    .run(now - 10, pair.refreshTokenValue);

  const result = consumeRefreshToken({
    refreshTokenValue: pair.refreshTokenValue,
    clientId: client.client_id,
    requestedScope: null,
    clientAllowedScopes: client.allowed_scopes
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, 400);
  assert.equal(result.error, 'invalid_grant');
  assert.equal(result.error_description, 'Refresh token has expired');
});

test('consumeRefreshToken rejects a token presented by a different client', () => {
  const pair = issuePair();

  const result = consumeRefreshToken({
    refreshTokenValue: pair.refreshTokenValue,
    clientId: otherClient.client_id,
    requestedScope: null,
    clientAllowedScopes: otherClient.allowed_scopes
  });

  assert.equal(result.ok, false);
  assert.equal(result.status, 400);
  assert.equal(result.error, 'invalid_grant');
  assert.equal(result.error_description, 'Refresh token was not issued to this client');

  assert.equal(data.getToken(pair.refreshTokenValue).revoked, 0, 'rejected token must remain usable');
});

test('consumeRefreshToken narrows scope when requested and rejects scope exceeding the original', () => {
  const pair = issuePair('openid profile email');

  const narrowed = consumeRefreshToken({
    refreshTokenValue: pair.refreshTokenValue,
    clientId: client.client_id,
    requestedScope: 'openid profile',
    clientAllowedScopes: client.allowed_scopes
  });
  assert.equal(narrowed.ok, true);
  assert.equal(narrowed.newScope, 'openid profile');

  const secondPair = issuePair('openid profile email');
  const exceeding = consumeRefreshToken({
    refreshTokenValue: secondPair.refreshTokenValue,
    clientId: client.client_id,
    requestedScope: 'openid profile email address',
    clientAllowedScopes: client.allowed_scopes
  });
  assert.equal(exceeding.ok, false);
  assert.equal(exceeding.error, 'invalid_scope');
});
