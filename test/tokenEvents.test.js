const test = require('node:test');
const assert = require('node:assert/strict');

const {
  config,
  getDb,
  data,
  grantService,
  seedConfidentialClient,
  getDefaultUser,
  pkcePair,
  REDIRECT_URI
} = require('./helpers/setup');

const { TOKEN_EVENT_TYPES } = grantService;

const client = seedConfidentialClient();
const user = getDefaultUser();

function issueCode(overrides = {}) {
  const { verifier, challenge } = pkcePair();
  const code = grantService.issueAuthorizationCode({
    clientId: client.client_id,
    userId: user.id,
    redirectUri: REDIRECT_URI,
    scope: 'openid profile email',
    codeChallenge: challenge,
    codeChallengeMethod: 'S256',
    ...overrides
  });
  return { code, verifier };
}

function storeRefreshToken(value, scope = 'openid profile email') {
  const now = Math.floor(Date.now() / 1000);
  data.storeToken(
    'refresh_token',
    value,
    client.client_id,
    user.id,
    scope,
    now + config.refreshTokenTTL,
    null
  );
}

function allEventRows() {
  return getDb().prepare('SELECT id, event_type, created_at FROM token_events ORDER BY id ASC').all();
}

function eventsOfType(eventType) {
  return allEventRows().filter(e => e.event_type === eventType);
}

function countOfType(eventType) {
  return getDb()
    .prepare('SELECT COUNT(*) as count FROM token_events WHERE event_type = ?')
    .get(eventType).count;
}

test('token events: successful authorization code consumption is recorded', () => {
  const { code, verifier } = issueCode();

  const result = grantService.consumeAuthorizationCode({
    code,
    clientId: client.client_id,
    redirectUri: REDIRECT_URI,
    codeVerifier: verifier
  });
  assert.equal(result.ok, true);

  const events = eventsOfType(TOKEN_EVENT_TYPES.AUTHORIZATION_CODE_CONSUMED);
  assert.ok(events.length >= 1, 'authorization_code_consumed event should be recorded');
  const latest = events[events.length - 1];
  assert.equal(typeof latest.id, 'number');
  assert.equal(typeof latest.created_at, 'number');
  assert.equal(latest.event_type, TOKEN_EVENT_TYPES.AUTHORIZATION_CODE_CONSUMED);
});

test('token events: invalid authorization code is recorded as invalid_token_rejected', () => {
  const result = grantService.consumeAuthorizationCode({
    code: 'non-existent-code',
    clientId: client.client_id,
    redirectUri: REDIRECT_URI,
    codeVerifier: pkcePair().verifier
  });
  assert.equal(result.ok, false);

  const events = eventsOfType(TOKEN_EVENT_TYPES.INVALID_TOKEN_REJECTED);
  assert.ok(events.length >= 1, 'invalid_token_rejected event should be recorded');
});

test('token events: successful refresh token rotation is recorded', () => {
  const refreshValue = 'refresh_unit_rotate_' + Math.random().toString(16).slice(2);
  storeRefreshToken(refreshValue);

  const result = grantService.consumeRefreshToken({
    refreshTokenValue: refreshValue,
    clientId: client.client_id,
    requestedScope: null,
    clientAllowedScopes: client.allowed_scopes
  });
  assert.equal(result.ok, true);

  const events = eventsOfType(TOKEN_EVENT_TYPES.REFRESH_TOKEN_ROTATED);
  assert.ok(events.length >= 1, 'refresh_token_rotated event should be recorded');
  const latest = events[events.length - 1];
  assert.equal(latest.event_type, TOKEN_EVENT_TYPES.REFRESH_TOKEN_ROTATED);
});

test('token events: invalid refresh token is recorded as invalid_token_rejected', () => {
  const result = grantService.consumeRefreshToken({
    refreshTokenValue: 'refresh_does_not_exist',
    clientId: client.client_id,
    requestedScope: null,
    clientAllowedScopes: client.allowed_scopes
  });
  assert.equal(result.ok, false);
  assert.equal(result.error, 'invalid_grant');

  const rejected = eventsOfType(TOKEN_EVENT_TYPES.INVALID_TOKEN_REJECTED);
  assert.ok(rejected.length >= 1);
});

test('token events: scope-exceeding refresh attempt does not record an invalid token event', () => {
  const refreshValue = 'refresh_unit_scope_' + Math.random().toString(16).slice(2);
  storeRefreshToken(refreshValue, 'openid profile');

  const before = countOfType(TOKEN_EVENT_TYPES.INVALID_TOKEN_REJECTED);
  const beforeRotated = countOfType(TOKEN_EVENT_TYPES.REFRESH_TOKEN_ROTATED);

  const result = grantService.consumeRefreshToken({
    refreshTokenValue: refreshValue,
    clientId: client.client_id,
    requestedScope: 'openid profile email address',
    clientAllowedScopes: client.allowed_scopes
  });
  assert.equal(result.ok, false);
  assert.equal(result.error, 'invalid_scope');

  assert.equal(
    countOfType(TOKEN_EVENT_TYPES.INVALID_TOKEN_REJECTED),
    before,
    'scope errors must not be recorded as invalid token rejections'
  );
  assert.equal(
    countOfType(TOKEN_EVENT_TYPES.REFRESH_TOKEN_ROTATED),
    beforeRotated,
    'failed rotation must not record a rotated event'
  );
});

test('token events: getTokenEvents filters by event type and returns newest first', () => {
  data.recordTokenEvent(TOKEN_EVENT_TYPES.AUTHORIZATION_CODE_CONSUMED);
  data.recordTokenEvent(TOKEN_EVENT_TYPES.REFRESH_TOKEN_ROTATED);
  data.recordTokenEvent(TOKEN_EVENT_TYPES.AUTHORIZATION_CODE_CONSUMED);

  const consumed = data.getTokenEvents({ eventType: TOKEN_EVENT_TYPES.AUTHORIZATION_CODE_CONSUMED });
  assert.ok(consumed.length >= 2);
  assert.ok(consumed.every(e => e.event_type === TOKEN_EVENT_TYPES.AUTHORIZATION_CODE_CONSUMED));

  for (let i = 1; i < consumed.length; i++) {
    assert.ok(
      consumed[i - 1].created_at >= consumed[i].created_at,
      'events should be ordered newest first'
    );
  }

  const rotated = data.getTokenEvents({ eventType: TOKEN_EVENT_TYPES.REFRESH_TOKEN_ROTATED });
  assert.ok(rotated.every(e => e.event_type === TOKEN_EVENT_TYPES.REFRESH_TOKEN_ROTATED));
  assert.ok(rotated.length >= 1);

  const all = data.getTokenEvents();
  assert.ok(all.length >= consumed.length + rotated.length);
});

test('token events: limit is respected', () => {
  for (let i = 0; i < 5; i++) {
    data.recordTokenEvent(TOKEN_EVENT_TYPES.INVALID_TOKEN_REJECTED);
  }
  const limited = data.getTokenEvents({ eventType: TOKEN_EVENT_TYPES.INVALID_TOKEN_REJECTED, limit: 2 });
  assert.equal(limited.length, 2);
});

test('token events: no code, token, or verifier values are persisted to event rows', () => {
  const sensitiveCode = 'sensitive-code-value-' + Math.random().toString(16).slice(2);
  const sensitiveVerifier = 'sensitive-verifier-' + Math.random().toString(16).slice(2);
  const sensitiveRefresh = 'refresh_sensitive_' + Math.random().toString(16).slice(2);

  getDb()
    .prepare('INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(sensitiveCode, client.client_id, user.id, REDIRECT_URI, 'openid profile email', 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', 'S256', Math.floor(Date.now() / 1000) - 10);

  grantService.consumeAuthorizationCode({
    code: sensitiveCode,
    clientId: client.client_id,
    redirectUri: REDIRECT_URI,
    codeVerifier: sensitiveVerifier
  });

  storeRefreshToken(sensitiveRefresh);
  grantService.consumeRefreshToken({
    refreshTokenValue: sensitiveRefresh,
    clientId: client.client_id,
    requestedScope: null,
    clientAllowedScopes: client.allowed_scopes
  });

  const rows = allEventRows();
  assert.ok(rows.length >= 2, 'events should have been recorded');

  for (const row of rows) {
    assert.deepEqual(
      Object.keys(row).sort(),
      ['created_at', 'event_type', 'id'],
      'event rows must only contain id, event_type, created_at'
    );
    assert.equal(typeof row.id, 'number');
    assert.equal(typeof row.created_at, 'number');
    assert.ok(typeof row.event_type === 'string' && row.event_type.length > 0);
  }

  const serialized = JSON.stringify(rows);
  assert.ok(!serialized.includes(sensitiveCode), 'authorization code value must not be stored in events');
  assert.ok(!serialized.includes(sensitiveVerifier), 'code verifier must not be stored in events');
  assert.ok(!serialized.includes(sensitiveRefresh), 'refresh token value must not be stored in events');
});
