const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const { buildConfig, defaults } = require('../src/config');
const { createDatabase } = require('../src/db');
const { createJwtService } = require('../src/jwt');
const { createDataStore } = require('../src/data');
const { createGrantService, GrantServiceError } = require('../src/grantService');
const { generateCodeChallenge } = require('../src/pkce');

function createServiceContext(overrides = {}) {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'grant-svc-'));
  const dbPath = path.join(tmpDir, `grant-${crypto.randomBytes(4).toString('hex')}.db`);
  const config = buildConfig({
    ...defaults,
    dbPath,
    port: 0,
    host: '127.0.0.1',
    issuer: 'http://localhost:9999',
    ...overrides
  });
  const db = createDatabase(config);
  const data = createDataStore({ db, config });
  const jwt = createJwtService(config);
  const grant = createGrantService({
    db,
    config,
    signAccessToken: jwt.signAccessToken,
    getUserById: data.getUserById
  });
  return { config, db, data, jwt, grant };
}

function seedUser(db) {
  const passwordHash = crypto.createHash('sha256').update('password123').digest('hex');
  const sub = 'user-unit-' + crypto.randomBytes(4).toString('hex');
  const username = 'alice_' + crypto.randomBytes(4).toString('hex');
  const info = db.prepare(`
    INSERT INTO users (sub, username, password_hash, name, email)
    VALUES (?, ?, ?, ?, ?)
  `).run(sub, username, passwordHash, 'Alice Unit', `${username}@example.com`);
  return info.lastInsertRowid;
}

function validCodeChallenge() {
  const verifier = crypto.randomBytes(32).toString('hex');
  return { verifier, challenge: generateCodeChallenge(verifier) };
}

test('createAuthorizationCode persists a code with S256 challenge', () => {
  const { grant, db } = createServiceContext();
  const userId = seedUser(db);
  const { verifier, challenge } = validCodeChallenge();

  const created = grant.createAuthorizationCode({
    clientId: 'client_unit_1',
    userId,
    redirectUri: 'http://localhost/callback',
    scope: 'openid profile',
    codeChallenge: challenge,
    codeChallengeMethod: 'S256',
    ttl: 600
  });

  assert.ok(created.code);
  assert.equal(created.client_id, 'client_unit_1');
  assert.equal(created.code_challenge_method, 'S256');
  assert.ok(created.expires_at > Math.floor(Date.now() / 1000));

  const stored = grant.getAuthorizationCode(created.code);
  assert.equal(stored.used, 0);
  assert.equal(stored.code_challenge, challenge);
});

test('createAuthorizationCode defaults method to S256 and ttl from config', () => {
  const { grant, config, db } = createServiceContext({ authorizationCodeTTL: 120 });
  const userId = seedUser(db);
  const { challenge } = validCodeChallenge();

  const created = grant.createAuthorizationCode({
    clientId: 'client_unit_2',
    userId,
    redirectUri: 'http://localhost/callback',
    scope: 'openid',
    codeChallenge: challenge
  });

  assert.equal(created.code_challenge_method, 'S256');
  const expectedExpiryFloor = Math.floor(Date.now() / 1000) + 120 - 2;
  assert.ok(created.expires_at >= expectedExpiryFloor);
});

test('createAuthorizationCode rejects unsupported challenge method', () => {
  const { grant, db } = createServiceContext();
  const userId = seedUser(db);
  const { challenge } = validCodeChallenge();

  assert.throws(
    () => grant.createAuthorizationCode({
      clientId: 'c', userId, redirectUri: 'u', scope: 'openid',
      codeChallenge: challenge, codeChallengeMethod: 'plain'
    }),
    (err) => err instanceof GrantServiceError && err.error === 'invalid_request'
  );
});

test('getAuthorizationCode returns null for unknown code', () => {
  const { grant } = createServiceContext();
  assert.equal(grant.getAuthorizationCode('missing'), null);
});

test('consumeAuthorizationCode returns the grant and marks it used', () => {
  const { grant, db } = createServiceContext();
  const userId = seedUser(db);
  const { verifier, challenge } = validCodeChallenge();

  const created = grant.createAuthorizationCode({
    clientId: 'client_unit_4',
    userId,
    redirectUri: 'http://localhost/callback',
    scope: 'openid profile',
    codeChallenge: challenge
  });

  const consumed = grant.consumeAuthorizationCode({
    code: created.code,
    clientId: 'client_unit_4',
    redirectUri: 'http://localhost/callback',
    codeVerifier: verifier
  });

  assert.equal(consumed.code, created.code);
  assert.equal(grant.getAuthorizationCode(created.code).used, 1);
});

test('consumeAuthorizationCode rejects unknown code with invalid_grant', () => {
  const { grant } = createServiceContext();
  assert.throws(
    () => grant.consumeAuthorizationCode({
      code: 'unknown', clientId: 'c', redirectUri: 'u', codeVerifier: 'v'.repeat(64)
    }),
    (err) => err instanceof GrantServiceError && err.error === 'invalid_grant'
  );
});

test('consumeAuthorizationCode enforces single use', () => {
  const { grant, db } = createServiceContext();
  const userId = seedUser(db);
  const { verifier, challenge } = validCodeChallenge();

  const created = grant.createAuthorizationCode({
    clientId: 'client_unit_5', userId,
    redirectUri: 'http://localhost/cb', scope: 'openid', codeChallenge: challenge
  });

  grant.consumeAuthorizationCode({
    code: created.code, clientId: 'client_unit_5',
    redirectUri: 'http://localhost/cb', codeVerifier: verifier
  });

  assert.throws(
    () => grant.consumeAuthorizationCode({
      code: created.code, clientId: 'client_unit_5',
      redirectUri: 'http://localhost/cb', codeVerifier: verifier
    }),
    (err) => err instanceof GrantServiceError && /already been used/.test(err.error_description)
  );
});

test('consumeAuthorizationCode rejects mismatched client_id', () => {
  const { grant, db } = createServiceContext();
  const userId = seedUser(db);
  const { verifier, challenge } = validCodeChallenge();

  const created = grant.createAuthorizationCode({
    clientId: 'owner', userId,
    redirectUri: 'http://localhost/cb', scope: 'openid', codeChallenge: challenge
  });

  assert.throws(
    () => grant.consumeAuthorizationCode({
      code: created.code, clientId: 'attacker',
      redirectUri: 'http://localhost/cb', codeVerifier: verifier
    }),
    (err) => err instanceof GrantServiceError && err.error === 'invalid_grant'
  );
  assert.equal(grant.getAuthorizationCode(created.code).used, 0);
});

test('consumeAuthorizationCode rejects wrong PKCE verifier', () => {
  const { grant, db } = createServiceContext();
  const userId = seedUser(db);
  const { challenge } = validCodeChallenge();
  const wrongVerifier = crypto.randomBytes(32).toString('hex');

  const created = grant.createAuthorizationCode({
    clientId: 'c', userId, redirectUri: 'u', scope: 'openid', codeChallenge: challenge
  });

  assert.throws(
    () => grant.consumeAuthorizationCode({
      code: created.code, clientId: 'c', redirectUri: 'u', codeVerifier: wrongVerifier
    }),
    (err) => err instanceof GrantServiceError && /PKCE verification failed/.test(err.error_description)
  );
});

test('consumeAuthorizationCode rejects expired code', () => {
  const { grant, db } = createServiceContext();
  const userId = seedUser(db);
  const { verifier, challenge } = validCodeChallenge();

  const created = grant.createAuthorizationCode({
    clientId: 'c', userId, redirectUri: 'u', scope: 'openid', codeChallenge: challenge
  });

  db.prepare('UPDATE authorization_codes SET expires_at = ? WHERE code = ?')
    .run(Math.floor(Date.now() / 1000) - 10, created.code);

  assert.throws(
    () => grant.consumeAuthorizationCode({
      code: created.code, clientId: 'c', redirectUri: 'u', codeVerifier: verifier
    }),
    (err) => err instanceof GrantServiceError && /expired/.test(err.error_description)
  );
});

test('consumeAuthorizationCode reports invalid_request on missing params', () => {
  const { grant } = createServiceContext();
  assert.throws(
    () => grant.consumeAuthorizationCode({ code: '', clientId: 'c', redirectUri: 'u', codeVerifier: 'v' }),
    (err) => err instanceof GrantServiceError && err.error === 'invalid_request'
  );
});

test('successful authorization code consumption records an authorization_code_consumed event', () => {
  const { grant, db } = createServiceContext();
  const userId = seedUser(db);
  const { verifier, challenge } = validCodeChallenge();

  const created = grant.createAuthorizationCode({
    clientId: 'c', userId, redirectUri: 'u', scope: 'openid', codeChallenge: challenge
  });

  const before = grant.queryTokenEvents();
  assert.equal(before.length, 0);

  grant.consumeAuthorizationCode({
    code: created.code, clientId: 'c', redirectUri: 'u', codeVerifier: verifier
  });

  const events = grant.queryTokenEvents();
  assert.equal(events.length, 1);
  assert.equal(events[0].event_type, grant.TOKEN_EVENT_TYPES.AUTHORIZATION_CODE_CONSUMED);
  assert.equal(typeof events[0].id, 'number');
  assert.equal(typeof events[0].occurred_at, 'number');
  assert.ok(!('code' in events[0]), 'event must not contain the authorization code');
});

test('rejected invalid code records invalid_token_rejected event', () => {
  const { grant } = createServiceContext();

  assert.throws(
    () => grant.consumeAuthorizationCode({
      code: 'nonexistent', clientId: 'c', redirectUri: 'u', codeVerifier: 'v'.repeat(32)
    }),
    (err) => err instanceof GrantServiceError && err.error === 'invalid_grant'
  );

  const events = grant.queryTokenEvents({ eventType: grant.TOKEN_EVENT_TYPES.INVALID_TOKEN_REJECTED });
  assert.equal(events.length, 1);
});

test('token event table never stores code, token value, challenge, or verifier', () => {
  const { grant, db } = createServiceContext();
  const userId = seedUser(db);
  const secretVerifier = 'SENSITIVE-VERIFIER-' + crypto.randomBytes(8).toString('hex');
  const challenge = crypto.createHash('sha256').update(secretVerifier).digest('base64url');
  const secretCode = 'SENSITIVE-CODE-' + crypto.randomBytes(8).toString('hex');

  db.prepare(`
    INSERT INTO authorization_codes
      (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, 'S256', ?)
  `).run(secretCode, 'c', userId, 'u', 'openid', challenge, Math.floor(Date.now() / 1000) + 600);

  assert.throws(
    () => grant.consumeAuthorizationCode({
      code: secretCode, clientId: 'c', redirectUri: 'u', codeVerifier: 'wrong-verifier'
    })
  );

  grant.consumeAuthorizationCode({
    code: secretCode, clientId: 'c', redirectUri: 'u', codeVerifier: secretVerifier
  });

  const rows = db.prepare('SELECT * FROM token_events').all();
  const serialized = JSON.stringify(rows);
  assert.ok(rows.length >= 2);
  for (const row of rows) {
    const keys = Object.keys(row).sort();
    assert.deepEqual(keys, ['event_type', 'id', 'occurred_at']);
  }
  assert.ok(!serialized.includes(secretCode), 'code value leaked into token_events');
  assert.ok(!serialized.includes(secretVerifier), 'verifier leaked into token_events');
  assert.ok(!serialized.includes(challenge), 'challenge leaked into token_events');
});

test('queryTokenEvents filters by event type and returns rows ordered by time', () => {
  const { grant, db } = createServiceContext();
  grant.recordTokenEvent(grant.TOKEN_EVENT_TYPES.REFRESH_TOKEN_ROTATED);
  grant.recordTokenEvent(grant.TOKEN_EVENT_TYPES.INVALID_TOKEN_REJECTED);
  grant.recordTokenEvent(grant.TOKEN_EVENT_TYPES.REFRESH_TOKEN_ROTATED);

  const rotations = grant.queryTokenEvents({ eventType: grant.TOKEN_EVENT_TYPES.REFRESH_TOKEN_ROTATED });
  assert.equal(rotations.length, 2);
  assert.ok(rotations.every(e => e.event_type === grant.TOKEN_EVENT_TYPES.REFRESH_TOKEN_ROTATED));

  const rejections = grant.queryTokenEvents({ eventType: grant.TOKEN_EVENT_TYPES.INVALID_TOKEN_REJECTED });
  assert.equal(rejections.length, 1);

  const all = grant.queryTokenEvents();
  assert.equal(all.length, 3);
  for (let i = 1; i < all.length; i++) {
    assert.ok(all[i].occurred_at >= all[i - 1].occurred_at);
  }

  const limited = grant.queryTokenEvents({ limit: 2 });
  assert.equal(limited.length, 2);
});
