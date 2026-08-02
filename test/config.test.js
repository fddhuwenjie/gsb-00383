const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { loadConfig, DEFAULTS } = require('../src/config');
const { createJwtService } = require('../src/jwt');

test('config: defaults are used when no environment variables are set', () => {
  const config = loadConfig({}, {});

  assert.equal(config.port, 3000);
  assert.equal(config.issuer, null, 'issuer must default to null so it is derived from the listening address');
  assert.ok(config.dbPath.endsWith(path.join('data', 'auth.db')));
  assert.ok(config.privateKeyPath.endsWith(path.join('keys', 'private.pem')));
  assert.ok(config.publicKeyPath.endsWith(path.join('keys', 'public.pem')));

  assert.equal(config.accessTokenTTL, 3600);
  assert.equal(config.refreshTokenTTL, 86400 * 30);
  assert.equal(config.authorizationCodeTTL, 600);
  assert.deepEqual(config.defaultScopes, ['openid', 'profile', 'email']);
});

test('config: environment variables override the defaults', () => {
  const env = {
    PORT: '9999',
    ISSUER: 'https://issuer.example.com',
    DB_PATH: '/tmp/custom-auth.db',
    PRIVATE_KEY_PATH: '/tmp/keys/private.pem',
    PUBLIC_KEY_PATH: '/tmp/keys/public.pem',
    ACCESS_TOKEN_TTL: '120',
    REFRESH_TOKEN_TTL: '600',
    AUTHORIZATION_CODE_TTL: '30'
  };

  const config = loadConfig(env, {});

  assert.equal(config.port, 9999);
  assert.equal(config.issuer, 'https://issuer.example.com');
  assert.equal(config.dbPath, '/tmp/custom-auth.db');
  assert.equal(config.privateKeyPath, '/tmp/keys/private.pem');
  assert.equal(config.publicKeyPath, '/tmp/keys/public.pem');
  assert.equal(config.accessTokenTTL, 120);
  assert.equal(config.refreshTokenTTL, 600);
  assert.equal(config.authorizationCodeTTL, 30);
});

test('config: invalid numeric environment variables fall back to defaults', () => {
  const config = loadConfig({ PORT: 'not-a-number', ACCESS_TOKEN_TTL: '' }, {});
  assert.equal(config.port, 3000);
  assert.equal(config.accessTokenTTL, 3600);
});

test('config: explicit overrides take precedence over environment variables', () => {
  const config = loadConfig({ PORT: '8080' }, { port: 7000, issuer: 'https://override.example' });
  assert.equal(config.port, 7000);
  assert.equal(config.issuer, 'https://override.example');
});

test('config: a token signed for one issuer is rejected when verified against a different issuer', async () => {
  const issuerAConfig = loadConfig({}, {
    issuer: 'https://issuer-a.example',
    privateKeyPath: DEFAULTS.privateKeyPath,
    publicKeyPath: DEFAULTS.publicKeyPath
  });
  const issuerBConfig = loadConfig({}, {
    issuer: 'https://issuer-b.example',
    privateKeyPath: DEFAULTS.privateKeyPath,
    publicKeyPath: DEFAULTS.publicKeyPath
  });

  const jwtA = createJwtService({ config: issuerAConfig });
  const jwtB = createJwtService({ config: issuerBConfig });

  const token = await jwtA.signAccessToken({
    sub: 'user-001',
    scope: 'openid profile',
    client_id: 'client_x'
  });

  const verifiedByA = await jwtA.verifyJwt(token);
  assert.equal(verifiedByA.valid, true);
  assert.equal(verifiedByA.payload.iss, 'https://issuer-a.example');

  const verifiedByB = await jwtB.verifyJwt(token);
  assert.equal(verifiedByB.valid, false, 'token must be invalid for a mismatching issuer');
  assert.match(verifiedByB.error, /unexpected "iss" claim/i, 'error should report the unexpected iss claim');
});
