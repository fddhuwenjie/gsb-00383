const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const { defaults, buildConfig, loadConfig } = require('../src/config');

test('defaults expose port, issuer and centralized key/db paths', () => {
  assert.equal(defaults.port, 3000);
  assert.equal(defaults.host, '0.0.0.0');
  assert.equal(defaults.issuer, null);
  assert.equal(defaults.authorizationCodeTTL, 600);
  assert.equal(defaults.accessTokenTTL, 3600);
  assert.ok(Array.isArray(defaults.defaultScopes));

  const root = path.join(__dirname, '..');
  assert.equal(defaults.dbPath, path.join(root, 'data', 'auth.db'));
  assert.equal(defaults.privateKeyPath, path.join(root, 'keys', 'private.pem'));
  assert.equal(defaults.publicKeyPath, path.join(root, 'keys', 'public.pem'));
});

test('buildConfig uses defaults and normalizes issuer/port', () => {
  const cfg = buildConfig({});
  assert.equal(cfg.port, 3000);
  assert.equal(cfg.issuer, null);

  const withIssuer = buildConfig({ issuer: 'http://example.com/', port: '9000' });
  assert.equal(withIssuer.issuer, 'http://example.com');
  assert.equal(withIssuer.port, 9000);
});

test('loadConfig reads environment variable overrides', () => {
  const env = {
    PORT: '8123',
    HOST: '127.0.0.1',
    ISSUER: 'http://env.example.com/',
    DB_PATH: '/tmp/custom-auth.db',
    PRIVATE_KEY_PATH: '/tmp/private.pem',
    PUBLIC_KEY_PATH: '/tmp/public.pem',
    KEY_ID: 'env-kid',
    ACCESS_TOKEN_TTL: '60',
    REFRESH_TOKEN_TTL: '120',
    AUTHORIZATION_CODE_TTL: '15'
  };

  const cfg = loadConfig(env);

  assert.equal(cfg.port, 8123);
  assert.equal(cfg.host, '127.0.0.1');
  assert.equal(cfg.issuer, 'http://env.example.com');
  assert.equal(cfg.dbPath, '/tmp/custom-auth.db');
  assert.equal(cfg.privateKeyPath, '/tmp/private.pem');
  assert.equal(cfg.publicKeyPath, '/tmp/public.pem');
  assert.equal(cfg.keyId, 'env-kid');
  assert.equal(cfg.accessTokenTTL, 60);
  assert.equal(cfg.refreshTokenTTL, 120);
  assert.equal(cfg.authorizationCodeTTL, 15);
});

test('explicit overrides take precedence over environment variables', () => {
  const env = { PORT: '8123', ISSUER: 'http://env.example.com' };
  const cfg = loadConfig(env, { port: 9999, issuer: 'http://override.example.com' });

  assert.equal(cfg.port, 9999);
  assert.equal(cfg.issuer, 'http://override.example.com');
});
