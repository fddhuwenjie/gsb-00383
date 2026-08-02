const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const os = require('os');
const fs = require('fs');

const { loadConfig, resolveIssuer } = require('../src/config');

const ROOT = path.join(__dirname, '..');

// --- Default configuration ---------------------------------------------------

test('loadConfig provides single-source defaults when nothing is set', () => {
  // Clear any env that would override defaults for this call.
  const saved = {};
  for (const key of ['PORT', 'ISSUER', 'DB_PATH', 'PRIVATE_KEY_PATH', 'PUBLIC_KEY_PATH']) {
    saved[key] = process.env[key];
    delete process.env[key];
  }
  try {
    const config = loadConfig();
    assert.strictEqual(config.port, 3000);
    assert.strictEqual(config.issuer, 'http://localhost:3000');
    assert.strictEqual(config.issuerExplicit, false);
    assert.strictEqual(config.dbPath, path.join(ROOT, 'data', 'auth.db'));
    assert.strictEqual(config.privateKeyPath, path.join(ROOT, 'keys', 'private.pem'));
    assert.strictEqual(config.publicKeyPath, path.join(ROOT, 'keys', 'public.pem'));
    assert.strictEqual(config.accessTokenTTL, 3600);
    assert.deepStrictEqual(config.defaultScopes, ['openid', 'profile', 'email']);
  } finally {
    for (const key of Object.keys(saved)) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  }
});

test('resolveIssuer derives the issuer from the actual listen port when unset', () => {
  const config = loadConfig({ dbPath: '/tmp/ignored.db' });
  assert.strictEqual(config.issuerExplicit, false);
  const resolved = resolveIssuer(config, 54321);
  assert.strictEqual(resolved, 'http://localhost:54321');
  assert.strictEqual(config.issuer, 'http://localhost:54321');
});

// --- Environment variable / override overrides -------------------------------

test('loadConfig honours explicit overrides over defaults', () => {
  const config = loadConfig({
    port: 9999,
    issuer: 'https://issuer.example.com',
    dbPath: '/custom/auth.db',
    privateKeyPath: '/custom/private.pem',
    publicKeyPath: '/custom/public.pem'
  });
  assert.strictEqual(config.port, 9999);
  assert.strictEqual(config.issuer, 'https://issuer.example.com');
  assert.strictEqual(config.issuerExplicit, true);
  assert.strictEqual(config.dbPath, '/custom/auth.db');
  assert.strictEqual(config.privateKeyPath, '/custom/private.pem');
  assert.strictEqual(config.publicKeyPath, '/custom/public.pem');
});

test('an explicit issuer is not overwritten by resolveIssuer', () => {
  const config = loadConfig({ issuer: 'https://pinned.example.com' });
  assert.strictEqual(config.issuerExplicit, true);
  resolveIssuer(config, 12345);
  assert.strictEqual(config.issuer, 'https://pinned.example.com');
});

test('loadConfig reads environment variables', () => {
  const saved = {};
  for (const key of ['PORT', 'ISSUER', 'DB_PATH']) {
    saved[key] = process.env[key];
  }
  process.env.PORT = '8123';
  process.env.ISSUER = 'https://env-issuer.example.com';
  process.env.DB_PATH = '/env/auth.db';
  try {
    const config = loadConfig();
    assert.strictEqual(config.port, 8123);
    assert.strictEqual(config.issuer, 'https://env-issuer.example.com');
    assert.strictEqual(config.issuerExplicit, true);
    assert.strictEqual(config.dbPath, '/env/auth.db');
  } finally {
    for (const key of Object.keys(saved)) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  }
});

// --- Wrong issuer -------------------------------------------------------------

test('verifyJwt rejects a token whose issuer does not match config', async () => {
  const tmpDb = path.join(os.tmpdir(), `config-issuer-${process.pid}.db`);
  const jwt = require('../src/jwt');
  const db = require('../src/db');

  // Sign a token under one issuer.
  const signConfig = loadConfig({ dbPath: tmpDb, issuer: 'https://issuer-a.example.com' });
  db.configure(signConfig);
  db.initDatabase();
  jwt.configure(signConfig);
  const token = await jwt.signAccessToken({ sub: 'user-001', scope: 'openid' });

  // A verifier configured with the same issuer accepts it.
  const okResult = await jwt.verifyJwt(token);
  assert.strictEqual(okResult.valid, true);

  // Reconfigure the verifier with a different issuer: verification must fail.
  jwt.configure(loadConfig({ dbPath: tmpDb, issuer: 'https://issuer-b.example.com' }));
  const badResult = await jwt.verifyJwt(token);
  assert.strictEqual(badResult.valid, false);
  assert.ok(badResult.error, 'a verification error message is present');

  for (const suffix of ['', '-wal', '-shm']) {
    try { fs.unlinkSync(tmpDb + suffix); } catch (e) {}
  }
});
