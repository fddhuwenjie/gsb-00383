const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { spawn } = require('child_process');

const { createConfig, DEFAULTS } = require('../src/config');
const { initJwt, signAccessToken, verifyJwt } = require('../src/jwt');

test('默认配置：无环境变量时使用集中默认值', () => {
  const config = createConfig({});

  assert.strictEqual(config.port, 3000);
  assert.strictEqual(config.issuer, 'http://localhost:3000');
  assert.strictEqual(config.dbPath, DEFAULTS.dbPath);
  assert.ok(config.dbPath.endsWith(path.join('data', 'auth.db')));
  assert.strictEqual(config.privateKeyPath, DEFAULTS.privateKeyPath);
  assert.strictEqual(config.publicKeyPath, DEFAULTS.publicKeyPath);
  assert.ok(config.privateKeyPath.endsWith(path.join('keys', 'private.pem')));
  assert.ok(config.publicKeyPath.endsWith(path.join('keys', 'public.pem')));
  assert.strictEqual(config.accessTokenTTL, 3600);
  assert.strictEqual(config.refreshTokenTTL, 86400 * 30);
  assert.strictEqual(config.authorizationCodeTTL, 600);
  assert.deepStrictEqual(config.defaultScopes, ['openid', 'profile', 'email']);
});

test('环境变量覆盖：PORT/ISSUER/DB_PATH/密钥路径可覆盖，issuer 默认随端口推导', () => {
  const byPort = createConfig({ PORT: '9383' });
  assert.strictEqual(byPort.port, 9383);
  assert.strictEqual(byPort.issuer, 'http://localhost:9383');

  const explicitIssuer = createConfig({ PORT: '9383', ISSUER: 'https://auth.example.com' });
  assert.strictEqual(explicitIssuer.issuer, 'https://auth.example.com');

  const overridden = createConfig({
    DB_PATH: ':memory:',
    PRIVATE_KEY_PATH: '/tmp/test-private.pem',
    PUBLIC_KEY_PATH: '/tmp/test-public.pem'
  });
  assert.strictEqual(overridden.dbPath, ':memory:');
  assert.strictEqual(overridden.privateKeyPath, '/tmp/test-private.pem');
  assert.strictEqual(overridden.publicKeyPath, '/tmp/test-public.pem');
});

test('环境变量覆盖：服务启动后 discovery issuer 与实际监听地址一致', async () => {
  const port = 9617;
  const child = spawn(process.execPath, ['src/server.js'], {
    env: { ...process.env, PORT: String(port) },
    cwd: path.join(__dirname, '..')
  });

  try {
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('server start timeout')), 5000);
      child.stdout.on('data', () => {
        clearTimeout(timer);
        resolve();
      });
      child.on('error', reject);
    });

    const res = await fetch(`http://localhost:${port}/.well-known/openid-configuration`);
    assert.strictEqual(res.status, 200);
    const body = await res.json();
    assert.strictEqual(body.issuer, `http://localhost:${port}`);
    assert.strictEqual(body.token_endpoint, `http://localhost:${port}/token`);
    assert.strictEqual(body.jwks_uri, `http://localhost:${port}/.well-known/jwks.json`);
  } finally {
    child.kill();
  }
});

test('错误 issuer：签名与验证 issuer 不一致时验签失败', async () => {
  const goodConfig = createConfig({ ISSUER: 'http://localhost:3000' });
  initJwt(goodConfig);
  const token = await signAccessToken({ sub: 'user-001', scope: 'openid' });

  const ok = await verifyJwt(token);
  assert.strictEqual(ok.valid, true);
  assert.strictEqual(ok.payload.iss, 'http://localhost:3000');

  const wrongConfig = createConfig({ ISSUER: 'http://evil.example.com' });
  initJwt(wrongConfig);
  const bad = await verifyJwt(token);
  assert.strictEqual(bad.valid, false);
});
