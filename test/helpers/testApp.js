const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const http = require('http');

const { buildConfig, defaults } = require('../../src/config');
const { createApp, startAsync, deriveIssuerFromAddress } = require('../../src/server');

function createTmpDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

function createTestConfig(overrides = {}) {
  const tmpDir = createTmpDir('oauth-test-');
  const dbPath = path.join(tmpDir, `test-${crypto.randomBytes(4).toString('hex')}.db`);

  return buildConfig({
    ...defaults,
    dbPath,
    port: 0,
    host: '127.0.0.1',
    issuer: null,
    ...overrides
  });
}

async function startTestApp(config = createTestConfig()) {
  const server = await startAsync(config);
  const address = server.address();
  if (!config.issuer) {
    config.issuer = deriveIssuerFromAddress(address);
  }
  return { server, config };
}

function stopTestApp(server) {
  return new Promise((resolve) => {
    if (!server) return resolve();
    server.close(() => resolve());
  });
}

function request(server, method, reqPath, data, headers = {}) {
  return new Promise((resolve, reject) => {
    const { port } = server.address();
    const url = new URL(reqPath, `http://127.0.0.1:${port}`);
    const options = {
      hostname: '127.0.0.1',
      port: url.port,
      path: url.pathname + url.search,
      method,
      headers
    };

    let body = data;
    if (body && (method === 'POST' || method === 'PUT')) {
      if (typeof body === 'object' && !Buffer.isBuffer(body)) {
        if (headers['Content-Type'] === 'application/json') {
          body = JSON.stringify(body);
        } else {
          body = new URLSearchParams(body).toString();
          options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }
      }
      options.headers['Content-Length'] = Buffer.byteLength(body);
    }

    const req = http.request(options, (res) => {
      let raw = '';
      res.on('data', chunk => { raw += chunk; });
      res.on('end', () => {
        let parsed = raw;
        try { parsed = JSON.parse(raw); } catch (e) {}
        resolve({ status: res.statusCode, headers: res.headers, body: parsed, raw });
      });
    });

    req.on('error', reject);
    if (body && (method === 'POST' || method === 'PUT')) req.write(body);
    req.end();
  });
}

function basicAuthHeader(client) {
  return 'Basic ' + Buffer.from(client.client_id + ':' + client.client_secret).toString('base64');
}

module.exports = {
  createTestConfig,
  startTestApp,
  stopTestApp,
  request,
  basicAuthHeader
};
