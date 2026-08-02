const { loadConfig } = require('../../src/config');
const { initDatabase, getDb } = require('../../src/db');
const { createData } = require('../../src/data');
const { createJwtService } = require('../../src/jwt');
const { createGrantService } = require('../../src/grantService');
const { buildApp } = require('../../src/server');
const pkce = require('../../src/pkce');

const config = loadConfig({}, {
  dbPath: ':memory:',
  port: 0,
  issuer: null
});

initDatabase(config.dbPath);

const data = createData({ defaultScopes: config.defaultScopes });
const jwt = createJwtService({ config });
const grantService = createGrantService({ config, data });

const REDIRECT_URI = 'http://localhost:8080/callback';
const ALLOWED_SCOPES = ['openid', 'profile', 'email'];

function seedConfidentialClient() {
  return data.registerClient(
    'Test Confidential Client',
    'confidential',
    [REDIRECT_URI],
    ['authorization_code', 'refresh_token'],
    ALLOWED_SCOPES
  );
}

function seedPublicClient() {
  return data.registerClient(
    'Test Public Client',
    'public',
    [REDIRECT_URI],
    ['authorization_code', 'refresh_token'],
    ALLOWED_SCOPES
  );
}

function getDefaultUser() {
  return data.getUserByUsername('alice');
}

async function startTestServer() {
  const app = buildApp({ config, data, jwt, grantService });
  const server = await new Promise((resolve) => {
    const s = app.listen(0, () => {
      if (!config.issuer) {
        const address = s.address();
        config.issuer = `http://127.0.0.1:${address.port}`;
      }
      resolve(s);
    });
  });
  const baseUrl = config.issuer;
  return {
    baseUrl,
    close: () => new Promise((resolve) => server.close(resolve))
  };
}

function pkcePair() {
  const verifier = pkce.generateCodeVerifier();
  const challenge = pkce.generateCodeChallenge(verifier);
  return { verifier, challenge, method: 'S256' };
}

module.exports = {
  config,
  getDb,
  data,
  jwt,
  grantService,
  TOKEN_EVENT_TYPES: grantService.TOKEN_EVENT_TYPES,
  seedConfidentialClient,
  seedPublicClient,
  getDefaultUser,
  startTestServer,
  pkcePair,
  generateCodeVerifier: pkce.generateCodeVerifier,
  generateCodeChallenge: pkce.generateCodeChallenge,
  verifyCodeChallenge: pkce.verifyCodeChallenge,
  REDIRECT_URI,
  ALLOWED_SCOPES
};
