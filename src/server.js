const express = require('express');
const { loadConfig, buildConfig } = require('./config');
const { createDatabase } = require('./db');
const { createJwtService } = require('./jwt');
const { createDataStore } = require('./data');
const { createGrantService } = require('./grantService');

const createRegisterRouter = require('./routes/register');
const createAuthorizeRouter = require('./routes/authorize');
const createTokenRouter = require('./routes/token');
const createIntrospectRouter = require('./routes/introspect');
const createUserinfoRouter = require('./routes/userinfo');
const createWellKnownRouter = require('./routes/well-known');
const createAdminRouter = require('./routes/admin');

function deriveIssuerFromAddress(address) {
  if (!address) return null;
  const host = address.address === '::' || address.address === '0.0.0.0'
    ? 'localhost'
    : address.address;
  return `http://${host}:${address.port}`;
}

function createApp(config) {
  const cfg = buildConfig(config);
  if (config && typeof config === 'object') {
    Object.assign(config, cfg);
  }

  if (!config.issuer) {
    throw new Error('createApp requires a non-empty config.issuer. Resolve it before constructing the app.');
  }

  const db = createDatabase(config);
  const jwt = createJwtService(config);
  const data = createDataStore({ db, config });
  const grantService = createGrantService({
    db,
    config,
    signAccessToken: jwt.signAccessToken,
    getUserById: data.getUserById
  });

  const app = express();
  app.use(express.json());
  app.locals.config = config;

  app.use('/register', createRegisterRouter({
    config,
    registerClient: data.registerClient
  }));

  app.use(createAuthorizeRouter({
    config,
    getClientById: data.getClientById,
    verifyUserPassword: data.verifyUserPassword,
    getUserByUsername: data.getUserByUsername,
    createAuthorizationCode: grantService.createAuthorizationCode
  }));

  app.use(createTokenRouter({
    config,
    getClientById: data.getClientById,
    verifyClientCredentials: data.verifyClientCredentials,
    getUserById: data.getUserById,
    getToken: data.getToken,
    storeToken: data.storeToken,
    signAccessToken: jwt.signAccessToken,
    verifyJwt: jwt.verifyJwt,
    consumeAuthorizationCode: grantService.consumeAuthorizationCode,
    issueTokenPair: grantService.issueTokenPair,
    rotateRefreshToken: grantService.rotateRefreshToken,
    GrantServiceError: grantService.GrantServiceError
  }));

  app.use(createIntrospectRouter({
    getToken: data.getToken,
    revokeToken: data.revokeToken,
    getClientById: data.getClientById,
    verifyClientCredentials: data.verifyClientCredentials,
    isTokenExpired: data.isTokenExpired
  }));

  app.use(createUserinfoRouter({
    verifyJwt: jwt.verifyJwt
  }));

  app.use('/.well-known', createWellKnownRouter({
    config,
    getJwks: jwt.getJwks
  }));

  app.use(createAdminRouter({
    config,
    queryTokenEvents: grantService.queryTokenEvents
  }));

  app.get('/', (req, res) => {
    res.json({
      name: 'OAuth 2.1 Authorization Server',
      status: 'running',
      discovery: '/.well-known/openid-configuration',
      jwks: '/.well-known/jwks.json'
    });
  });

  app.use((req, res) => {
    res.status(404).json({
      error: 'not_found',
      error_description: 'The requested resource was not found'
    });
  });

  app.use((err, req, res, next) => {
    console.error('Unhandled error:', err);
    res.status(500).json({
      error: 'server_error',
      error_description: 'Internal server error'
    });
  });

  return app;
}

function logStartup(config, address) {
  const actual = deriveIssuerFromAddress(address);
  console.log(`OAuth 2.1 Authorization Server running on ${actual}`);
  console.log(`Discovery: ${config.issuer}/.well-known/openid-configuration`);
  console.log(`JWKS: ${config.issuer}/.well-known/jwks.json`);
  console.log('Issuer:', config.issuer);
  console.log('');
  console.log('Test user: alice / password123');
}

function resolveConfig(overrides) {
  const envConfig = loadConfig();
  const built = buildConfig({ ...envConfig, ...overrides });
  if (overrides && typeof overrides === 'object') {
    Object.assign(overrides, built);
    return overrides;
  }
  return built;
}

function start(overrides = {}) {
  const config = resolveConfig(overrides);

  if (config.port !== 0 && !config.issuer) {
    config.issuer = `http://localhost:${config.port}`;
  }

  if (config.port === 0) {
    throw new Error('start() requires a fixed port. Use startAsync() for random ports so the issuer can be derived from the bound address.');
  }

  const app = createApp(config);
  const server = app.listen(config.port, config.host, () => {
    logStartup(config, server.address());
  });
  return server;
}

async function startAsync(overrides = {}) {
  const config = resolveConfig(overrides);
  const explicitIssuerProvided = Boolean(overrides.issuer || process.env.ISSUER);

  if (config.port !== 0 && !config.issuer) {
    config.issuer = `http://localhost:${config.port}`;
  }

  if (config.port === 0 && !explicitIssuerProvided) {
    config.issuer = 'http://localhost';
  }

  const app = createApp(config);

  const server = await new Promise((resolve, reject) => {
    const s = app.listen(config.port, config.host, () => resolve(s));
    s.once('error', reject);
  });

  if (config.port === 0 && !explicitIssuerProvided) {
    const address = server.address();
    config.issuer = deriveIssuerFromAddress(address);
  }

  logStartup(config, server.address());
  return server;
}

if (require.main === module) {
  start();
}

module.exports = { createApp, start, startAsync, deriveIssuerFromAddress };
