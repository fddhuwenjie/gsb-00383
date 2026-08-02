const express = require('express');
const { loadConfig } = require('./config');
const { initDatabase } = require('./db');
const { createData } = require('./data');
const { createJwtService } = require('./jwt');
const { createGrantService } = require('./grantService');

const createRegisterRoute = require('./routes/register');
const createAuthorizeRoute = require('./routes/authorize');
const createTokenRoute = require('./routes/token');
const createIntrospectRoute = require('./routes/introspect');
const createUserinfoRoute = require('./routes/userinfo');
const createWellKnownRoute = require('./routes/well-known');
const createAdminRoute = require('./routes/admin');

function buildApp({ config, data, jwt, grantService }) {
  const app = express();

  app.use(express.json());

  app.use('/register', createRegisterRoute({ config, data }));
  app.use(createAuthorizeRoute({ config, data, grantService }));
  app.use(createTokenRoute({ config, data, jwt, grantService }));
  app.use(createIntrospectRoute({ data }));
  app.use(createUserinfoRoute({ jwt }));
  app.use('/.well-known', createWellKnownRoute({ config, jwt }));
  app.use('/admin', createAdminRoute({ data }));

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

function compose(config) {
  initDatabase(config.dbPath);
  const data = createData({ defaultScopes: config.defaultScopes });
  const jwt = createJwtService({ config });
  const grantService = createGrantService({ config, data });
  const app = buildApp({ config, data, jwt, grantService });
  return { app, config, data, jwt, grantService };
}

function deriveIssuer(server, config) {
  if (config.issuer) {
    return config.issuer;
  }
  const address = server.address();
  const host = address.address === '::' || address.address === '0.0.0.0'
    ? 'localhost'
    : address.address;
  config.issuer = `http://${host}:${address.port}`;
  return config.issuer;
}

function start(overrides = {}) {
  const config = loadConfig(process.env, overrides);
  const { app } = compose(config);

  const server = app.listen(config.port, () => {
    const issuer = deriveIssuer(server, config);
    if (require.main === module) {
      console.log(`OAuth 2.1 Authorization Server running on ${issuer}`);
      console.log(`Discovery: ${issuer}/.well-known/openid-configuration`);
      console.log(`JWKS: ${issuer}/.well-known/jwks.json`);
      console.log('');
      console.log('Test user: alice / password123');
    }
  });

  server.config = config;
  return server;
}

if (require.main === module) {
  start();
}

module.exports = { start, compose, buildApp, deriveIssuer };
