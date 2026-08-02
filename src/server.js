const express = require('express');
const { loadConfig, resolveIssuer } = require('./config');

const db = require('./db');
const data = require('./data');
const jwt = require('./jwt');
const grantService = require('./grantService');

const registerRoute = require('./routes/register');
const authorizeRoute = require('./routes/authorize');
const tokenRoute = require('./routes/token');
const introspectRoute = require('./routes/introspect');
const userinfoRoute = require('./routes/userinfo');
const wellKnownRoute = require('./routes/well-known');
const tokenEventsRoute = require('./routes/token-events');

/**
 * Inject the single shared config object into every module that needs it.
 * Called once by the entry point (and by tests) so no module reads process.env
 * or picks its own defaults. The same object reference is shared everywhere, so
 * a later resolveIssuer() update is visible to all of them.
 */
function configureModules(config) {
  db.configure(config);
  data.configure(config);
  jwt.configure(config);
  grantService.configure(config);

  registerRoute.configure(config);
  authorizeRoute.configure(config);
  tokenRoute.configure(config);
  wellKnownRoute.configure(config);
  // introspect, userinfo and token-events routes derive everything from
  // data/jwt and need no direct config injection.
}

/**
 * Build a fully wired Express app for the given config and initialise the DB.
 * Does not call listen(); callers (entry point or tests) own the server.
 */
function createApp(config) {
  configureModules(config);

  const app = express();
  app.use(express.json());

  app.use('/register', registerRoute);
  app.use(authorizeRoute);
  app.use(tokenRoute);
  app.use(introspectRoute);
  app.use(userinfoRoute);
  app.use('/.well-known', wellKnownRoute);
  app.use(tokenEventsRoute);

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

  db.initDatabase();

  return app;
}

/**
 * Load config, build the app and start listening. Once bound, the issuer is
 * derived from the actual listen address (unless ISSUER was pinned), so tokens
 * are signed/verified against the address clients really use.
 */
function start(overrides = {}) {
  const config = loadConfig(overrides);
  const app = createApp(config);

  const server = app.listen(config.port, () => {
    const actualPort = server.address().port;
    const issuer = resolveIssuer(config, actualPort);
    console.log(`OAuth 2.1 Authorization Server running on http://localhost:${actualPort}`);
    console.log(`Issuer: ${issuer}`);
    console.log(`Discovery: ${issuer}/.well-known/openid-configuration`);
    console.log(`JWKS: ${issuer}/.well-known/jwks.json`);
    console.log('');
    console.log('Test user: alice / password123');
  });

  return server;
}

if (require.main === module) {
  start();
}

module.exports = { createApp, start, configureModules, loadConfig, resolveIssuer };
