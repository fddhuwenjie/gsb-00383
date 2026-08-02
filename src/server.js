const express = require('express');
const { createConfig } = require('./config');
const { initDatabase } = require('./db');
const { initData } = require('./data');
const { initJwt } = require('./jwt');
const { initGrantService } = require('./services/grantService');

const registerRoute = require('./routes/register');
const authorizeRoute = require('./routes/authorize');
const tokenRoute = require('./routes/token');
const introspectRoute = require('./routes/introspect');
const userinfoRoute = require('./routes/userinfo');
const wellKnownRoute = require('./routes/well-known');
const tokenEventsRoute = require('./routes/token-events');

const config = createConfig(process.env);
initDatabase(config);
initData(config);
initJwt(config);
initGrantService(config);

const app = express();
app.locals.config = config;

app.use(express.json());

app.use('/register', registerRoute);
app.use(authorizeRoute);
app.use(tokenRoute);
app.use(introspectRoute);
app.use(userinfoRoute);
app.use(tokenEventsRoute);
app.use('/.well-known', wellKnownRoute);

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

if (require.main === module) {
  app.listen(config.port, () => {
    console.log(`OAuth 2.1 Authorization Server running on http://localhost:${config.port}`);
    console.log(`Discovery: http://localhost:${config.port}/.well-known/openid-configuration`);
    console.log(`JWKS: http://localhost:${config.port}/.well-known/jwks.json`);
    console.log('');
    console.log('Test user: alice / password123');
  });
}

module.exports = app;
