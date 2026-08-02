const path = require('path');

const DEFAULTS = {
  port: 3000,
  dbPath: path.join(__dirname, '..', 'data', 'auth.db'),
  privateKeyPath: path.join(__dirname, '..', 'keys', 'private.pem'),
  publicKeyPath: path.join(__dirname, '..', 'keys', 'public.pem'),
  accessTokenTTL: 3600,
  refreshTokenTTL: 86400 * 30,
  authorizationCodeTTL: 600,
  defaultScopes: ['openid', 'profile', 'email']
};

function createConfig(env = {}) {
  const port = Number(env.PORT) || DEFAULTS.port;
  return {
    port,
    issuer: env.ISSUER || `http://localhost:${port}`,
    dbPath: env.DB_PATH || DEFAULTS.dbPath,
    privateKeyPath: env.PRIVATE_KEY_PATH || DEFAULTS.privateKeyPath,
    publicKeyPath: env.PUBLIC_KEY_PATH || DEFAULTS.publicKeyPath,
    accessTokenTTL: DEFAULTS.accessTokenTTL,
    refreshTokenTTL: DEFAULTS.refreshTokenTTL,
    authorizationCodeTTL: DEFAULTS.authorizationCodeTTL,
    defaultScopes: [...DEFAULTS.defaultScopes]
  };
}

module.exports = { createConfig, DEFAULTS };
