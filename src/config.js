const path = require('path');

const projectRoot = path.join(__dirname, '..');

const DEFAULTS = Object.freeze({
  port: 3000,
  issuer: null,
  dbPath: path.join(projectRoot, 'data', 'auth.db'),
  privateKeyPath: path.join(projectRoot, 'keys', 'private.pem'),
  publicKeyPath: path.join(projectRoot, 'keys', 'public.pem'),
  accessTokenTTL: 3600,
  refreshTokenTTL: 86400 * 30,
  authorizationCodeTTL: 600,
  defaultScopes: Object.freeze(['openid', 'profile', 'email'])
});

function toInt(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = parseInt(value, 10);
  return Number.isNaN(parsed) ? fallback : parsed;
}

function loadConfig(env = process.env, overrides = {}) {
  const config = {
    port: toInt(env.PORT, DEFAULTS.port),
    issuer: env.ISSUER || DEFAULTS.issuer,
    dbPath: env.DB_PATH || DEFAULTS.dbPath,
    privateKeyPath: env.PRIVATE_KEY_PATH || DEFAULTS.privateKeyPath,
    publicKeyPath: env.PUBLIC_KEY_PATH || DEFAULTS.publicKeyPath,
    accessTokenTTL: toInt(env.ACCESS_TOKEN_TTL, DEFAULTS.accessTokenTTL),
    refreshTokenTTL: toInt(env.REFRESH_TOKEN_TTL, DEFAULTS.refreshTokenTTL),
    authorizationCodeTTL: toInt(env.AUTHORIZATION_CODE_TTL, DEFAULTS.authorizationCodeTTL),
    defaultScopes: [...DEFAULTS.defaultScopes]
  };

  for (const [key, value] of Object.entries(overrides)) {
    if (value !== undefined) {
      config[key] = value;
    }
  }

  return config;
}

module.exports = { loadConfig, DEFAULTS };
