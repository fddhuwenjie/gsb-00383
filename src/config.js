const path = require('path');

const ROOT_DIR = path.join(__dirname, '..');

const defaults = Object.freeze({
  port: 3000,
  host: '0.0.0.0',
  issuer: null,
  dbPath: path.join(ROOT_DIR, 'data', 'auth.db'),
  privateKeyPath: path.join(ROOT_DIR, 'keys', 'private.pem'),
  publicKeyPath: path.join(ROOT_DIR, 'keys', 'public.pem'),
  keyId: 'oauth21-key-1',
  adminApiKey: null,
  accessTokenTTL: 3600,
  refreshTokenTTL: 86400 * 30,
  authorizationCodeTTL: 600,
  defaultScopes: Object.freeze(['openid', 'profile', 'email'])
});

function toInt(value, fallback) {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function normalizeIssuer(issuer) {
  if (!issuer) return null;
  return issuer.replace(/\/+$/, '');
}

function buildConfig(overrides = {}) {
  const merged = { ...defaults, ...overrides };
  merged.defaultScopes = overrides.defaultScopes || defaults.defaultScopes;
  merged.issuer = normalizeIssuer(merged.issuer);
  merged.port = toInt(merged.port, defaults.port);
  return merged;
}

function loadConfig(env = process.env, overrides = {}) {
  const fromEnv = {};

  if (env.PORT !== undefined) fromEnv.port = toInt(env.PORT, defaults.port);
  if (env.HOST !== undefined) fromEnv.host = env.HOST;
  if (env.ISSUER !== undefined) fromEnv.issuer = env.ISSUER;
  if (env.DB_PATH !== undefined) fromEnv.dbPath = env.DB_PATH;
  if (env.PRIVATE_KEY_PATH !== undefined) fromEnv.privateKeyPath = env.PRIVATE_KEY_PATH;
  if (env.PUBLIC_KEY_PATH !== undefined) fromEnv.publicKeyPath = env.PUBLIC_KEY_PATH;
  if (env.KEY_ID !== undefined) fromEnv.keyId = env.KEY_ID;
  if (env.ADMIN_API_KEY !== undefined) fromEnv.adminApiKey = env.ADMIN_API_KEY;
  if (env.ACCESS_TOKEN_TTL !== undefined) fromEnv.accessTokenTTL = toInt(env.ACCESS_TOKEN_TTL, defaults.accessTokenTTL);
  if (env.REFRESH_TOKEN_TTL !== undefined) fromEnv.refreshTokenTTL = toInt(env.REFRESH_TOKEN_TTL, defaults.refreshTokenTTL);
  if (env.AUTHORIZATION_CODE_TTL !== undefined) fromEnv.authorizationCodeTTL = toInt(env.AUTHORIZATION_CODE_TTL, defaults.authorizationCodeTTL);

  return buildConfig({ ...fromEnv, ...overrides });
}

module.exports = {
  defaults,
  buildConfig,
  loadConfig,
  ...loadConfig()
};
