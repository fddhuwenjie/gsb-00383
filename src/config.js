const path = require('path');

const ROOT = path.join(__dirname, '..');

// Fixed protocol/token defaults live here so no other module hard-codes them.
const DEFAULTS = {
  accessTokenTTL: 3600,
  refreshTokenTTL: 86400 * 30,
  authorizationCodeTTL: 600,
  defaultScopes: ['openid', 'profile', 'email']
};

function pick(overrides, key, envValue, fallback) {
  if (overrides[key] !== undefined) return overrides[key];
  if (envValue !== undefined && envValue !== null && envValue !== '') return envValue;
  return fallback;
}

/**
 * Build the single source of truth for service configuration.
 *
 * Environment variables and defaults are read exactly once, here. The service
 * entry point calls this and injects the returned object into every module, so
 * nothing else reads process.env or invents its own defaults.
 *
 * Supported env / override keys:
 *   PORT / port
 *   ISSUER / issuer                     (if unset, derived from the listen address)
 *   DB_PATH / dbPath
 *   PRIVATE_KEY_PATH / privateKeyPath
 *   PUBLIC_KEY_PATH / publicKeyPath
 */
function loadConfig(overrides = {}) {
  const env = process.env;

  const port = Number(pick(overrides, 'port', env.PORT, 3000));

  // Track whether the issuer was pinned explicitly; if not, resolveIssuer()
  // will derive it from the actual bound address once the server listens.
  const issuerExplicit = overrides.issuer !== undefined ||
    (env.ISSUER !== undefined && env.ISSUER !== null && env.ISSUER !== '');

  const config = {
    port,
    issuer: issuerExplicit
      ? pick(overrides, 'issuer', env.ISSUER, null)
      : `http://localhost:${port}`,
    issuerExplicit,
    dbPath: pick(overrides, 'dbPath', env.DB_PATH, path.join(ROOT, 'data', 'auth.db')),
    privateKeyPath: pick(overrides, 'privateKeyPath', env.PRIVATE_KEY_PATH, path.join(ROOT, 'keys', 'private.pem')),
    publicKeyPath: pick(overrides, 'publicKeyPath', env.PUBLIC_KEY_PATH, path.join(ROOT, 'keys', 'public.pem')),
    accessTokenTTL: pick(overrides, 'accessTokenTTL', undefined, DEFAULTS.accessTokenTTL),
    refreshTokenTTL: pick(overrides, 'refreshTokenTTL', undefined, DEFAULTS.refreshTokenTTL),
    authorizationCodeTTL: pick(overrides, 'authorizationCodeTTL', undefined, DEFAULTS.authorizationCodeTTL),
    defaultScopes: overrides.defaultScopes || DEFAULTS.defaultScopes.slice()
  };

  return config;
}

/**
 * Finalize the issuer from the address the server actually bound to.
 *
 * When ISSUER was not pinned explicitly, the issuer is derived from the real
 * listen port so tokens are signed/verified against the address clients use.
 * The passed config object is mutated in place; because every module shares the
 * same reference, the update is seen everywhere. Returns the resolved issuer.
 */
function resolveIssuer(config, actualPort) {
  if (!config.issuerExplicit) {
    config.issuer = `http://localhost:${actualPort}`;
  }
  return config.issuer;
}

module.exports = { loadConfig, resolveIssuer };
