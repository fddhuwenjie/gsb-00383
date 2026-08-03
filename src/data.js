const crypto = require('crypto');

function createDataStore({ db, config }) {
  const cfg = config;

  function generateClientId() {
    return 'client_' + crypto.randomBytes(16).toString('hex');
  }

  function generateClientSecret() {
    return crypto.randomBytes(32).toString('hex');
  }

  function registerClient(clientName, clientType, redirectUris, grantTypes, allowedScopes) {
    const clientId = generateClientId();
    const clientSecret = clientType === 'confidential' ? generateClientSecret() : null;
    const now = Math.floor(Date.now() / 1000);
    const scopes = allowedScopes && Array.isArray(allowedScopes) && allowedScopes.length > 0
      ? allowedScopes
      : cfg.defaultScopes;

    db.prepare(`
      INSERT INTO clients (client_id, client_secret, client_name, client_type, redirect_uris, grant_types, allowed_scopes, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      clientId,
      clientSecret,
      clientName,
      clientType,
      JSON.stringify(redirectUris),
      JSON.stringify(grantTypes),
      JSON.stringify(scopes),
      now
    );

    return {
      client_id: clientId,
      client_secret: clientSecret,
      client_name: clientName,
      client_type: clientType,
      redirect_uris: redirectUris,
      grant_types: grantTypes,
      allowed_scopes: scopes,
      created_at: now
    };
  }

  function getClientById(clientId) {
    const row = db.prepare('SELECT * FROM clients WHERE client_id = ?').get(clientId);
    if (!row) return null;

    return {
      ...row,
      redirect_uris: JSON.parse(row.redirect_uris),
      grant_types: JSON.parse(row.grant_types),
      allowed_scopes: row.allowed_scopes ? JSON.parse(row.allowed_scopes) : cfg.defaultScopes
    };
  }

  function verifyClientCredentials(clientId, clientSecret) {
    const client = getClientById(clientId);
    if (!client) return false;
    if (client.client_type === 'confidential') {
      return client.client_secret === clientSecret;
    }
    return true;
  }

  function getUserByUsername(username) {
    return db.prepare('SELECT * FROM users WHERE username = ?').get(username) || null;
  }

  function getUserById(userId) {
    return db.prepare('SELECT * FROM users WHERE id = ?').get(userId) || null;
  }

  function verifyUserPassword(username, password) {
    const user = getUserByUsername(username);
    if (!user) return false;
    const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
    return user.password_hash === passwordHash;
  }

  function storeToken(tokenType, tokenValue, clientId, userId, scope, expiresAt, associatedRefresh) {
    const now = Math.floor(Date.now() / 1000);
    db.prepare(`
      INSERT INTO tokens (token_type, token_value, client_id, user_id, scope, expires_at, associated_refresh, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(tokenType, tokenValue, clientId, userId, scope, expiresAt, associatedRefresh || null, now);
  }

  function getToken(tokenValue) {
    return db.prepare('SELECT * FROM tokens WHERE token_value = ?').get(tokenValue) || null;
  }

  function revokeToken(tokenValue) {
    const result = db.prepare('UPDATE tokens SET revoked = 1 WHERE token_value = ?').run(tokenValue);
    return result.changes > 0;
  }

  function isTokenRevoked(tokenValue) {
    const token = getToken(tokenValue);
    if (!token) return true;
    return token.revoked === 1;
  }

  function isTokenExpired(tokenRow) {
    if (!tokenRow.expires_at) return false;
    return Math.floor(Date.now() / 1000) > tokenRow.expires_at;
  }

  function generateRefreshToken() {
    return 'refresh_' + crypto.randomBytes(32).toString('hex');
  }

  return {
    registerClient,
    getClientById,
    verifyClientCredentials,
    getUserByUsername,
    getUserById,
    verifyUserPassword,
    storeToken,
    getToken,
    revokeToken,
    isTokenRevoked,
    isTokenExpired,
    generateRefreshToken
  };
}

module.exports = { createDataStore };
