const { getDb } = require('./db');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const config = require('./config');

function generateClientId() {
  return 'client_' + crypto.randomBytes(16).toString('hex');
}

function generateClientSecret() {
  return crypto.randomBytes(32).toString('hex');
}

function registerClient(clientName, clientType, redirectUris, grantTypes, allowedScopes) {
  const db = getDb();
  const clientId = generateClientId();
  const clientSecret = clientType === 'confidential' ? generateClientSecret() : null;
  const now = Math.floor(Date.now() / 1000);
  const scopes = allowedScopes && Array.isArray(allowedScopes) && allowedScopes.length > 0
    ? allowedScopes
    : config.defaultScopes;

  const stmt = db.prepare(`
    INSERT INTO clients (client_id, client_secret, client_name, client_type, redirect_uris, grant_types, allowed_scopes, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(
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
  const db = getDb();
  const row = db.prepare('SELECT * FROM clients WHERE client_id = ?').get(clientId);
  if (!row) return null;

  return {
    ...row,
    redirect_uris: JSON.parse(row.redirect_uris),
    grant_types: JSON.parse(row.grant_types),
    allowed_scopes: row.allowed_scopes ? JSON.parse(row.allowed_scopes) : config.defaultScopes
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

function createAuthorizationCode(clientId, userId, redirectUri, scope, codeChallenge, codeChallengeMethod, ttl) {
  const db = getDb();
  const code = uuidv4();
  const expiresAt = Math.floor(Date.now() / 1000) + ttl;

  db.prepare(`
    INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(code, clientId, userId, redirectUri, scope, codeChallenge, codeChallengeMethod, expiresAt);

  return code;
}

function getAuthorizationCode(code) {
  const db = getDb();
  const row = db.prepare('SELECT * FROM authorization_codes WHERE code = ?').get(code);
  return row || null;
}

function markAuthorizationCodeUsed(codeId) {
  const db = getDb();
  db.prepare('UPDATE authorization_codes SET used = 1 WHERE id = ?').run(codeId);
}

function getUserByUsername(username) {
  const db = getDb();
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username) || null;
}

function getUserById(userId) {
  const db = getDb();
  return db.prepare('SELECT * FROM users WHERE id = ?').get(userId) || null;
}

function verifyUserPassword(username, password) {
  const db = getDb();
  const user = getUserByUsername(username);
  if (!user) return false;
  const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
  return user.password_hash === passwordHash;
}

function storeToken(tokenType, tokenValue, clientId, userId, scope, expiresAt, associatedRefresh) {
  const db = getDb();
  const now = Math.floor(Date.now() / 1000);

  db.prepare(`
    INSERT INTO tokens (token_type, token_value, client_id, user_id, scope, expires_at, associated_refresh, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(tokenType, tokenValue, clientId, userId, scope, expiresAt, associatedRefresh || null, now);
}

function getToken(tokenValue) {
  const db = getDb();
  return db.prepare('SELECT * FROM tokens WHERE token_value = ?').get(tokenValue) || null;
}

function revokeToken(tokenValue) {
  const db = getDb();
  const result = db.prepare('UPDATE tokens SET revoked = 1 WHERE token_value = ?').run(tokenValue);
  return result.changes > 0;
}

function revokeRefreshTokenFamily(refreshTokenValue) {
  const db = getDb();
  const token = getToken(refreshTokenValue);
  if (!token) return false;
  db.prepare('UPDATE tokens SET revoked = 1 WHERE associated_refresh = ? OR token_value = ?')
    .run(refreshTokenValue, refreshTokenValue);
  return true;
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

module.exports = {
  registerClient,
  getClientById,
  verifyClientCredentials,
  createAuthorizationCode,
  getAuthorizationCode,
  markAuthorizationCodeUsed,
  getUserByUsername,
  getUserById,
  verifyUserPassword,
  storeToken,
  getToken,
  revokeToken,
  revokeRefreshTokenFamily,
  isTokenRevoked,
  isTokenExpired,
  generateRefreshToken
};
