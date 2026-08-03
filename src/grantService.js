const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { verifyCodeChallenge } = require('./pkce');

const TOKEN_EVENT_TYPES = Object.freeze({
  AUTHORIZATION_CODE_CONSUMED: 'authorization_code_consumed',
  REFRESH_TOKEN_ROTATED: 'refresh_token_rotated',
  INVALID_TOKEN_REJECTED: 'invalid_token_rejected'
});

class GrantServiceError extends Error {
  constructor(error, description, status = 400) {
    super(description);
    this.name = 'GrantServiceError';
    this.error = error;
    this.error_description = description;
    this.status = status;
  }
}

function createGrantService({ db, config, signAccessToken, getUserById }) {
  const cfg = config;

  function recordTokenEvent(eventType) {
    const occurredAt = Math.floor(Date.now() / 1000);
    const info = db.prepare(`
      INSERT INTO token_events (event_type, occurred_at)
      VALUES (?, ?)
    `).run(eventType, occurredAt);
    return { id: info.lastInsertRowid, event_type: eventType, occurred_at: occurredAt };
  }

  function queryTokenEvents({ eventType, limit } = {}) {
    const maxRows = Number.isInteger(limit) && limit > 0 ? Math.min(limit, 1000) : 100;
    if (eventType) {
      return db.prepare(`
        SELECT id, event_type, occurred_at
        FROM token_events
        WHERE event_type = ?
        ORDER BY occurred_at ASC, id ASC
        LIMIT ?
      `).all(eventType, maxRows);
    }
    return db.prepare(`
      SELECT id, event_type, occurred_at
      FROM token_events
      ORDER BY occurred_at ASC, id ASC
      LIMIT ?
    `).all(maxRows);
  }

  function generateCode() {
    return uuidv4();
  }

  function generateRefreshTokenValue() {
    return 'refresh_' + crypto.randomBytes(32).toString('hex');
  }

  function buildAccessTokenPayload(user, clientId, scope) {
    return {
      sub: user.sub,
      scope,
      client_id: clientId,
      username: user.username,
      name: user.name,
      email: user.email
    };
  }

  function createAuthorizationCode({
    clientId,
    userId,
    redirectUri,
    scope,
    codeChallenge,
    codeChallengeMethod,
    ttl
  }) {
    if (!clientId || !userId || !redirectUri || scope === undefined || !codeChallenge) {
      throw new GrantServiceError('server_error', 'Missing required fields for authorization code', 500);
    }

    const method = codeChallengeMethod || 'S256';
    if (method !== 'S256') {
      throw new GrantServiceError('invalid_request', 'Only S256 code challenge method is supported');
    }

    const code = generateCode();
    const lifetime = ttl || cfg.authorizationCodeTTL;
    const expiresAt = Math.floor(Date.now() / 1000) + lifetime;

    db.prepare(`
      INSERT INTO authorization_codes
        (code, client_id, user_id, redirect_uri, scope, code_challenge, code_challenge_method, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      code,
      clientId,
      userId,
      redirectUri,
      scope,
      codeChallenge,
      method,
      expiresAt
    );

    return {
      code,
      client_id: clientId,
      user_id: userId,
      redirect_uri: redirectUri,
      scope,
      code_challenge: codeChallenge,
      code_challenge_method: method,
      expires_at: expiresAt
    };
  }

  function getAuthorizationCode(code) {
    if (!code) return null;
    return db.prepare('SELECT * FROM authorization_codes WHERE code = ?').get(code) || null;
  }

  function consumeAuthorizationCode({ code, clientId, redirectUri, codeVerifier }) {
    if (!code) {
      throw new GrantServiceError('invalid_request', 'code is required');
    }
    if (!redirectUri) {
      throw new GrantServiceError('invalid_request', 'redirect_uri is required');
    }
    if (!codeVerifier) {
      throw new GrantServiceError('invalid_request', 'code_verifier is required (PKCE)');
    }

    const consumeTransaction = db.transaction(() => {
      const authCode = db
        .prepare('SELECT * FROM authorization_codes WHERE code = ?')
        .get(code);

      if (!authCode) {
        throw new GrantServiceError('invalid_grant', 'Invalid authorization code');
      }

      if (authCode.used === 1) {
        throw new GrantServiceError('invalid_grant', 'Authorization code has already been used');
      }

      const now = Math.floor(Date.now() / 1000);
      if (authCode.expires_at < now) {
        throw new GrantServiceError('invalid_grant', 'Authorization code has expired');
      }

      if (authCode.client_id !== clientId) {
        throw new GrantServiceError('invalid_grant', 'Authorization code was not issued to this client');
      }

      if (authCode.redirect_uri !== redirectUri) {
        throw new GrantServiceError('invalid_grant', 'redirect_uri does not match');
      }

      if (authCode.code_challenge_method !== 'S256') {
        throw new GrantServiceError('invalid_grant', 'Unsupported code challenge method');
      }

      if (!verifyCodeChallenge(codeVerifier, authCode.code_challenge)) {
        throw new GrantServiceError('invalid_grant', 'PKCE verification failed');
      }

      const result = db
        .prepare('UPDATE authorization_codes SET used = 1 WHERE id = ? AND used = 0')
        .run(authCode.id);

      if (result.changes === 0) {
        throw new GrantServiceError('invalid_grant', 'Authorization code has already been used');
      }

      recordTokenEvent(TOKEN_EVENT_TYPES.AUTHORIZATION_CODE_CONSUMED);

      return authCode;
    });

    try {
      return consumeTransaction();
    } catch (err) {
      if (err instanceof GrantServiceError && err.error === 'invalid_grant') {
        recordTokenEvent(TOKEN_EVENT_TYPES.INVALID_TOKEN_REJECTED);
      }
      throw err;
    }
  }

  async function issueTokenPair({ user, clientId, scope }) {
    if (!user || !clientId || scope === undefined) {
      throw new GrantServiceError('server_error', 'Missing required fields for token issuance', 500);
    }

    const refreshTokenValue = generateRefreshTokenValue();
    const now = Math.floor(Date.now() / 1000);
    const accessExpiresAt = now + cfg.accessTokenTTL;
    const refreshExpiresAt = now + cfg.refreshTokenTTL;

    const accessTokenPayload = buildAccessTokenPayload(user, clientId, scope);
    const accessToken = await signAccessToken(accessTokenPayload);

    db.transaction(() => {
      db.prepare(`
        INSERT INTO tokens (token_type, token_value, client_id, user_id, scope, expires_at, associated_refresh, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        'access_token',
        accessToken,
        clientId,
        user.id,
        scope,
        accessExpiresAt,
        refreshTokenValue,
        now
      );

      db.prepare(`
        INSERT INTO tokens (token_type, token_value, client_id, user_id, scope, expires_at, associated_refresh, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        'refresh_token',
        refreshTokenValue,
        clientId,
        user.id,
        scope,
        refreshExpiresAt,
        null,
        now
      );
    })();

    return {
      access_token: accessToken,
      refresh_token: refreshTokenValue,
      token_type: 'Bearer',
      expires_in: cfg.accessTokenTTL,
      scope
    };
  }

  function resolveRefreshScope(oldToken, requestedScope, clientAllowedScopes) {
    const originalScopes = oldToken.scope ? oldToken.scope.split(' ').filter(Boolean) : [];
    const allowedScopes = clientAllowedScopes || [];

    if (requestedScope) {
      const requestedScopes = requestedScope.split(' ').filter(Boolean);

      const allInOriginal = requestedScopes.every(s => originalScopes.includes(s));
      if (!allInOriginal) {
        throw new GrantServiceError('invalid_scope', 'Requested scope exceeds original scope');
      }

      const allAllowedByClient = requestedScopes.every(s => allowedScopes.includes(s));
      if (!allAllowedByClient) {
        throw new GrantServiceError(
          'invalid_scope',
          `Requested scope exceeds client allowed_scopes. Allowed: ${allowedScopes.join(' ')}`
        );
      }

      return requestedScope;
    }

    const allAllowedByClient = originalScopes.every(s => allowedScopes.includes(s));
    if (!allAllowedByClient) {
      throw new GrantServiceError(
        'invalid_scope',
        `Original token scope exceeds client allowed_scopes. Allowed: ${allowedScopes.join(' ')}`
      );
    }

    return oldToken.scope;
  }

  function consumeRefreshToken({ refreshTokenValue, clientId, scope, clientAllowedScopes }) {
    if (!refreshTokenValue) {
      throw new GrantServiceError('invalid_request', 'refresh_token is required');
    }

    const now = Math.floor(Date.now() / 1000);

    let oldToken;
    let newScope;
    let user;

    db.transaction(() => {
      oldToken = db
        .prepare('SELECT * FROM tokens WHERE token_value = ? AND token_type = ?')
        .get(refreshTokenValue, 'refresh_token');

      if (!oldToken) {
        throw new GrantServiceError('invalid_grant', 'Invalid refresh token');
      }

      if (oldToken.revoked === 1) {
        throw new GrantServiceError('invalid_grant', 'Refresh token has been revoked');
      }

      if (oldToken.expires_at && oldToken.expires_at < now) {
        throw new GrantServiceError('invalid_grant', 'Refresh token has expired');
      }

      if (oldToken.client_id !== clientId) {
        throw new GrantServiceError('invalid_grant', 'Refresh token was not issued to this client');
      }

      newScope = resolveRefreshScope(oldToken, scope, clientAllowedScopes);

      const revokeResult = db
        .prepare('UPDATE tokens SET revoked = 1 WHERE id = ? AND revoked = 0')
        .run(oldToken.id);

      if (revokeResult.changes === 0) {
        throw new GrantServiceError('invalid_grant', 'Refresh token has been revoked');
      }

      user = getUserById(oldToken.user_id);
      if (!user) {
        throw new GrantServiceError('server_error', 'User not found');
      }
    })();

    return { oldToken, newScope, user, now };
  }

  async function rotateRefreshToken({ refreshTokenValue, clientId, scope, clientAllowedScopes }) {
    let consumed;
    try {
      consumed = consumeRefreshToken({
        refreshTokenValue,
        clientId,
        scope,
        clientAllowedScopes
      });
    } catch (err) {
      if (err instanceof GrantServiceError && err.error === 'invalid_grant') {
        recordTokenEvent(TOKEN_EVENT_TYPES.INVALID_TOKEN_REJECTED);
      }
      throw err;
    }

    const { user, newScope, now } = consumed;

    const newRefreshTokenValue = generateRefreshTokenValue();
    const accessExpiresAt = now + cfg.accessTokenTTL;
    const refreshExpiresAt = now + cfg.refreshTokenTTL;

    const accessTokenPayload = buildAccessTokenPayload(user, clientId, newScope);
    const newAccessToken = await signAccessToken(accessTokenPayload);

    db.transaction(() => {
      db.prepare(`
        INSERT INTO tokens (token_type, token_value, client_id, user_id, scope, expires_at, associated_refresh, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        'access_token',
        newAccessToken,
        clientId,
        user.id,
        newScope,
        accessExpiresAt,
        newRefreshTokenValue,
        now
      );

      db.prepare(`
        INSERT INTO tokens (token_type, token_value, client_id, user_id, scope, expires_at, associated_refresh, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        'refresh_token',
        newRefreshTokenValue,
        clientId,
        user.id,
        newScope,
        refreshExpiresAt,
        null,
        now
      );

      recordTokenEvent(TOKEN_EVENT_TYPES.REFRESH_TOKEN_ROTATED);
    })();

    return {
      access_token: newAccessToken,
      refresh_token: newRefreshTokenValue,
      token_type: 'Bearer',
      expires_in: cfg.accessTokenTTL,
      scope: newScope
    };
  }

  return {
    TOKEN_EVENT_TYPES,
    createAuthorizationCode,
    getAuthorizationCode,
    consumeAuthorizationCode,
    issueTokenPair,
    rotateRefreshToken,
    recordTokenEvent,
    queryTokenEvents,
    GrantServiceError
  };
}

module.exports = { createGrantService, GrantServiceError };
