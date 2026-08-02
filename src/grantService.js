const {
  createAuthorizationCode,
  getAuthorizationCode,
  markAuthorizationCodeUsed,
  getUserById,
  storeToken,
  getToken,
  generateRefreshToken,
  revokeToken,
  recordTokenEvent,
  TOKEN_EVENT_TYPES
} = require('./data');
const { verifyCodeChallenge } = require('./pkce');
const { signAccessToken } = require('./jwt');

let config;

// Receive the shared config object from the entry point (token TTLs).
function configure(cfg) {
  config = cfg;
}

/**
 * Grant service for the OAuth 2.1 authorization_code and refresh_token grants.
 *
 * Owns the lifecycle of authorization codes (creation, lookup, single-use
 * consumption) and of issued token pairs (access + refresh token issuance and
 * refresh token rotation). Routes should call these helpers and translate the
 * results into protocol responses rather than touching the authorization_codes
 * or tokens tables directly.
 */

// Shape a failed consumption so the route can render an OAuth error response
// without knowing anything about the code record itself.
function grantError(status, error, description) {
  return { ok: false, status, error, error_description: description };
}

// An invalid_grant rejection means an invalid, expired, mismatched or reused
// code/token was presented. Record the event (type + time only) and return the
// protocol error. No code or token value is ever passed to the recorder.
function invalidGrantError(description) {
  recordTokenEvent(TOKEN_EVENT_TYPES.INVALID_TOKEN_REJECTED);
  return grantError(400, 'invalid_grant', description);
}

/**
 * Issue (create + persist) a new authorization code.
 * Returns the opaque code string, exactly like createAuthorizationCode.
 */
function issueAuthorizationCode(clientId, userId, redirectUri, scope, codeChallenge, codeChallengeMethod, ttl) {
  return createAuthorizationCode(
    clientId,
    userId,
    redirectUri,
    scope,
    codeChallenge,
    codeChallengeMethod,
    ttl
  );
}

/**
 * Look up an authorization code record by its opaque value.
 * Returns the raw record or null.
 */
function findAuthorizationCode(code) {
  return getAuthorizationCode(code);
}

/**
 * Validate and consume an authorization code in a single step.
 *
 * On success the code is marked as used and the record is returned so the
 * caller can issue tokens. On failure a protocol-shaped error is returned.
 * The validation order and error codes/descriptions match the original
 * token endpoint behaviour so existing clients and E2E tests stay green.
 *
 * @param {object} params
 * @param {string} params.code          - the authorization code value
 * @param {string} params.clientId      - authenticated client_id
 * @param {string} params.redirectUri   - redirect_uri from the token request
 * @param {string} params.codeVerifier  - PKCE code_verifier from the request
 */
function consumeAuthorizationCode({ code, clientId, redirectUri, codeVerifier }) {
  const authCode = findAuthorizationCode(code);
  if (!authCode) {
    return invalidGrantError('Invalid authorization code');
  }

  if (authCode.used === 1) {
    return invalidGrantError('Authorization code has already been used');
  }

  const now = Math.floor(Date.now() / 1000);
  if (authCode.expires_at < now) {
    return invalidGrantError('Authorization code has expired');
  }

  if (authCode.client_id !== clientId) {
    return invalidGrantError('Authorization code was not issued to this client');
  }

  if (authCode.redirect_uri !== redirectUri) {
    return invalidGrantError('redirect_uri does not match');
  }

  if (authCode.code_challenge_method === 'S256') {
    if (!verifyCodeChallenge(codeVerifier, authCode.code_challenge)) {
      return invalidGrantError('PKCE verification failed');
    }
  } else {
    return invalidGrantError('Unsupported code challenge method');
  }

  // Single use: mark consumed before the caller mints any tokens so a replay
  // of the same code is rejected by the used check above.
  markAuthorizationCodeUsed(authCode.id);
  recordTokenEvent(TOKEN_EVENT_TYPES.AUTHORIZATION_CODE_CONSUMED);

  return { ok: true, authCode };
}

/**
 * Build the JWT access-token payload from a user record and scope.
 * Shared by both grants so the emitted claims stay identical.
 */
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

/**
 * Issue a fresh access-token / refresh-token pair and persist both records.
 *
 * The access token is linked to the refresh token via associated_refresh so
 * revoking the refresh family works as before. Returns the protocol response
 * body fields (access_token, token_type, expires_in, refresh_token, scope).
 *
 * @param {object} params
 * @param {object} params.user      - user record (needs id, sub, username, name, email)
 * @param {string} params.clientId  - client the tokens are issued to
 * @param {string} params.scope     - granted scope string
 */
async function issueTokenPair({ user, clientId, scope }) {
  const refreshTokenValue = generateRefreshToken();
  const now = Math.floor(Date.now() / 1000);
  const refreshExpiresAt = now + config.refreshTokenTTL;

  const accessToken = await signAccessToken(buildAccessTokenPayload(user, clientId, scope));

  storeToken('access_token', accessToken, clientId, user.id, scope,
    now + config.accessTokenTTL, refreshTokenValue);

  storeToken('refresh_token', refreshTokenValue, clientId, user.id, scope,
    refreshExpiresAt, null);

  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: config.accessTokenTTL,
    refresh_token: refreshTokenValue,
    scope
  };
}

/**
 * Validate a refresh token and rotate it for a brand new token pair.
 *
 * On success the old refresh token is revoked (rotation) and a fresh pair is
 * issued. On failure a protocol-shaped error is returned. Validation order and
 * error codes/descriptions match the original token endpoint so existing
 * clients and E2E tests stay green.
 *
 * @param {object} params
 * @param {object} params.client               - authenticated client record
 * @param {string} params.refreshTokenValue     - refresh_token from the request
 * @param {string} [params.requestedScope]       - optional narrowed scope
 */
async function rotateRefreshToken({ client, refreshTokenValue, requestedScope }) {
  const oldRefreshToken = getToken(refreshTokenValue);
  if (!oldRefreshToken || oldRefreshToken.token_type !== 'refresh_token') {
    return invalidGrantError('Invalid refresh token');
  }

  if (oldRefreshToken.revoked === 1) {
    return invalidGrantError('Refresh token has been revoked');
  }

  const now = Math.floor(Date.now() / 1000);
  if (oldRefreshToken.expires_at && oldRefreshToken.expires_at < now) {
    return invalidGrantError('Refresh token has expired');
  }

  if (oldRefreshToken.client_id !== client.client_id) {
    return invalidGrantError('Refresh token was not issued to this client');
  }

  let newScope = oldRefreshToken.scope;
  const clientAllowedScopes = client.allowed_scopes || [];
  if (requestedScope) {
    const requestedScopes = requestedScope.split(' ');
    const originalScopes = oldRefreshToken.scope.split(' ');
    const allInOriginal = requestedScopes.every(s => originalScopes.includes(s));
    if (!allInOriginal) {
      return grantError(400, 'invalid_scope', 'Requested scope exceeds original scope');
    }
    const allAllowedByClient = requestedScopes.every(s => clientAllowedScopes.includes(s));
    if (!allAllowedByClient) {
      return grantError(400, 'invalid_scope',
        `Requested scope exceeds client allowed_scopes. Allowed: ${clientAllowedScopes.join(' ')}`);
    }
    newScope = requestedScope;
  } else {
    const originalScopes = oldRefreshToken.scope ? oldRefreshToken.scope.split(' ').filter(Boolean) : [];
    const allAllowedByClient = originalScopes.every(s => clientAllowedScopes.includes(s));
    if (!allAllowedByClient) {
      return grantError(400, 'invalid_scope',
        `Original token scope exceeds client allowed_scopes. Allowed: ${clientAllowedScopes.join(' ')}`);
    }
  }

  const user = getUserById(oldRefreshToken.user_id);
  if (!user) {
    return grantError(400, 'server_error', 'User not found');
  }

  const tokens = await issueTokenPair({ user, clientId: client.client_id, scope: newScope });

  // Rotation: the presented refresh token can never be used again.
  revokeToken(refreshTokenValue);
  recordTokenEvent(TOKEN_EVENT_TYPES.REFRESH_TOKEN_ROTATED);

  return { ok: true, tokens };
}

module.exports = {
  configure,
  issueAuthorizationCode,
  findAuthorizationCode,
  consumeAuthorizationCode,
  issueTokenPair,
  rotateRefreshToken
};
