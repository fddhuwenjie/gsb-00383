const {
  createAuthorizationCode,
  getAuthorizationCode,
  markAuthorizationCodeUsed,
  getUserById,
  storeToken,
  getToken,
  revokeToken,
  generateRefreshToken,
  recordTokenEvent
} = require('../data');
const { verifyCodeChallenge } = require('../pkce');
const { signAccessToken } = require('../jwt');

let grantConfig = null;

function initGrantService(config) {
  grantConfig = {
    authorizationCodeTTL: config.authorizationCodeTTL,
    accessTokenTTL: config.accessTokenTTL,
    refreshTokenTTL: config.refreshTokenTTL
  };
}

function issueAuthorizationCode({ clientId, userId, redirectUri, scope, codeChallenge, codeChallengeMethod }) {
  return createAuthorizationCode(
    clientId,
    userId,
    redirectUri,
    scope,
    codeChallenge,
    codeChallengeMethod,
    grantConfig.authorizationCodeTTL
  );
}

function findAuthorizationCode(code) {
  return getAuthorizationCode(code);
}

function grantError(status, error, description) {
  return { ok: false, status, error, error_description: description };
}

function invalidGrantError(description) {
  recordTokenEvent('invalid_token_rejected');
  return grantError(400, 'invalid_grant', description);
}

function consumeAuthorizationCode({ code, redirectUri, codeVerifier, client }) {
  const authCode = getAuthorizationCode(code);
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

  if (authCode.client_id !== client.client_id) {
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

  markAuthorizationCodeUsed(authCode.id);

  const user = getUserById(authCode.user_id);
  if (!user) {
    return grantError(400, 'server_error', 'User not found');
  }

  const codeScopes = authCode.scope ? authCode.scope.split(' ').filter(Boolean) : [];
  const clientAllowedScopes = client.allowed_scopes || [];
  const allAllowed = codeScopes.every(s => clientAllowedScopes.includes(s));
  if (!allAllowed) {
    return grantError(400, 'invalid_scope', `Scope exceeds client allowed_scopes. Allowed: ${clientAllowedScopes.join(' ')}`);
  }

  recordTokenEvent('authorization_code_consumed');

  return { ok: true, authCode, user };
}

async function issueTokenPair({ client, user, scope }) {
  const refreshTokenValue = generateRefreshToken();
  const refreshExpiresAt = Math.floor(Date.now() / 1000) + grantConfig.refreshTokenTTL;

  const accessTokenPayload = {
    sub: user.sub,
    scope,
    client_id: client.client_id,
    username: user.username,
    name: user.name,
    email: user.email
  };

  const accessToken = await signAccessToken(accessTokenPayload);

  storeToken('access_token', accessToken, client.client_id, user.id, scope,
    Math.floor(Date.now() / 1000) + grantConfig.accessTokenTTL, refreshTokenValue);

  storeToken('refresh_token', refreshTokenValue, client.client_id, user.id, scope,
    refreshExpiresAt, null);

  return {
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: grantConfig.accessTokenTTL,
    refresh_token: refreshTokenValue,
    scope
  };
}

async function rotateRefreshToken({ refreshToken, scope, client }) {
  const oldRefreshToken = getToken(refreshToken);
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
  if (scope) {
    const requestedScopes = scope.split(' ');
    const originalScopes = oldRefreshToken.scope.split(' ');
    const allInOriginal = requestedScopes.every(s => originalScopes.includes(s));
    if (!allInOriginal) {
      return grantError(400, 'invalid_scope', 'Requested scope exceeds original scope');
    }
    const clientAllowedScopes = client.allowed_scopes || [];
    const allAllowedByClient = requestedScopes.every(s => clientAllowedScopes.includes(s));
    if (!allAllowedByClient) {
      return grantError(400, 'invalid_scope', `Requested scope exceeds client allowed_scopes. Allowed: ${clientAllowedScopes.join(' ')}`);
    }
    newScope = scope;
  } else {
    const originalScopes = oldRefreshToken.scope ? oldRefreshToken.scope.split(' ').filter(Boolean) : [];
    const clientAllowedScopes = client.allowed_scopes || [];
    const allAllowedByClient = originalScopes.every(s => clientAllowedScopes.includes(s));
    if (!allAllowedByClient) {
      return grantError(400, 'invalid_scope', `Original token scope exceeds client allowed_scopes. Allowed: ${clientAllowedScopes.join(' ')}`);
    }
  }

  const user = getUserById(oldRefreshToken.user_id);
  if (!user) {
    return grantError(400, 'server_error', 'User not found');
  }

  const tokens = await issueTokenPair({ client, user, scope: newScope });

  revokeToken(refreshToken);

  recordTokenEvent('refresh_token_rotated');

  return { ok: true, tokens };
}

module.exports = {
  initGrantService,
  issueAuthorizationCode,
  findAuthorizationCode,
  consumeAuthorizationCode,
  issueTokenPair,
  rotateRefreshToken
};
