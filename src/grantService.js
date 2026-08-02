const { verifyCodeChallenge } = require('./pkce');
const { TOKEN_EVENT_TYPES } = require('./tokenEventTypes');

function createGrantService({ config, data }) {
  function recordEvent(eventType) {
    try {
      data.recordTokenEvent(eventType);
    } catch (err) {
      console.error('Failed to record token event:', err.message);
    }
  }

  function issueAuthorizationCode({
    clientId,
    userId,
    redirectUri,
    scope,
    codeChallenge,
    codeChallengeMethod,
    ttl
  }) {
    const effectiveTtl = typeof ttl === 'number' ? ttl : config.authorizationCodeTTL;
    return data.createAuthorizationCode(
      clientId,
      userId,
      redirectUri,
      scope,
      codeChallenge,
      codeChallengeMethod,
      effectiveTtl
    );
  }

  function fetchAuthorizationCode(code) {
    return data.getAuthorizationCode(code);
  }

  function consumeAuthorizationCode({ code, clientId, redirectUri, codeVerifier }) {
    const failure = (error_description) => ({
      ok: false,
      status: 400,
      error: 'invalid_grant',
      error_description
    });

    const authCode = data.getAuthorizationCode(code);
    let result;

    if (!authCode) {
      result = failure('Invalid authorization code');
    } else if (authCode.used === 1) {
      result = failure('Authorization code has already been used');
    } else if (authCode.expires_at < Math.floor(Date.now() / 1000)) {
      result = failure('Authorization code has expired');
    } else if (authCode.client_id !== clientId) {
      result = failure('Authorization code was not issued to this client');
    } else if (authCode.redirect_uri !== redirectUri) {
      result = failure('redirect_uri does not match');
    } else if (authCode.code_challenge_method !== 'S256') {
      result = failure('Unsupported code challenge method');
    } else if (!verifyCodeChallenge(codeVerifier, authCode.code_challenge)) {
      result = failure('PKCE verification failed');
    } else {
      data.markAuthorizationCodeUsed(authCode.id);
      result = { ok: true, authCode };
    }

    if (result.ok) {
      recordEvent(TOKEN_EVENT_TYPES.AUTHORIZATION_CODE_CONSUMED);
    } else {
      recordEvent(TOKEN_EVENT_TYPES.INVALID_TOKEN_REJECTED);
    }

    return result;
  }

  function issueTokenPair({ clientId, userId, scope, accessToken }) {
    const now = Math.floor(Date.now() / 1000);
    const refreshTokenValue = data.generateRefreshToken();
    const accessExpiresAt = now + config.accessTokenTTL;
    const refreshExpiresAt = now + config.refreshTokenTTL;

    data.storeToken(
      'access_token',
      accessToken,
      clientId,
      userId,
      scope,
      accessExpiresAt,
      refreshTokenValue
    );

    data.storeToken(
      'refresh_token',
      refreshTokenValue,
      clientId,
      userId,
      scope,
      refreshExpiresAt,
      null
    );

    return {
      refreshTokenValue,
      accessExpiresAt,
      refreshExpiresAt
    };
  }

  function consumeRefreshToken({ refreshTokenValue, clientId, requestedScope, clientAllowedScopes }) {
    const grantFailure = (error_description) => ({
      ok: false,
      status: 400,
      error: 'invalid_grant',
      error_description
    });
    const scopeFailure = (error_description) => ({
      ok: false,
      status: 400,
      error: 'invalid_scope',
      error_description
    });

    const oldRefreshToken = data.getToken(refreshTokenValue);
    let result;

    if (!oldRefreshToken || oldRefreshToken.token_type !== 'refresh_token') {
      result = grantFailure('Invalid refresh token');
    } else if (oldRefreshToken.revoked === 1) {
      result = grantFailure('Refresh token has been revoked');
    } else if (oldRefreshToken.expires_at && oldRefreshToken.expires_at < Math.floor(Date.now() / 1000)) {
      result = grantFailure('Refresh token has expired');
    } else if (oldRefreshToken.client_id !== clientId) {
      result = grantFailure('Refresh token was not issued to this client');
    } else {
      let newScope = oldRefreshToken.scope;
      let scopeError = null;

      if (requestedScope) {
        const requestedScopes = requestedScope.split(' ');
        const originalScopes = oldRefreshToken.scope.split(' ');
        const allInOriginal = requestedScopes.every(s => originalScopes.includes(s));
        if (!allInOriginal) {
          scopeError = scopeFailure('Requested scope exceeds original scope');
        } else {
          const allAllowedByClient = requestedScopes.every(s => clientAllowedScopes.includes(s));
          if (!allAllowedByClient) {
            scopeError = scopeFailure(`Requested scope exceeds client allowed_scopes. Allowed: ${clientAllowedScopes.join(' ')}`);
          }
          newScope = requestedScope;
        }
      } else {
        const originalScopes = oldRefreshToken.scope
          ? oldRefreshToken.scope.split(' ').filter(Boolean)
          : [];
        const allAllowedByClient = originalScopes.every(s => clientAllowedScopes.includes(s));
        if (!allAllowedByClient) {
          scopeError = scopeFailure(`Original token scope exceeds client allowed_scopes. Allowed: ${clientAllowedScopes.join(' ')}`);
        }
      }

      if (scopeError) {
        result = scopeError;
      } else {
        data.revokeToken(refreshTokenValue);
        result = {
          ok: true,
          oldRefreshToken,
          newScope,
          userId: oldRefreshToken.user_id
        };
      }
    }

    if (result.ok) {
      recordEvent(TOKEN_EVENT_TYPES.REFRESH_TOKEN_ROTATED);
    } else if (result.error === 'invalid_grant') {
      recordEvent(TOKEN_EVENT_TYPES.INVALID_TOKEN_REJECTED);
    }

    return result;
  }

  return {
    issueAuthorizationCode,
    fetchAuthorizationCode,
    consumeAuthorizationCode,
    issueTokenPair,
    consumeRefreshToken,
    TOKEN_EVENT_TYPES
  };
}

module.exports = { createGrantService };
