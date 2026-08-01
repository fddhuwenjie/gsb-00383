const express = require('express');
const {
  getClientById,
  verifyClientCredentials,
  getAuthorizationCode,
  markAuthorizationCodeUsed,
  getUserById,
  storeToken,
  getToken,
  generateRefreshToken,
  revokeToken
} = require('../data');
const { signAccessToken, verifyJwt } = require('../jwt');
const { verifyCodeChallenge } = require('../pkce');
const config = require('../config');

const router = express.Router();

function parseBasicAuth(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Basic ')) return null;
  const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
  const [clientId, ...rest] = decoded.split(':');
  const clientSecret = rest.join(':');
  return { client_id: clientId, client_secret: clientSecret };
}

function extractClientAuth(req) {
  const basic = parseBasicAuth(req);
  if (basic) return basic;
  if (req.body && req.body.client_id) {
    return {
      client_id: req.body.client_id,
      client_secret: req.body.client_secret || null
    };
  }
  return null;
}

router.post('/token', express.urlencoded({ extended: true }), async (req, res) => {
  const { grant_type, code, redirect_uri, code_verifier, refresh_token, scope } = req.body;

  const clientAuth = extractClientAuth(req);
  if (!clientAuth || !clientAuth.client_id) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Client authentication is required'
    });
  }

  const client = getClientById(clientAuth.client_id);
  if (!client) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Unknown client'
    });
  }

  if (client.client_type === 'confidential') {
    if (!verifyClientCredentials(clientAuth.client_id, clientAuth.client_secret)) {
      return res.status(401).json({
        error: 'invalid_client',
        error_description: 'Invalid client credentials'
      });
    }
  }

  if (grant_type === 'authorization_code') {
    return handleAuthorizationCodeGrant(req, res, client, code, redirect_uri, code_verifier);
  } else if (grant_type === 'refresh_token') {
    return handleRefreshTokenGrant(req, res, client, refresh_token, scope);
  } else {
    return res.status(400).json({
      error: 'unsupported_grant_type',
      error_description: 'Only authorization_code and refresh_token grants are supported (OAuth 2.1)'
    });
  }
});

async function handleAuthorizationCodeGrant(req, res, client, code, redirect_uri, code_verifier) {
  if (!code) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'code is required'
    });
  }

  if (!redirect_uri) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'redirect_uri is required'
    });
  }

  if (!code_verifier) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'code_verifier is required (PKCE)'
    });
  }

  const authCode = getAuthorizationCode(code);
  if (!authCode) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Invalid authorization code'
    });
  }

  if (authCode.used === 1) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Authorization code has already been used'
    });
  }

  const now = Math.floor(Date.now() / 1000);
  if (authCode.expires_at < now) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Authorization code has expired'
    });
  }

  if (authCode.client_id !== client.client_id) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Authorization code was not issued to this client'
    });
  }

  if (authCode.redirect_uri !== redirect_uri) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'redirect_uri does not match'
    });
  }

  if (authCode.code_challenge_method === 'S256') {
    if (!verifyCodeChallenge(code_verifier, authCode.code_challenge)) {
      return res.status(400).json({
        error: 'invalid_grant',
        error_description: 'PKCE verification failed'
      });
    }
  } else {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Unsupported code challenge method'
    });
  }

  markAuthorizationCodeUsed(authCode.id);

  const user = getUserById(authCode.user_id);
  if (!user) {
    return res.status(400).json({
      error: 'server_error',
      error_description: 'User not found'
    });
  }

  const codeScopes = authCode.scope ? authCode.scope.split(' ').filter(Boolean) : [];
  const clientAllowedScopes = client.allowed_scopes || [];
  const allAllowed = codeScopes.every(s => clientAllowedScopes.includes(s));
  if (!allAllowed) {
    return res.status(400).json({
      error: 'invalid_scope',
      error_description: `Scope exceeds client allowed_scopes. Allowed: ${clientAllowedScopes.join(' ')}`
    });
  }

  const refreshTokenValue = generateRefreshToken();
  const refreshExpiresAt = Math.floor(Date.now() / 1000) + config.refreshTokenTTL;

  const accessTokenPayload = {
    sub: user.sub,
    scope: authCode.scope,
    client_id: client.client_id,
    username: user.username,
    name: user.name,
    email: user.email
  };

  const accessToken = await signAccessToken(accessTokenPayload);

  storeToken('access_token', accessToken, client.client_id, user.id, authCode.scope,
    Math.floor(Date.now() / 1000) + config.accessTokenTTL, refreshTokenValue);

  storeToken('refresh_token', refreshTokenValue, client.client_id, user.id, authCode.scope,
    refreshExpiresAt, null);

  return res.json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: config.accessTokenTTL,
    refresh_token: refreshTokenValue,
    scope: authCode.scope
  });
}

async function handleRefreshTokenGrant(req, res, client, refreshTokenValue, scope) {
  if (!refreshTokenValue) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'refresh_token is required'
    });
  }

  const oldRefreshToken = getToken(refreshTokenValue);
  if (!oldRefreshToken || oldRefreshToken.token_type !== 'refresh_token') {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Invalid refresh token'
    });
  }

  if (oldRefreshToken.revoked === 1) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Refresh token has been revoked'
    });
  }

  const now = Math.floor(Date.now() / 1000);
  if (oldRefreshToken.expires_at && oldRefreshToken.expires_at < now) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Refresh token has expired'
    });
  }

  if (oldRefreshToken.client_id !== client.client_id) {
    return res.status(400).json({
      error: 'invalid_grant',
      error_description: 'Refresh token was not issued to this client'
    });
  }

  let newScope = oldRefreshToken.scope;
  if (scope) {
    const requestedScopes = scope.split(' ');
    const originalScopes = oldRefreshToken.scope.split(' ');
    const allInOriginal = requestedScopes.every(s => originalScopes.includes(s));
    if (!allInOriginal) {
      return res.status(400).json({
        error: 'invalid_scope',
        error_description: 'Requested scope exceeds original scope'
      });
    }
    const clientAllowedScopes = client.allowed_scopes || [];
    const allAllowedByClient = requestedScopes.every(s => clientAllowedScopes.includes(s));
    if (!allAllowedByClient) {
      return res.status(400).json({
        error: 'invalid_scope',
        error_description: `Requested scope exceeds client allowed_scopes. Allowed: ${clientAllowedScopes.join(' ')}`
      });
    }
    newScope = scope;
  } else {
    const originalScopes = oldRefreshToken.scope ? oldRefreshToken.scope.split(' ').filter(Boolean) : [];
    const clientAllowedScopes = client.allowed_scopes || [];
    const allAllowedByClient = originalScopes.every(s => clientAllowedScopes.includes(s));
    if (!allAllowedByClient) {
      return res.status(400).json({
        error: 'invalid_scope',
        error_description: `Original token scope exceeds client allowed_scopes. Allowed: ${clientAllowedScopes.join(' ')}`
      });
    }
  }

  const user = getUserById(oldRefreshToken.user_id);
  if (!user) {
    return res.status(400).json({
      error: 'server_error',
      error_description: 'User not found'
    });
  }

  const newRefreshTokenValue = generateRefreshToken();
  const refreshExpiresAt = Math.floor(Date.now() / 1000) + config.refreshTokenTTL;

  const accessTokenPayload = {
    sub: user.sub,
    scope: newScope,
    client_id: client.client_id,
    username: user.username,
    name: user.name,
    email: user.email
  };

  const newAccessToken = await signAccessToken(accessTokenPayload);

  storeToken('access_token', newAccessToken, client.client_id, user.id, newScope,
    Math.floor(Date.now() / 1000) + config.accessTokenTTL, newRefreshTokenValue);

  storeToken('refresh_token', newRefreshTokenValue, client.client_id, user.id, newScope,
    refreshExpiresAt, null);

  revokeToken(refreshTokenValue);

  return res.json({
    access_token: newAccessToken,
    token_type: 'Bearer',
    expires_in: config.accessTokenTTL,
    refresh_token: newRefreshTokenValue,
    scope: newScope
  });
}

router.post('/token/downscope', express.urlencoded({ extended: true }), async (req, res) => {
  const { access_token, scope } = req.body;

  const clientAuth = extractClientAuth(req);
  if (!clientAuth || !clientAuth.client_id) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Client authentication is required'
    });
  }

  const client = getClientById(clientAuth.client_id);
  if (!client) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Unknown client'
    });
  }

  if (client.client_type === 'confidential') {
    if (!verifyClientCredentials(clientAuth.client_id, clientAuth.client_secret)) {
      return res.status(401).json({
        error: 'invalid_client',
        error_description: 'Invalid client credentials'
      });
    }
  }

  if (!access_token) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'access_token is required'
    });
  }

  if (!scope) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'scope is required for downscoping'
    });
  }

  const jwtResult = await verifyJwt(access_token);
  if (!jwtResult.valid) {
    return res.status(400).json({
      error: 'invalid_token',
      error_description: 'Invalid access token: ' + jwtResult.error
    });
  }

  const tokenRecord = getToken(access_token);
  if (!tokenRecord || tokenRecord.token_type !== 'access_token') {
    return res.status(400).json({
      error: 'invalid_token',
      error_description: 'Access token not found'
    });
  }

  if (tokenRecord.revoked === 1) {
    return res.status(400).json({
      error: 'invalid_token',
      error_description: 'Access token has been revoked'
    });
  }

  const now = Math.floor(Date.now() / 1000);
  if (tokenRecord.expires_at && tokenRecord.expires_at < now) {
    return res.status(400).json({
      error: 'invalid_token',
      error_description: 'Access token has expired'
    });
  }

  if (tokenRecord.client_id !== client.client_id) {
    return res.status(400).json({
      error: 'invalid_token',
      error_description: 'Access token was not issued to this client'
    });
  }

  const originalScopes = tokenRecord.scope ? tokenRecord.scope.split(' ').filter(Boolean) : [];
  const requestedScopes = scope.split(' ').filter(Boolean);

  if (requestedScopes.length === 0) {
    return res.status(400).json({
      error: 'invalid_scope',
      error_description: 'At least one scope must be requested'
    });
  }

  const allInOriginal = requestedScopes.every(s => originalScopes.includes(s));
  if (!allInOriginal) {
    return res.status(400).json({
      error: 'invalid_scope',
      error_description: 'Requested scope must be a subset of the original token scope'
    });
  }

  const clientAllowedScopes = client.allowed_scopes || [];
  const allAllowedByClient = requestedScopes.every(s => clientAllowedScopes.includes(s));
  if (!allAllowedByClient) {
    return res.status(400).json({
      error: 'invalid_scope',
      error_description: `Requested scope exceeds client allowed_scopes. Allowed: ${clientAllowedScopes.join(' ')}`
    });
  }

  const remainingSeconds = tokenRecord.expires_at - now;
  const newExpiresIn = Math.min(remainingSeconds, config.accessTokenTTL);

  const originalPayload = jwtResult.payload;
  const newPayload = {
    sub: originalPayload.sub,
    scope: scope,
    client_id: client.client_id,
    username: originalPayload.username,
    name: originalPayload.name,
    email: originalPayload.email
  };

  const newAccessToken = await signAccessToken(newPayload, newExpiresIn);

  storeToken('access_token', newAccessToken, client.client_id, tokenRecord.user_id, scope,
    now + newExpiresIn, null);

  return res.json({
    access_token: newAccessToken,
    token_type: 'Bearer',
    expires_in: newExpiresIn,
    scope: scope
  });
});

module.exports = router;
