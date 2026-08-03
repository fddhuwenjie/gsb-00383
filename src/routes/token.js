const express = require('express');

function createTokenRouter({
  config,
  getClientById,
  verifyClientCredentials,
  getUserById,
  getToken,
  storeToken,
  signAccessToken,
  verifyJwt,
  consumeAuthorizationCode,
  issueTokenPair,
  rotateRefreshToken,
  GrantServiceError
}) {
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

  function mapGrantServiceError(res, err) {
    return res.status(err.status).json({
      error: err.error,
      error_description: err.error_description
    });
  }

  function authenticateClient(req, res) {
    const clientAuth = extractClientAuth(req);
    if (!clientAuth || !clientAuth.client_id) {
      res.status(401).json({
        error: 'invalid_client',
        error_description: 'Client authentication is required'
      });
      return null;
    }

    const client = getClientById(clientAuth.client_id);
    if (!client) {
      res.status(401).json({
        error: 'invalid_client',
        error_description: 'Unknown client'
      });
      return null;
    }

    if (client.client_type === 'confidential') {
      if (!verifyClientCredentials(clientAuth.client_id, clientAuth.client_secret)) {
        res.status(401).json({
          error: 'invalid_client',
          error_description: 'Invalid client credentials'
        });
        return null;
      }
    }

    return client;
  }

  async function handleAuthorizationCodeGrant(res, client, code, redirect_uri, code_verifier) {
    let authCode;
    try {
      authCode = consumeAuthorizationCode({
        code,
        clientId: client.client_id,
        redirectUri: redirect_uri,
        codeVerifier: code_verifier
      });
    } catch (err) {
      if (err instanceof GrantServiceError) {
        return mapGrantServiceError(res, err);
      }
      throw err;
    }

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

    let tokenResponse;
    try {
      tokenResponse = await issueTokenPair({
        user,
        clientId: client.client_id,
        scope: authCode.scope
      });
    } catch (err) {
      if (err instanceof GrantServiceError) {
        return mapGrantServiceError(res, err);
      }
      throw err;
    }

    return res.json(tokenResponse);
  }

  async function handleRefreshTokenGrant(res, client, refreshTokenValue, scope) {
    let tokenResponse;
    try {
      tokenResponse = await rotateRefreshToken({
        refreshTokenValue,
        clientId: client.client_id,
        scope,
        getUserById,
        clientAllowedScopes: client.allowed_scopes || []
      });
    } catch (err) {
      if (err instanceof GrantServiceError) {
        return mapGrantServiceError(res, err);
      }
      throw err;
    }

    return res.json(tokenResponse);
  }

  router.post('/token', express.urlencoded({ extended: true }), async (req, res) => {
    const { grant_type, code, redirect_uri, code_verifier, refresh_token, scope } = req.body;

    const client = authenticateClient(req, res);
    if (!client) return;

    if (grant_type === 'authorization_code') {
      return handleAuthorizationCodeGrant(res, client, code, redirect_uri, code_verifier);
    } else if (grant_type === 'refresh_token') {
      return handleRefreshTokenGrant(res, client, refresh_token, scope);
    } else {
      return res.status(400).json({
        error: 'unsupported_grant_type',
        error_description: 'Only authorization_code and refresh_token grants are supported (OAuth 2.1)'
      });
    }
  });

  router.post('/token/downscope', express.urlencoded({ extended: true }), async (req, res) => {
    const { access_token, scope } = req.body;

    const client = authenticateClient(req, res);
    if (!client) return;

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

  return router;
}

module.exports = createTokenRouter;
