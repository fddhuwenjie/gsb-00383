const express = require('express');
const url = require('url');
const { getClientById, verifyUserPassword, getUserByUsername, createAuthorizationCode } = require('../data');
const config = require('../config');

const router = express.Router();

const loginFormHtml = (client, redirectUri, scope, state, codeChallenge, codeChallengeMethod, errorMsg) => `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Sign In - OAuth 2.1 Server</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 400px; margin: 60px auto; padding: 20px; }
    .card { background: #fff; border-radius: 8px; padding: 24px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    h1 { font-size: 20px; margin-top: 0; color: #1a1a1a; }
    .client-info { color: #666; margin-bottom: 16px; font-size: 14px; }
    label { display: block; margin: 12px 0 6px; font-size: 14px; color: #333; }
    input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 6px; font-size: 14px; box-sizing: border-box; }
    button { width: 100%; padding: 12px; margin-top: 16px; background: #4f46e5; color: white; border: none; border-radius: 6px; font-size: 14px; cursor: pointer; }
    button:hover { background: #4338ca; }
    .error { color: #dc2626; font-size: 13px; margin-bottom: 12px; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Sign In</h1>
    <div class="client-info">Application: <strong>${client.client_name}</strong></div>
    ${errorMsg ? `<div class="error">${errorMsg}</div>` : ''}
    <form method="POST" action="/authorize">
      <input type="hidden" name="client_id" value="${client.client_id}">
      <input type="hidden" name="redirect_uri" value="${redirectUri}">
      <input type="hidden" name="response_type" value="code">
      <input type="hidden" name="scope" value="${scope}">
      <input type="hidden" name="state" value="${state || ''}">
      <input type="hidden" name="code_challenge" value="${codeChallenge}">
      <input type="hidden" name="code_challenge_method" value="${codeChallengeMethod}">
      
      <label>Username</label>
      <input type="text" name="username" required autofocus>
      
      <label>Password</label>
      <input type="password" name="password" required>
      
      <button type="submit">Sign In</button>
    </form>
  </div>
</body>
</html>
`;

const consentHtml = (client, redirectUri, scope, state, codeChallenge, codeChallengeMethod, user) => `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Authorize - OAuth 2.1 Server</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 400px; margin: 60px auto; padding: 20px; }
    .card { background: #fff; border-radius: 8px; padding: 24px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
    h1 { font-size: 20px; margin-top: 0; color: #1a1a1a; }
    .user-info { color: #666; margin-bottom: 12px; font-size: 14px; }
    .scopes { background: #f3f4f6; padding: 12px; border-radius: 6px; margin: 16px 0; }
    .scope-item { padding: 4px 0; font-size: 14px; }
    .btn-group { display: flex; gap: 10px; margin-top: 16px; }
    button { flex: 1; padding: 12px; border: none; border-radius: 6px; font-size: 14px; cursor: pointer; }
    .btn-allow { background: #4f46e5; color: white; }
    .btn-allow:hover { background: #4338ca; }
    .btn-deny { background: #e5e7eb; color: #333; }
    .btn-deny:hover { background: #d1d5db; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Authorize Application</h1>
    <div class="user-info">Signed in as <strong>${user.name}</strong> (${user.email})</div>
    <p style="font-size: 14px; color: #333;">
      <strong>${client.client_name}</strong> is requesting access to:
    </p>
    <div class="scopes">
      ${scope.split(' ').map(s => `<div class="scope-item">• ${s}</div>`).join('')}
    </div>
    <form method="POST" action="/authorize/consent">
      <input type="hidden" name="client_id" value="${client.client_id}">
      <input type="hidden" name="redirect_uri" value="${redirectUri}">
      <input type="hidden" name="response_type" value="code">
      <input type="hidden" name="scope" value="${scope}">
      <input type="hidden" name="state" value="${state || ''}">
      <input type="hidden" name="code_challenge" value="${codeChallenge}">
      <input type="hidden" name="code_challenge_method" value="${codeChallengeMethod}">
      <input type="hidden" name="username" value="${user.username}">
      <div class="btn-group">
        <button type="submit" name="action" value="deny" class="btn-deny">Deny</button>
        <button type="submit" name="action" value="allow" class="btn-allow">Allow</button>
      </div>
    </form>
  </div>
</body>
</html>
`;

function redirectWithError(redirectUri, error, description, state, res) {
  const u = new URL(redirectUri);
  u.searchParams.set('error', error);
  if (description) u.searchParams.set('error_description', description);
  if (state) u.searchParams.set('state', state);
  return res.redirect(u.toString());
}

router.get('/authorize', (req, res) => {
  const {
    response_type,
    client_id,
    redirect_uri,
    scope,
    state,
    code_challenge,
    code_challenge_method
  } = req.query;

  if (response_type !== 'code') {
    return res.status(400).json({
      error: 'unsupported_response_type',
      error_description: 'Only "code" response type is supported (OAuth 2.1)'
    });
  }

  if (!client_id) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'client_id is required'
    });
  }

  const client = getClientById(client_id);
  if (!client) {
    return res.status(400).json({
      error: 'invalid_client',
      error_description: 'Unknown client_id'
    });
  }

  if (!redirect_uri) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: 'redirect_uri is required'
    });
  }

  if (!client.redirect_uris.includes(redirect_uri)) {
    return res.status(400).json({
      error: 'invalid_redirect_uri',
      error_description: 'Redirect URI does not match any registered URI'
    });
  }

  const scopeStr = scope || 'openid profile';
  const requestedScopes = scopeStr.split(' ').filter(Boolean);
  const allowedScopes = client.allowed_scopes || [];
  const allAllowed = requestedScopes.every(s => allowedScopes.includes(s));
  if (!allAllowed) {
    return redirectWithError(
      redirect_uri,
      'invalid_scope',
      `Requested scope exceeds client allowed_scopes. Allowed: ${allowedScopes.join(' ')}`,
      state,
      res
    );
  }

  if (!code_challenge) {
    return redirectWithError(
      redirect_uri,
      'invalid_request',
      'PKCE code_challenge is required (S256 only)',
      state,
      res
    );
  }

  if (code_challenge_method && code_challenge_method !== 'S256') {
    return redirectWithError(
      redirect_uri,
      'invalid_request',
      'Only S256 code challenge method is supported',
      state,
      res
    );
  }

  const actualMethod = code_challenge_method || 'S256';
  if (actualMethod !== 'S256') {
    return redirectWithError(
      redirect_uri,
      'invalid_request',
      'Only S256 code challenge method is supported',
      state,
      res
    );
  }

  res.send(loginFormHtml(
    client,
    redirect_uri,
    scopeStr,
    state,
    code_challenge,
    actualMethod,
    null
  ));
});

router.post('/authorize', express.urlencoded({ extended: true }), (req, res) => {
  const {
    client_id,
    redirect_uri,
    scope,
    state,
    code_challenge,
    code_challenge_method,
    username,
    password
  } = req.body;

  const client = getClientById(client_id);
  if (!client) {
    return res.status(400).send('Invalid client');
  }

  if (!client.redirect_uris.includes(redirect_uri)) {
    return res.status(400).send('Invalid redirect_uri');
  }

  const requestedScopes = scope ? scope.split(' ').filter(Boolean) : [];
  const allowedScopes = client.allowed_scopes || [];
  const allAllowed = requestedScopes.every(s => allowedScopes.includes(s));
  if (!allAllowed) {
    return redirectWithError(
      redirect_uri,
      'invalid_scope',
      `Requested scope exceeds client allowed_scopes. Allowed: ${allowedScopes.join(' ')}`,
      state,
      res
    );
  }

  const valid = verifyUserPassword(username, password);
  if (!valid) {
    return res.send(loginFormHtml(
      client,
      redirect_uri,
      scope,
      state,
      code_challenge,
      code_challenge_method,
      'Invalid username or password'
    ));
  }

  const user = getUserByUsername(username);
  res.send(consentHtml(
    client,
    redirect_uri,
    scope,
    state,
    code_challenge,
    code_challenge_method,
    user
  ));
});

router.post('/authorize/consent', express.urlencoded({ extended: true }), (req, res) => {
  const {
    client_id,
    redirect_uri,
    scope,
    state,
    code_challenge,
    code_challenge_method,
    action,
    username
  } = req.body;

  const client = getClientById(client_id);
  if (!client) {
    return res.status(400).send('Invalid client');
  }

  if (!client.redirect_uris.includes(redirect_uri)) {
    return res.status(400).send('Invalid redirect_uri');
  }

  const requestedScopes = scope ? scope.split(' ').filter(Boolean) : [];
  const allowedScopes = client.allowed_scopes || [];
  const allAllowed = requestedScopes.every(s => allowedScopes.includes(s));
  if (!allAllowed) {
    return redirectWithError(
      redirect_uri,
      'invalid_scope',
      `Requested scope exceeds client allowed_scopes. Allowed: ${allowedScopes.join(' ')}`,
      state,
      res
    );
  }

  if (action === 'deny') {
    return redirectWithError(redirect_uri, 'access_denied', 'User denied access', state, res);
  }

  const user = getUserByUsername(username);
  if (!user) {
    return redirectWithError(redirect_uri, 'server_error', 'User not found', state, res);
  }

  const code = createAuthorizationCode(
    client_id,
    user.id,
    redirect_uri,
    scope,
    code_challenge,
    code_challenge_method,
    config.authorizationCodeTTL
  );

  const u = new URL(redirect_uri);
  u.searchParams.set('code', code);
  if (state) u.searchParams.set('state', state);
  res.redirect(u.toString());
});

module.exports = router;
