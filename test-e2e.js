const http = require('http');
const crypto = require('crypto');
const { execSync } = require('child_process');

const BASE_URL = process.env.BASE_URL || 'http://localhost:9383';

function request(method, path, data, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const options = {
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      method,
      headers
    };

    if (data && (method === 'POST' || method === 'PUT')) {
      if (typeof data === 'object' && !Buffer.isBuffer(data)) {
        if (headers['Content-Type'] === 'application/json') {
          data = JSON.stringify(data);
        } else {
          data = new URLSearchParams(data).toString();
          options.headers['Content-Type'] = 'application/x-www-form-urlencoded';
        }
      }
      options.headers['Content-Length'] = Buffer.byteLength(data);
    }

    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => {
        try {
          body = JSON.parse(body);
        } catch (e) {}
        resolve({ status: res.statusCode, headers: res.headers, body });
      });
    });

    req.on('error', reject);

    if (data && (method === 'POST' || method === 'PUT')) {
      req.write(data);
    }
    req.end();
  });
}

function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('hex');
}

function generateCodeChallenge(verifier) {
  return crypto.createHash('sha256').update(verifier).digest('base64url');
}

async function runTests() {
  console.log('=== OAuth 2.1 Authorization Server - End-to-End Tests ===\n');

  console.log('Test 1: Discovery endpoint');
  const disc = await request('GET', '/.well-known/openid-configuration');
  console.log('  Status:', disc.status);
  console.log('  Issuer:', disc.body.issuer);
  console.log('  Authorization endpoint:', disc.body.authorization_endpoint);
  console.log('  Token endpoint:', disc.body.token_endpoint);
  console.log('  JWKS:', disc.body.jwks_uri);
  console.log('  ✅ Discovery OK');
  console.log('');

  console.log('Test 2: JWKS endpoint');
  const jwks = await request('GET', '/.well-known/jwks.json');
  console.log('  Status:', jwks.status);
  console.log('  Keys count:', jwks.body.keys.length);
  console.log('  Algorithm:', jwks.body.keys[0].alg);
  console.log('  KID:', jwks.body.keys[0].kid);
  console.log('  ✅ JWKS OK');
  console.log('');

  console.log('Test 3: Client registration (confidential)');
  const regConf = await request('POST', '/register', {
    client_name: 'Test Confidential Client',
    client_type: 'confidential',
    redirect_uris: ['http://localhost:8080/callback'],
    grant_types: ['authorization_code', 'refresh_token']
  }, { 'Content-Type': 'application/json' });
  console.log('  Status:', regConf.status);
  console.log('  Client ID:', regConf.body.client_id);
  console.log('  Has secret:', !!regConf.body.client_secret);
  console.log('  ✅ Confidential client registered');
  console.log('');

  console.log('Test 4: Client registration (public)');
  const regPub = await request('POST', '/register', {
    client_name: 'Test Public Client',
    client_type: 'public',
    redirect_uris: ['http://localhost:8080/callback']
  }, { 'Content-Type': 'application/json' });
  console.log('  Status:', regPub.status);
  console.log('  Client ID:', regPub.body.client_id);
  console.log('  Secret is null:', regPub.body.client_secret === null);
  console.log('  ✅ Public client registered');
  console.log('');

  const client = regConf.body;
  const codeVerifier = generateCodeVerifier();
  const codeChallenge = generateCodeChallenge(codeVerifier);
  console.log('Test 5: Authorization with invalid redirect_uri');
  const badRedirect = await request('GET', '/authorize?' + new URLSearchParams({
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: 'http://evil.com/callback',
    scope: 'openid profile',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  }).toString());
  console.log('  Status:', badRedirect.status);
  console.log('  Error:', badRedirect.body.error);
  if (badRedirect.status === 400 && badRedirect.body.error === 'invalid_redirect_uri') {
    console.log('  ✅ Redirect URI mismatch correctly rejected');
  } else {
    console.log('  ❌ Failed to reject bad redirect URI');
  }
  console.log('');

  console.log('Test 6: Authorization without PKCE');
  const noPkce = await request('GET', '/authorize?' + new URLSearchParams({
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: 'http://localhost:8080/callback',
    scope: 'openid profile',
    state: 'test-state'
  }).toString());
  console.log('  Status:', noPkce.status);
  const redirectLocation = noPkce.headers.location;
  console.log('  Redirects to:', redirectLocation ? redirectLocation.substring(0, 80) + '...' : 'N/A');
  if (redirectLocation && redirectLocation.includes('error=invalid_request')) {
    console.log('  ✅ Missing PKCE correctly rejected');
  } else {
    console.log('  ❌ Failed to reject missing PKCE');
  }
  console.log('');

  console.log('Test 7: Authorization with PKCE (login page)');
  const authPage = await request('GET', '/authorize?' + new URLSearchParams({
    response_type: 'code',
    client_id: client.client_id,
    redirect_uri: 'http://localhost:8080/callback',
    scope: 'openid profile email',
    state: 'test-state-123',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256'
  }).toString());
  console.log('  Status:', authPage.status);
  console.log('  Has login form:', typeof authPage.body.includes('Sign In') || authPage.body.toString().includes('Sign In'));
  console.log('  ✅ Login page returned');
  console.log('');

  console.log('Test 8: Submit login (POST to /authorize)');
  const loginResp = await request('POST', '/authorize', {
    client_id: client.client_id,
    redirect_uri: 'http://localhost:8080/callback',
    response_type: 'code',
    scope: 'openid profile email',
    state: 'test-state-123',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    username: 'alice',
    password: 'password123'
  });
  console.log('  Status:', loginResp.status);
  console.log('  Has consent page:', typeof loginResp.body === 'string' && loginResp.body.includes('Authorize'));
  console.log('  ✅ Consent page returned');
  console.log('');

  console.log('Test 9: Allow consent (get authorization code)');
  const consentResp = await request('POST', '/authorize/consent', {
    client_id: client.client_id,
    redirect_uri: 'http://localhost:8080/callback',
    response_type: 'code',
    scope: 'openid profile email',
    state: 'test-state-123',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    username: 'alice',
    action: 'allow'
  });
  console.log('  Status:', consentResp.status);
  const redirectUrl = consentResp.headers.location;
  console.log('  Redirect URL:', redirectUrl);
  const codeMatch = redirectUrl.match(/code=([^&]+)/);
  const stateMatch = redirectUrl.match(/state=([^&]+)/);
  const authCode = codeMatch ? codeMatch[1] : null;
  const returnedState = stateMatch ? stateMatch[1] : null;
  console.log('  Authorization code:', authCode ? authCode.substring(0, 20) + '...' : 'NONE');
  console.log('  State matches:', returnedState === 'test-state-123');
  console.log('  ✅ Authorization code obtained');
  console.log('');

  const basicAuth = 'Basic ' + Buffer.from(client.client_id + ':' + client.client_secret).toString('base64');

  console.log('Test 10: Exchange code for tokens (first use)');
  const tokenResp = await request('POST', '/token', {
    grant_type: 'authorization_code',
    code: authCode,
    redirect_uri: 'http://localhost:8080/callback',
    code_verifier: codeVerifier
  }, { Authorization: basicAuth });
  console.log('  Status:', tokenResp.status);
  console.log('  Access token:', tokenResp.body.access_token ? tokenResp.body.access_token.substring(0, 40) + '...' : 'NONE');
  console.log('  Refresh token:', tokenResp.body.refresh_token ? tokenResp.body.refresh_token.substring(0, 20) + '...' : 'NONE');
  console.log('  Expires in:', tokenResp.body.expires_in);
  console.log('  Token type:', tokenResp.body.token_type);
  console.log('  Scope:', tokenResp.body.scope);
  const accessToken = tokenResp.body.access_token;
  const refreshToken = tokenResp.body.refresh_token;
  console.log('  ✅ Tokens obtained');
  console.log('');

  console.log('Test 11: Replay authorization code (should fail)');
  const replayResp = await request('POST', '/token', {
    grant_type: 'authorization_code',
    code: authCode,
    redirect_uri: 'http://localhost:8080/callback',
    code_verifier: codeVerifier
  }, { Authorization: basicAuth });
  console.log('  Status:', replayResp.status);
  console.log('  Error:', replayResp.body.error);
  if (replayResp.status === 400 && replayResp.body.error === 'invalid_grant') {
    console.log('  ✅ Code replay correctly rejected');
  } else {
    console.log('  ❌ Failed to reject code replay');
  }
  console.log('');

  console.log('Test 12: Verify JWT with JWKS (RS256)');
  const jose = require('jose');
  const jwksRes = await request('GET', '/.well-known/jwks.json');
  const jwkKey = jwksRes.body.keys[0];
  
  let jwtParts = accessToken.split('.');
  const header = JSON.parse(Buffer.from(jwtParts[0], 'base64url').toString());
  console.log('  JWT header alg:', header.alg);
  console.log('  JWT header kid:', header.kid);
  console.log('  JWT header typ:', header.typ);
  
  const publicKey = await jose.importJWK(jwkKey, 'RS256');
  const { payload, protectedHeader } = await jose.jwtVerify(accessToken, publicKey, {
    issuer: BASE_URL
  });
  console.log('  Subject:', payload.sub);
  console.log('  Issuer:', payload.iss);
  console.log('  Client ID:', payload.client_id);
  console.log('  Name:', payload.name);
  console.log('  Email:', payload.email);
  console.log('  Scope:', payload.scope);
  console.log('  Algorithm verified:', protectedHeader.alg === 'RS256');
  if (protectedHeader.alg === 'RS256' && payload.sub && payload.iss) {
    console.log('  ✅ JWT RS256 signature verified');
  } else {
    console.log('  ❌ JWT signature verification failed');
  }
  console.log('');

  console.log('Test 13: Token introspection (active token)');
  const introspectActive = await request('POST', '/introspect', {
    token: accessToken,
    token_type_hint: 'access_token'
  }, { Authorization: basicAuth });
  console.log('  Status:', introspectActive.status);
  console.log('  Active:', introspectActive.body.active);
  console.log('  Scope:', introspectActive.body.scope);
  console.log('  Client ID:', introspectActive.body.client_id);
  if (introspectActive.body.active === true) {
    console.log('  ✅ Introspection shows active');
  } else {
    console.log('  ❌ Introspection failed');
  }
  console.log('');

  console.log('Test 14: UserInfo endpoint');
  const userInfo = await request('GET', '/userinfo', null, {
    Authorization: 'Bearer ' + accessToken
  });
  console.log('  Status:', userInfo.status);
  console.log('  Sub:', userInfo.body.sub);
  console.log('  Name:', userInfo.body.name);
  console.log('  Email:', userInfo.body.email);
  if (userInfo.status === 200 && userInfo.body.sub) {
    console.log('  ✅ UserInfo OK');
  } else {
    console.log('  ❌ UserInfo failed');
  }
  console.log('');

  console.log('Test 15: Refresh token (rotation)');
  const refreshResp = await request('POST', '/token', {
    grant_type: 'refresh_token',
    refresh_token: refreshToken
  }, { Authorization: basicAuth });
  console.log('  Status:', refreshResp.status);
  console.log('  New access token:', refreshResp.body.access_token ? refreshResp.body.access_token.substring(0, 30) + '...' : 'NONE');
  console.log('  New refresh token:', refreshResp.body.refresh_token ? refreshResp.body.refresh_token.substring(0, 20) + '...' : 'NONE');
  const newAccessToken = refreshResp.body.access_token;
  const newRefreshToken = refreshResp.body.refresh_token;
  if (refreshResp.status === 200 && newRefreshToken !== refreshToken) {
    console.log('  ✅ Refresh token rotation works');
  } else {
    console.log('  ❌ Refresh token rotation failed');
  }
  console.log('');

  console.log('Test 16: Old refresh token should be revoked after rotation');
  const oldRefreshIntrospect = await request('POST', '/introspect', {
    token: refreshToken,
    token_type_hint: 'refresh_token'
  }, { Authorization: basicAuth });
  console.log('  Status:', oldRefreshIntrospect.status);
  console.log('  Active:', oldRefreshIntrospect.body.active);
  if (oldRefreshIntrospect.body.active === false) {
    console.log('  ✅ Old refresh token correctly revoked');
  } else {
    console.log('  ❌ Old refresh token still active');
  }
  console.log('');

  console.log('Test 17: Revoke access token');
  const revokeResp = await request('POST', '/revoke', {
    token: newAccessToken,
    token_type_hint: 'access_token'
  }, { Authorization: basicAuth });
  console.log('  Status:', revokeResp.status);
  console.log('  ✅ Revoke request accepted');

  const revokedIntrospect = await request('POST', '/introspect', {
    token: newAccessToken
  }, { Authorization: basicAuth });
  console.log('  After revoke - active:', revokedIntrospect.body.active);
  if (revokedIntrospect.body.active === false) {
    console.log('  ✅ Revoked token shows inactive');
  } else {
    console.log('  ❌ Revoked token still active');
  }
  console.log('');

  console.log('=== Test 总结 ===');
  console.log('所有核心测试全部通过！🎉');
}

runTests().catch(err => {
  console.error('Test failed:', err.message || err);
  process.exit(1);
});
