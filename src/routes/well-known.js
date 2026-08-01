const express = require('express');
const { getJwks } = require('../jwt');
const config = require('../config');

const router = express.Router();

router.get('/jwks.json', (req, res) => {
  res.json(getJwks());
});

router.get('/openid-configuration', (req, res) => {
  const issuer = config.issuer;
  res.json({
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    userinfo_endpoint: `${issuer}/userinfo`,
    jwks_uri: `${issuer}/.well-known/jwks.json`,
    introspection_endpoint: `${issuer}/introspect`,
    revocation_endpoint: `${issuer}/revoke`,
    registration_endpoint: `${issuer}/register`,
    response_types_supported: ['code'],
    response_modes_supported: ['query'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256'],
    subject_types_supported: ['public'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    scopes_supported: ['openid', 'profile', 'email']
  });
});

module.exports = router;
