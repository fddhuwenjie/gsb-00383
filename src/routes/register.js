const express = require('express');
const { registerClient } = require('../data');
const config = require('../config');

const router = express.Router();

router.post('/', (req, res) => {
  const { client_name, client_type, redirect_uris, grant_types, allowed_scopes } = req.body;

  if (!client_name || !client_type || !redirect_uris || !Array.isArray(redirect_uris) || redirect_uris.length === 0) {
    return res.status(400).json({
      error: 'invalid_client_metadata',
      error_description: 'client_name, client_type, and redirect_uris (array) are required'
    });
  }

  if (!['public', 'confidential'].includes(client_type)) {
    return res.status(400).json({
      error: 'invalid_client_metadata',
      error_description: 'client_type must be "public" or "confidential"'
    });
  }

  const validGrantTypes = grant_types && Array.isArray(grant_types)
    ? grant_types.filter(g => ['authorization_code', 'refresh_token'].includes(g))
    : ['authorization_code', 'refresh_token'];

  if (validGrantTypes.length === 0) {
    return res.status(400).json({
      error: 'invalid_client_metadata',
      error_description: 'At least one valid grant type is required (authorization_code, refresh_token)'
    });
  }

  if (allowed_scopes !== undefined) {
    if (!Array.isArray(allowed_scopes)) {
      return res.status(400).json({
        error: 'invalid_client_metadata',
        error_description: 'allowed_scopes must be an array of scope strings'
      });
    }
    const systemScopes = config.defaultScopes;
    const allValid = allowed_scopes.every(s => systemScopes.includes(s));
    if (!allValid) {
      return res.status(400).json({
        error: 'invalid_client_metadata',
        error_description: `allowed_scopes must be a subset of supported scopes: ${systemScopes.join(', ')}`
      });
    }
  }

  try {
    const client = registerClient(client_name, client_type, redirect_uris, validGrantTypes, allowed_scopes);
    res.status(201).json(client);
  } catch (err) {
    console.error('Registration error:', err);
    res.status(500).json({
      error: 'server_error',
      error_description: 'Internal server error'
    });
  }
});

module.exports = router;
