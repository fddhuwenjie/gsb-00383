const express = require('express');
const {
  getToken,
  revokeToken,
  getClientById,
  verifyClientCredentials,
  isTokenExpired
} = require('../data');

const router = express.Router();

function parseBasicAuth(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Basic ')) return null;
  const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
  const [clientId, ...rest] = decoded.split(':');
  const clientSecret = rest.join(':');
  return { client_id: clientId, client_secret: clientSecret };
}

function authenticateClient(req, res) {
  const basic = parseBasicAuth(req);
  const clientId = basic ? basic.client_id : (req.body && req.body.client_id);
  const clientSecret = basic ? basic.client_secret : (req.body && req.body.client_secret);

  if (!clientId) {
    return null;
  }

  const client = getClientById(clientId);
  if (!client) return null;

  if (client.client_type === 'confidential') {
    if (!verifyClientCredentials(clientId, clientSecret)) {
      return null;
    }
  }

  return client;
}

router.post('/introspect', express.urlencoded({ extended: true }), (req, res) => {
  const { token, token_type_hint } = req.body;

  const client = authenticateClient(req, res);
  if (!client) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Client authentication failed'
    });
  }

  if (!token) {
    return res.json({ active: false });
  }

  const tokenRecord = getToken(token);
  if (!tokenRecord) {
    return res.json({ active: false });
  }

  if (tokenRecord.revoked === 1) {
    return res.json({ active: false });
  }

  if (isTokenExpired(tokenRecord)) {
    return res.json({ active: false });
  }

  if (tokenRecord.client_id !== client.client_id) {
    return res.json({ active: false });
  }

  const response = {
    active: true,
    scope: tokenRecord.scope,
    client_id: tokenRecord.client_id,
    token_type: tokenRecord.token_type,
    exp: tokenRecord.expires_at,
    iat: tokenRecord.created_at
  };

  return res.json(response);
});

router.post('/revoke', express.urlencoded({ extended: true }), (req, res) => {
  const { token, token_type_hint } = req.body;

  const client = authenticateClient(req, res);
  if (!client) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Client authentication failed'
    });
  }

  if (!token) {
    return res.sendStatus(200);
  }

  const tokenRecord = getToken(token);
  if (tokenRecord && tokenRecord.client_id === client.client_id) {
    revokeToken(token);
  }

  return res.sendStatus(200);
});

module.exports = router;
