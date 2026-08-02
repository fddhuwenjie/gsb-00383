const express = require('express');
const { createClientAuthenticator } = require('../clientAuth');

function createIntrospectRoute({ data }) {
  const router = express.Router();
  const authenticateClient = createClientAuthenticator({ data });

  router.post('/introspect', express.urlencoded({ extended: true }), (req, res) => {
    const { token, token_type_hint } = req.body;

    const client = authenticateClient(req);
    if (!client) {
      return res.status(401).json({
        error: 'invalid_client',
        error_description: 'Client authentication failed'
      });
    }

    if (!token) {
      return res.json({ active: false });
    }

    const tokenRecord = data.getToken(token);
    if (!tokenRecord) {
      return res.json({ active: false });
    }

    if (tokenRecord.revoked === 1) {
      return res.json({ active: false });
    }

    if (data.isTokenExpired(tokenRecord)) {
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

    const client = authenticateClient(req);
    if (!client) {
      return res.status(401).json({
        error: 'invalid_client',
        error_description: 'Client authentication failed'
      });
    }

    if (!token) {
      return res.sendStatus(200);
    }

    const tokenRecord = data.getToken(token);
    if (tokenRecord && tokenRecord.client_id === client.client_id) {
      data.revokeToken(token);
    }

    return res.sendStatus(200);
  });

  return router;
}

module.exports = createIntrospectRoute;
