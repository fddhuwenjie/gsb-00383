const express = require('express');
const {
  getClientById,
  verifyClientCredentials,
  getTokenEvents,
  TOKEN_EVENT_TYPES
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

function authenticateClient(req) {
  const basic = parseBasicAuth(req);
  const clientId = basic ? basic.client_id : (req.query && req.query.client_id);
  const clientSecret = basic ? basic.client_secret : (req.query && req.query.client_secret);

  if (!clientId) return null;

  const client = getClientById(clientId);
  if (!client) return null;

  if (client.client_type === 'confidential') {
    if (!verifyClientCredentials(clientId, clientSecret)) {
      return null;
    }
  }

  return client;
}

router.get('/token-events', (req, res) => {
  const client = authenticateClient(req);
  if (!client) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Client authentication failed'
    });
  }

  const { event_type } = req.query;
  if (event_type && !TOKEN_EVENT_TYPES.includes(event_type)) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: `Unknown event_type. Supported: ${TOKEN_EVENT_TYPES.join(', ')}`
    });
  }

  const events = getTokenEvents(event_type || null);
  return res.json({ events });
});

module.exports = router;
