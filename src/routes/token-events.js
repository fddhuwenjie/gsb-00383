const express = require('express');
const {
  getClientById,
  verifyClientCredentials,
  getTokenEvents,
  TOKEN_EVENT_TYPES
} = require('../data');

const router = express.Router();

// Reuse the same client authentication as /introspect and /revoke: the event
// log is administrative data, so it is protected by confidential-client creds.
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

const VALID_EVENT_TYPES = Object.values(TOKEN_EVENT_TYPES);

router.get('/token-events', (req, res) => {
  const client = authenticateClient(req);
  if (!client) {
    return res.status(401).json({
      error: 'invalid_client',
      error_description: 'Client authentication failed'
    });
  }

  const { event_type } = req.query;
  if (event_type && !VALID_EVENT_TYPES.includes(event_type)) {
    return res.status(400).json({
      error: 'invalid_request',
      error_description: `event_type must be one of: ${VALID_EVENT_TYPES.join(', ')}`
    });
  }

  const events = getTokenEvents({ eventType: event_type });

  return res.json({
    event_types: VALID_EVENT_TYPES,
    count: events.length,
    events
  });
});

module.exports = router;
