const express = require('express');
const { createClientAuthenticator } = require('../clientAuth');
const { ALL_TOKEN_EVENT_TYPES } = require('../tokenEventTypes');

function createAdminRoute({ data }) {
  const router = express.Router();
  const authenticateClient = createClientAuthenticator({ data });

  router.get('/events', (req, res) => {
    const client = authenticateClient(req);
    if (!client) {
      return res.status(401).json({
        error: 'invalid_client',
        error_description: 'Client authentication failed'
      });
    }

    const { event_type, limit } = req.query;

    if (event_type && !ALL_TOKEN_EVENT_TYPES.includes(event_type)) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: `event_type must be one of: ${ALL_TOKEN_EVENT_TYPES.join(', ')}`
      });
    }

    const parsedLimit = limit ? parseInt(limit, 10) : 100;
    const events = data.getTokenEvents({
      eventType: event_type || null,
      limit: Number.isNaN(parsedLimit) ? 100 : parsedLimit
    });

    return res.json({ events });
  });

  return router;
}

module.exports = createAdminRoute;
