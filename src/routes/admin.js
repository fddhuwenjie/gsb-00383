const express = require('express');
const crypto = require('crypto');

const SUPPORTED_EVENT_TYPES = [
  'authorization_code_consumed',
  'refresh_token_rotated',
  'invalid_token_rejected'
];

function timingSafeEqualString(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function createAdminRouter({ config, queryTokenEvents }) {
  const router = express.Router();

  function authenticateAdmin(req, res) {
    if (!config.adminApiKey) {
      res.status(503).json({
        error: 'admin_disabled',
        error_description: 'Admin API is disabled because ADMIN_API_KEY is not configured'
      });
      return false;
    }

    const authHeader = req.headers.authorization || '';
    const provided = authHeader.startsWith('Bearer ')
      ? authHeader.slice(7)
      : (req.query && req.query.api_key) || null;

    if (!provided || !timingSafeEqualString(provided, config.adminApiKey)) {
      res.status(401).json({
        error: 'invalid_token',
        error_description: 'Admin authentication required'
      });
      return false;
    }

    return true;
  }

  router.get('/admin/events', (req, res) => {
    if (!authenticateAdmin(req, res)) return;

    const eventType = req.query.event_type || null;
    if (eventType && !SUPPORTED_EVENT_TYPES.includes(eventType)) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: `Unsupported event_type. Supported: ${SUPPORTED_EVENT_TYPES.join(', ')}`
      });
    }

    let limit = null;
    if (req.query.limit !== undefined) {
      limit = parseInt(req.query.limit, 10);
      if (!Number.isFinite(limit) || limit < 1) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'limit must be a positive integer'
        });
      }
    }

    const events = queryTokenEvents({ eventType, limit });
    return res.json({ events });
  });

  return router;
}

module.exports = createAdminRouter;
