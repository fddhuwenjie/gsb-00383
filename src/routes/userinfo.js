const express = require('express');

function createUserinfoRouter({ verifyJwt }) {
  const router = express.Router();

  function extractToken(req) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      return authHeader.slice(7);
    }
    if (req.query && req.query.access_token) {
      return req.query.access_token;
    }
    return null;
  }

  async function handleUserinfo(req, res, token) {
    if (!token) {
      return res.status(401).json({
        error: 'invalid_token',
        error_description: 'No access token provided'
      });
    }

    const result = await verifyJwt(token);
    if (!result.valid) {
      return res.status(401).json({
        error: 'invalid_token',
        error_description: result.error
      });
    }

    const { payload } = result;
    const scopes = payload.scope ? payload.scope.split(' ') : [];

    const userinfo = {
      sub: payload.sub
    };

    if (scopes.includes('profile')) {
      userinfo.name = payload.name;
      userinfo.preferred_username = payload.username;
    }

    if (scopes.includes('email')) {
      userinfo.email = payload.email;
      userinfo.email_verified = true;
    }

    return res.json(userinfo);
  }

  router.get('/userinfo', async (req, res) => {
    return handleUserinfo(req, res, extractToken(req));
  });

  router.post('/userinfo', express.urlencoded({ extended: true }), async (req, res) => {
    return handleUserinfo(req, res, extractToken(req) || (req.body && req.body.access_token));
  });

  return router;
}

module.exports = createUserinfoRouter;
