const path = require('path');

module.exports = {
  port: process.env.PORT || 3000,
  issuer: process.env.ISSUER || 'http://localhost:3000',
  dbPath: path.join(__dirname, '..', 'data', 'auth.db'),
  accessTokenTTL: 3600,
  refreshTokenTTL: 86400 * 30,
  authorizationCodeTTL: 600,
  defaultScopes: ['openid', 'profile', 'email']
};
