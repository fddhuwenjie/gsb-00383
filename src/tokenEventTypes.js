const TOKEN_EVENT_TYPES = Object.freeze({
  AUTHORIZATION_CODE_CONSUMED: 'authorization_code_consumed',
  REFRESH_TOKEN_ROTATED: 'refresh_token_rotated',
  INVALID_TOKEN_REJECTED: 'invalid_token_rejected'
});

const ALL_TOKEN_EVENT_TYPES = Object.freeze(Object.values(TOKEN_EVENT_TYPES));

module.exports = { TOKEN_EVENT_TYPES, ALL_TOKEN_EVENT_TYPES };
