function parseBasicAuth(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Basic ')) return null;
  const decoded = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
  const [clientId, ...rest] = decoded.split(':');
  const clientSecret = rest.join(':');
  return { client_id: clientId, client_secret: clientSecret };
}

function createClientAuthenticator({ data }) {
  return function authenticateClient(req) {
    const basic = parseBasicAuth(req);
    const clientId = basic ? basic.client_id : (req.body && req.body.client_id);
    const clientSecret = basic ? basic.client_secret : (req.body && req.body.client_secret);

    if (!clientId) {
      return null;
    }

    const client = data.getClientById(clientId);
    if (!client) return null;

    if (client.client_type === 'confidential') {
      if (!data.verifyClientCredentials(clientId, clientSecret)) {
        return null;
      }
    }

    return client;
  };
}

module.exports = { createClientAuthenticator, parseBasicAuth };
