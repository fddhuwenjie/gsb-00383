const fs = require('fs');
const crypto = require('crypto');
const jose = require('jose');

function createJwtService(config) {
  const cfg = config;

  let privateKey;
  let publicKey;
  let jwk;

  function readPrivateKey() {
    if (privateKey) return privateKey;
    const pem = fs.readFileSync(cfg.privateKeyPath, 'utf8');
    privateKey = crypto.createPrivateKey(pem);
    return privateKey;
  }

  function readPublicKey() {
    if (publicKey) return publicKey;
    const pem = fs.readFileSync(cfg.publicKeyPath, 'utf8');
    publicKey = crypto.createPublicKey(pem);
    return publicKey;
  }

  function getJwks() {
    if (jwk) return jwk;
    const key = readPublicKey();
    const jwkObj = key.export({ format: 'jwk' });
    jwk = {
      keys: [{
        kty: jwkObj.kty,
        n: jwkObj.n,
        e: jwkObj.e,
        kid: cfg.keyId,
        alg: 'RS256',
        use: 'sig'
      }]
    };
    return jwk;
  }

  async function signAccessToken(payload, expiresInSeconds) {
    const pem = fs.readFileSync(cfg.privateKeyPath, 'utf8');
    const key = await jose.importPKCS8(pem, 'RS256');

    if (!cfg.issuer) {
      throw new Error('Cannot sign access token: issuer is not configured');
    }

    const jti = 'jwt_' + crypto.randomBytes(16).toString('hex');
    const ttl = expiresInSeconds || cfg.accessTokenTTL;

    return new jose.SignJWT({ ...payload, jti })
      .setProtectedHeader({ alg: 'RS256', kid: cfg.keyId, typ: 'JWT' })
      .setIssuedAt()
      .setIssuer(cfg.issuer)
      .setExpirationTime(`${ttl}s`)
      .sign(key);
  }

  async function verifyJwt(token, options = {}) {
    const issuer = options.issuer || cfg.issuer;
    const pem = fs.readFileSync(cfg.publicKeyPath, 'utf8');
    const key = await jose.importSPKI(pem, 'RS256');

    try {
      const verifyOptions = {};
      if (issuer) verifyOptions.issuer = issuer;
      const { payload, protectedHeader } = await jose.jwtVerify(token, key, verifyOptions);
      return { valid: true, payload, header: protectedHeader };
    } catch (err) {
      return { valid: false, error: err.message };
    }
  }

  return { signAccessToken, verifyJwt, getJwks };
}

module.exports = { createJwtService };
