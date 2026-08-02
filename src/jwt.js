const fs = require('fs');
const crypto = require('crypto');
const jose = require('jose');

let jwtConfig = null;
let jwk = null;

function initJwt(config) {
  jwtConfig = {
    privateKeyPath: config.privateKeyPath,
    publicKeyPath: config.publicKeyPath,
    issuer: config.issuer,
    accessTokenTTL: config.accessTokenTTL
  };
  jwk = null;
}

function getJwks() {
  if (!jwk) {
    const publicKeyPem = fs.readFileSync(jwtConfig.publicKeyPath, 'utf8');
    const key = crypto.createPublicKey(publicKeyPem);
    const jwkObj = key.export({ format: 'jwk' });
    jwk = {
      keys: [{
        kty: jwkObj.kty,
        n: jwkObj.n,
        e: jwkObj.e,
        kid: 'oauth21-key-1',
        alg: 'RS256',
        use: 'sig'
      }]
    };
  }
  return jwk;
}

async function signAccessToken(payload, expiresInSeconds) {
  const privateKeyPem = fs.readFileSync(jwtConfig.privateKeyPath, 'utf8');
  const key = await jose.importPKCS8(privateKeyPem, 'RS256');

  const jti = 'jwt_' + crypto.randomBytes(16).toString('hex');
  const ttl = expiresInSeconds || jwtConfig.accessTokenTTL;

  const jwt = await new jose.SignJWT({ ...payload, jti })
    .setProtectedHeader({ alg: 'RS256', kid: 'oauth21-key-1', typ: 'JWT' })
    .setIssuedAt()
    .setIssuer(jwtConfig.issuer)
    .setExpirationTime(`${ttl}s`)
    .sign(key);

  return jwt;
}

async function verifyJwt(token) {
  const publicKeyPem = fs.readFileSync(jwtConfig.publicKeyPath, 'utf8');
  const key = await jose.importSPKI(publicKeyPem, 'RS256');

  try {
    const { payload, protectedHeader } = await jose.jwtVerify(token, key, {
      issuer: jwtConfig.issuer
    });
    return { valid: true, payload, header: protectedHeader };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

module.exports = { initJwt, signAccessToken, verifyJwt, getJwks };
