const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const jose = require('jose');
const config = require('./config');

let privateKey;
let publicKey;
let jwk;

function loadKeys() {
  const privateKeyPem = fs.readFileSync(path.join(__dirname, '..', 'keys', 'private.pem'), 'utf8');
  const publicKeyPem = fs.readFileSync(path.join(__dirname, '..', 'keys', 'public.pem'), 'utf8');

  privateKey = crypto.createPrivateKey(privateKeyPem);
  publicKey = crypto.createPublicKey(publicKeyPem);
}

function getJwks() {
  if (!jwk) {
    const publicKeyPem = fs.readFileSync(path.join(__dirname, '..', 'keys', 'public.pem'), 'utf8');
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
  const privateKeyPem = fs.readFileSync(path.join(__dirname, '..', 'keys', 'private.pem'), 'utf8');
  const key = await jose.importPKCS8(privateKeyPem, 'RS256');

  const jti = 'jwt_' + crypto.randomBytes(16).toString('hex');
  const ttl = expiresInSeconds || config.accessTokenTTL;

  const jwt = await new jose.SignJWT({ ...payload, jti })
    .setProtectedHeader({ alg: 'RS256', kid: 'oauth21-key-1', typ: 'JWT' })
    .setIssuedAt()
    .setIssuer(config.issuer)
    .setExpirationTime(`${ttl}s`)
    .sign(key);

  return jwt;
}

async function verifyJwt(token) {
  const publicKeyPem = fs.readFileSync(path.join(__dirname, '..', 'keys', 'public.pem'), 'utf8');
  const key = await jose.importSPKI(publicKeyPem, 'RS256');

  try {
    const { payload, protectedHeader } = await jose.jwtVerify(token, key, {
      issuer: config.issuer
    });
    return { valid: true, payload, header: protectedHeader };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

module.exports = { signAccessToken, verifyJwt, getJwks };
