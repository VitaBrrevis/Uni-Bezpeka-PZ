import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';
import fetch from 'node-fetch';

const algorithms = ['RS256'];

export function makeJwksClient(jwksUri) {
  return jwksClient({
    jwksUri,
    cache: true,
    cacheMaxEntries: 5,
    cacheMaxAge: 10 * 60 * 1000,
    rateLimit: true,
    jwksRequestsPerMinute: 10
  });
}

export function verifyWithJWKS(token, { issuer, audience, jwksClient }) {
  return new Promise((resolve, reject) => {
    function getKey(header, cb) {
      jwksClient.getSigningKey(header.kid, (err, key) => {
        if (err) return cb(err);
        const signingKey = key.getPublicKey();
        cb(null, signingKey);
      });
    }
    jwt.verify(token, getKey, { algorithms, issuer, audience }, (err, decoded) => {
      if (err) return reject(err);
      resolve(decoded);
    });
  });
}

export async function verifyWithPEM(token, { issuer, audience, pemUrl }) {
  const res = await fetch(pemUrl);
  if (!res.ok) throw new Error(`Cannot fetch PEM: ${res.status}`);
  const pem = await res.text();
  const decoded = jwt.verify(token, pem, { algorithms, issuer, audience });
  return decoded;
}

export async function verifyIdToken({ token, issuer, clientId, jwksUri, pemUrl }) {
  const client = makeJwksClient(jwksUri);
  try {
    const decoded = await verifyWithJWKS(token, { issuer, audience: clientId, jwksClient: client });
    return { valid: true, decoded, method: 'jwks' };
  } catch (e1) {
    if (!pemUrl) throw e1;
    const decoded = await verifyWithPEM(token, { issuer, audience: clientId, pemUrl });
    return { valid: true, decoded, method: 'pem' };
  }
}

export async function verifyAccessToken({ token, issuer, audience, jwksUri, pemUrl }) {
  const client = makeJwksClient(jwksUri);
  try {
    const decoded = await verifyWithJWKS(token, { issuer, audience, jwksClient: client });
    return { valid: true, decoded, method: 'jwks' };
  } catch (e1) {
    if (!pemUrl) throw e1;
    const decoded = await verifyWithPEM(token, { issuer, audience, pemUrl });
    return { valid: true, decoded, method: 'pem' };
  }
}
