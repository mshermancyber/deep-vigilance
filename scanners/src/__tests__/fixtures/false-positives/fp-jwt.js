// fp-jwt.js: JWT with verify() and proper algorithm — SAFE
const jwt = require('jsonwebtoken');
const SECRET = process.env.JWT_SECRET || 'super-secret-key';

function verifyToken(token) {
  // SAFE: proper algorithm, secret, and verification
  const decoded = jwt.verify(token, SECRET, { algorithms: ['HS256'] });
  return decoded;
}

function create(payload) {
  // SAFE: standard signing with secret
  return jwt.sign(payload, SECRET, { algorithm: 'HS256' });
}
