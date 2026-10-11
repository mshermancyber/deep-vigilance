// tp-jwt.js: JWT with alg:none vulnerability
const jwt = require('jsonwebtoken');

function verifyToken(token) {
  // VULNERABLE: allowing 'none' algorithm
  const decoded = jwt.verify(token, '', { algorithms: ['none', 'HS256'] });
  return decoded;
}

function create(payload) {
  // Also vulnerable: signing with 'none'
  return jwt.sign(payload, '', { algorithm: 'none' });
}
