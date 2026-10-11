// fp-sqli.js: Parameterized query — SAFE, no express, no hardcoded credentials
const { Pool } = require('pg');

const pool = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

async function getUser(userId) {
  // SAFE: parameterized query with placeholder ($1)
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [userId]);
  return result.rows;
}
