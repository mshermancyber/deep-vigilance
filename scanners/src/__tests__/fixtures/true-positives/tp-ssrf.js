// tp-ssrf.js: SSRF — user-supplied URL passed directly to fetch in same expression
const express = require('express');
const fetch = require('node-fetch');
const app = express();

app.post('/proxy', express.json(), async (req, res) => {
  // VULNERABLE: user-controlled URL passed directly to fetch
  const response = await fetch(req.body.url);
  const body = await response.text();
  res.send(body);
});
