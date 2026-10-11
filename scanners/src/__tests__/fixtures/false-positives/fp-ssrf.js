// fp-ssrf.js: SSRF with URL validation — SAFE
const express = require('express');
const fetch = require('node-fetch');
const app = express();

const ALLOWED_HOSTS = ['api.internal.example.com', 'cdn.example.com'];

function isAllowedUrl(url) {
  try {
    const parsed = new URL(url);
    return ALLOWED_HOSTS.includes(parsed.hostname);
  } catch {
    return false;
  }
}

app.post('/proxy', express.json(), async (req, res) => {
  const targetUrl = req.body.url;
  // SAFE: URL validated against allowlist before fetch
  if (!isAllowedUrl(targetUrl)) {
    return res.status(400).send('Invalid URL');
  }
  const response = await fetch(targetUrl);
  const body = await response.text();
  res.send(body);
});
