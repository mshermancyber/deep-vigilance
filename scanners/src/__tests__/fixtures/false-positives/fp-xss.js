// fp-xss.js: XSS with DOMPurify sanitization — SAFE
const express = require('express');
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');
const app = express();

app.get('/greet', (req, res) => {
  const name = req.query.name;
  // SAFE: sanitized with DOMPurify before rendering
  const window = new JSDOM('').window;
  const DOMPurify = createDOMPurify(window);
  const cleanName = DOMPurify.sanitize(name);
  res.send(`<html><body><h1>Hello ${cleanName}</h1></body></html>`);
});
