// fp-pathtraversal.js: Path with join + basename — SAFE
const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

const SAFE_DIR = '/var/files';

app.get('/download', (req, res) => {
  const userInput = req.query.file;
  // SAFE: basename strips traversal, path.join resolves safely
  const safeName = path.basename(userInput);
  const filePath = path.join(SAFE_DIR, safeName);
  // Ensure the resolved path is still within SAFE_DIR
  if (!filePath.startsWith(SAFE_DIR)) {
    return res.status(403).send('Forbidden');
  }
  fs.readFile(filePath, (err, data) => {
    if (err) return res.status(404).send('Not found');
    res.send(data);
  });
});
