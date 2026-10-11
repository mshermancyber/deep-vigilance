// tp-pathtraversal.js: Path Traversal — user input flows into fs.readFile
const express = require('express');
const fs = require('fs');
const app = express();

app.get('/download', (req, res) => {
  const fileName = req.query.file;
  // VULNERABLE: user-controlled path passed to fs.readFile
  fs.readFile('/var/files/' + fileName, (err, data) => {
    if (err) return res.status(404).send('Not found');
    res.send(data);
  });
});
