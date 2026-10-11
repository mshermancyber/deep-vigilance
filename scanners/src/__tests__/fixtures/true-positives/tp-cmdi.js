// tp-cmdi.js: Command Injection — user input flows into exec
const express = require('express');
const { exec } = require('child_process');
const app = express();

app.get('/ping', (req, res) => {
  const host = req.params.cmd;
  // VULNERABLE: user input passed to shell command
  exec('ping -c 1 ' + host, (err, stdout) => {
    if (err) return res.status(500).send('Error');
    res.send('<pre>' + stdout + '</pre>');
  });
});
