// tp-sqli.js: SQLi — user input concatenated into SQL query
const express = require('express');
const mysql = require('mysql');

const app = express();
const db = mysql.createConnection({ host: 'localhost', user: 'root', password: 'pass', database: 'app' });

app.get('/user', (req, res) => {
  const username = req.query.name;
  // VULNERABLE: direct concatenation into SQL
  const query = "SELECT * FROM users WHERE name = '" + username + "'";
  db.query(query, (err, rows) => {
    if (err) return res.status(500).send('Error');
    res.json(rows);
  });
});
