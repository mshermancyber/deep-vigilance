// tp-nosqli.js: NoSQL injection — $where with user input
const express = require('express');
const MongoClient = require('mongodb').MongoClient;
const app = express();

app.get('/users', express.json(), async (req, res) => {
  const client = await MongoClient.connect('mongodb://localhost:27017');
  const db = client.db('mydb');
  // VULNERABLE: $where with unsanitized user input
  const users = await db.collection('users').find({
    $where: "this.username == '" + req.body.username + "'"
  }).toArray();
  res.json(users);
});
