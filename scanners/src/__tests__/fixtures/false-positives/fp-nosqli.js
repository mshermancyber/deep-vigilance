// fp-nosqli.js: MongoDB with $eq (safe operator) — SAFE, no express
const MongoClient = require('mongodb').MongoClient;

async function findUsers(username) {
  const client = await MongoClient.connect('mongodb://localhost:27017');
  const db = client.db('mydb');
  // SAFE: using $eq operator — no injection possible
  const users = await db.collection('users').find({
    username: { $eq: username }
  }).toArray();
  return users;
}
