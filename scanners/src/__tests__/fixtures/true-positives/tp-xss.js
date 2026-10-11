// tp-xss.js: XSS — user input flows into innerHTML
const express = require('express');
const app = express();

app.get('/greet', (req, res) => {
  const name = req.query.name;
  // VULNERABLE: user-controlled value assigned to variable then used in innerHTML
  const message = '<h1>Hello ' + name + '</h1>';
  res.send(`
    <html><body>
      <div id="greeting"></div>
      <script>
        document.getElementById('greeting').innerHTML = '${message}';
      </script>
    </body></html>
  `);
});
