// fp-cmdi.js: Command with spawn (not exec) — SAFE
const { spawn } = require('child_process');

function listFiles() {
  // SAFE: using spawn with array args, no shell interpolation
  const child = spawn('ls', ['-la', '/var/log']);
  child.stdout.on('data', (data) => {
    console.log(data.toString());
  });
}
