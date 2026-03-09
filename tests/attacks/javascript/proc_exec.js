const { exec } = require('child_process');
exec('whoami', (err, stdout) => console.log(stdout));
