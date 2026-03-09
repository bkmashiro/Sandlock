const fs = require('fs');
fs.writeFileSync('/tmp/test.txt', 'ok');
console.log('wrote to /tmp');
