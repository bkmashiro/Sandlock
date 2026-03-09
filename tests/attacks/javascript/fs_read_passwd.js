const fs = require('fs');
console.log(fs.readFileSync('/etc/passwd', 'utf8'));
