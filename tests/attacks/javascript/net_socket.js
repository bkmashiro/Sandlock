const net = require('net');
const client = net.connect(80, 'example.com');
client.on('connect', () => console.log('connected'));
