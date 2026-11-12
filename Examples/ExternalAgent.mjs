// SPDX-License-Identifier: Apache-2.0
// Inspect one event batch through the local participant API without acknowledging it.
import fs from 'node:fs';
import net from 'node:net';

const [socketPath, credentialPath, room] = process.argv.slice(2);
if (!socketPath || !credentialPath || !room) {
  throw new Error('Usage: node ExternalAgent.mjs SOCKET CREDENTIAL_FILE ROOM_ID');
}
if (fs.lstatSync(credentialPath).isSymbolicLink() || fs.statSync(credentialPath).mode & 0o077) {
  throw new Error('Credential must be a private file with mode 0600');
}
const credential = JSON.parse(fs.readFileSync(credentialPath, 'utf8'));
function call(method, params = {}) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection(socketPath);
    const chunks = [];
    let length = 0;
    let complete = false;
    socket.setTimeout(45000, () => socket.destroy(new Error('API timeout')));
    socket.on('connect', () => socket.write(JSON.stringify({
      jsonrpc: '2.0', id: 1, method, params, auth: credential,
    }) + '\n'));
    socket.on('error', reject);
    socket.on('end', () => { if (!complete) reject(new Error('Incomplete API response')); });
    socket.on('data', chunk => {
      length += chunk.length;
      if (length > 1024 * 1024) return socket.destroy(new Error('Response too large'));
      chunks.push(chunk);
      if (!chunk.includes(10)) return;
      complete = true;
      try {
        const response = JSON.parse(Buffer.concat(chunks).toString('utf8').split('\n')[0]);
        if (response.error) reject(new Error(response.error.message));
        else resolve(response.result);
      } catch (error) { reject(error); }
      socket.end();
    });
  });
}
const consumer = 'javascript-example';
console.log(JSON.stringify(await call('status')));
await call('events.open', { consumer, room });
console.log(JSON.stringify(await call('events.next', { consumer })));
// Call events.ack with the exact batch ID only after durable application processing.
