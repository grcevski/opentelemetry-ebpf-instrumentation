// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const fs = require('fs');
const http = require('http');
const { execFileSync, spawn } = require('child_process');

// Node's child-process "pipe" uses a socket pair, which pipe_write does not
// intercept. Use a FIFO so the child has the same stdout path as a container.
const fifo = '/tmp/logs.fifo';
execFileSync('mkfifo', [fifo]);
const readerFD = fs.openSync(fifo, 'r+');
const writerFD = fs.openSync(fifo, 'w');
const child = spawn(process.execPath, ['app.js'], { stdio: ['ignore', writerFD, 'inherit'] });
fs.closeSync(writerFD);

let enriched = false;
let pending = '';
let paused = false;
const reader = fs.createReadStream(fifo, { fd: readerFD });
reader.on('data', chunk => {
  if (enriched) return;
  pending += chunk.toString();
  const end = pending.lastIndexOf('\n');
  if (end >= 0) {
    enriched = pending.slice(0, end).includes('"trace_id":"4bf92f3577b34da6a3ce929d0e0e4736"');
    pending = pending.slice(end + 1);
  }
});

http.createServer((req, res) => {
  if (req.url === '/pause') { reader.pause(); paused = true; }
  if (req.url === '/resume') { reader.resume(); paused = false; }
  res.end(JSON.stringify({ enriched, paused }));
}).listen(3031, '0.0.0.0');

process.on('SIGTERM', () => {
  child.kill('SIGTERM');
  process.exit(0);
});
