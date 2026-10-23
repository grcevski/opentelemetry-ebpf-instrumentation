// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

const http = require('http');

const line = JSON.stringify({ message: 'shutdown load', data: 'x'.repeat(960) }) + '\n';
let timer;
let lines = 0;
let blocked = false;

process.stdout.on('drain', () => { blocked = false; });

function logBatch() {
  if (blocked) return;
  for (let i = 0; i < 64; i++) {
    lines++;
    if (!process.stdout.write(line)) {
      blocked = true;
      return;
    }
  }
}

const server = http.createServer((req, res) => {
  if (req.url === '/marker') console.log(JSON.stringify({ message: 'shutdown marker' }));
  if (req.url === '/backpressure') console.log(JSON.stringify({ message: 'backpressure marker' }));
  if (req.url === '/start' && !timer) timer = setInterval(logBatch, 10);
  if (req.url === '/burst') {
    for (let i = 0; i < 256; i++) {
      lines++;
      if (!process.stdout.write(line)) blocked = true;
    }
  }
  res.end(JSON.stringify({ lines, blocked }));
});

process.on('SIGTERM', () => {
  clearInterval(timer);
  server.close();
});

server.listen(3030, '0.0.0.0');
