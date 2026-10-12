#!/usr/bin/env node
/** Tiny static server for the web dashboard. No dependencies. Usage: npm start [-- port] */
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const PORT = Number(process.argv[2] || process.env.PORT || 5173);
// Same security headers as vercel.json, so local runs match production.
let HEADERS = { 'X-Content-Type-Options': 'nosniff' };
try { HEADERS = Object.fromEntries(JSON.parse(fs.readFileSync(path.join(ROOT, 'vercel.json'), 'utf8')).headers[0].headers.map((h) => [h.key, h.value])); } catch { /* vercel.json missing: basic headers only */ }
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.csv': 'text/csv; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.md': 'text/markdown; charset=utf-8', '.woff2': 'font/woff2' };

http.createServer((req, res) => {
  let p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (p.endsWith('/')) p += 'index.html';
  const file = path.normalize(path.join(ROOT, p));
  if (!file.startsWith(ROOT + path.sep)) { res.writeHead(403).end('Forbidden'); return; }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain' }).end('Not found'); return; }
    res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream', ...HEADERS, 'Cache-Control': 'no-cache' });
    res.end(data);
  });
}).on('error', (e) => { console.error(e.code === 'EADDRINUSE' ? `Port ${PORT} is busy. Try: npm start -- 8080` : e.message); process.exit(1); })
  .listen(PORT, () => console.log(`\n  Sentinel-Z dashboard: http://localhost:${PORT}\n  Press Ctrl+C to stop.\n`));
