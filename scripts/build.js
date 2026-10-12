#!/usr/bin/env node
// Static build for hosting: copies only what the browser needs into dist/.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'dist');
const ITEMS = ['index.html', 'web', 'core', 'data/sample-events.csv'];

fs.rmSync(OUT, { recursive: true, force: true });
for (const item of ITEMS) {
  const src = path.join(ROOT, item);
  if (!fs.existsSync(src)) throw new Error('Missing ' + item);
  fs.cpSync(src, path.join(OUT, item), { recursive: true });
}
console.log('Built static site in dist/');