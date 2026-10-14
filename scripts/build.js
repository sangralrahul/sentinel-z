#!/usr/bin/env node
/**
 * Static build for hosting (Vercel, GitHub Pages, any web server).
 * Copies only what the browser needs into dist/. No bundler, no dependencies:
 * the site is plain ES modules, so the files are served exactly as written.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.join(ROOT, 'dist');
const ITEMS = ['index.html', 'web', 'core', 'data/sample-events.csv'];

fs.rmSync(OUT, { recursive: true, force: true });
let files = 0;
for (const item of ITEMS) {
  const src = path.join(ROOT, item);
  if (!fs.existsSync(src)) throw new Error(`Missing ${item}`);
  fs.cpSync(src, path.join(OUT, item), { recursive: true });
  files += fs.statSync(src).isDirectory() ? fs.readdirSync(src, { recursive: true }).length : 1;
}
console.log(`Built static site in dist/ (${files} files).`);
