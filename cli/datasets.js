/**
 * Adapters for public fraud datasets, so Sentinel-Z can be benchmarked on data
 * we did not generate ourselves. Files are streamed line by line, so multi-GB
 * CSVs never need to fit in memory, and customers are sampled by a hash of their
 * ID (never by row), which keeps every sampled customer's full history intact.
 *
 *  - PaySim (Lopez-Rojas et al., 2016): mobile-money transactions with fraud labels.
 *    Kaggle: https://www.kaggle.com/datasets/ealaxi/paysim1  (file: PS_*_log.csv)
 *  - IEEE-CIS Fraud Detection (Vesta, 2019): card-not-present e-commerce transactions.
 *    Kaggle: https://www.kaggle.com/competitions/ieee-fraud-detection  (train_transaction.csv,
 *    optional train_identity.csv in the same folder)
 *
 * The datasets are NOT included in this repository: download them from Kaggle and
 * respect their licences. Only the adapter code and the resulting metrics are ours.
 */
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import { sha256, utf8 } from '../core/sha256.js';

const BASE = Date.UTC(2026, 0, 1);

/** Split one CSV line (RFC 4180 quotes supported). */
export function splitCSVLine(line) {
  const out = [];
  let cur = '', q = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (q) {
      if (ch === '"') { if (line[i + 1] === '"') { cur += '"'; i++; } else q = false; }
      else cur += ch;
    } else if (ch === '"') q = true;
    else if (ch === ',') { out.push(cur); cur = ''; }
    else cur += ch;
  }
  out.push(cur);
  return out;
}

/** Deterministic customer sampling: keep a customer if hash(id) falls under the rate. */
export function keepCustomer(id, rate) {
  if (rate >= 1) return true;
  const h = sha256(utf8(String(id)));
  return ((h[0] << 8) | h[1]) / 65536 < rate;
}

async function* rows(file) {
  const rl = readline.createInterface({ input: fs.createReadStream(file), crlfDelay: Infinity });
  let header = null;
  for await (const line of rl) {
    if (!line) continue;
    const cells = splitCSVLine(line);
    if (!header) { header = cells.map((h) => h.trim()); continue; }
    const r = {};
    header.forEach((h, i) => { r[h] = cells[i]; });
    yield r;
  }
}

/**
 * PaySim → Sentinel-Z events.
 * step (hour) → timestamp; nameOrig → user; nameDest → beneficiary account;
 * oldbalanceOrg → balance; TRANSFER / CASH_OUT / PAYMENT / DEBIT → transfer; CASH_IN → deposit.
 */
export async function loadPaySim(file, { sample = 0.05, maxRows = Infinity } = {}) {
  const events = [];
  let seen = 0, n = 0;
  for await (const r of rows(file)) {
    seen++;
    if (!r.nameOrig || !keepCustomer(r.nameOrig, sample)) continue;
    const type = String(r.type || '').toUpperCase();
    const fraud = r.isFraud === '1';
    events.push({
      ts: BASE + Number(r.step) * 3600000 + (seen % 3600) * 1000, // spread events within the hour, order preserved
      user: r.nameOrig,
      event: type === 'CASH_IN' ? 'deposit' : 'transfer',
      amount: Number(r.amount),
      account: r.nameDest,
      balance: Number(r.oldbalanceOrg),
      note: type,
      label: fraud ? 'paysim_fraud' : 'normal',
      case: fraud ? `paysim-${r.nameOrig}` : undefined
    });
    if (++n >= maxRows) break;
  }
  return { events, seen, dataset: 'PaySim', source: path.basename(file) };
}

/**
 * IEEE-CIS → Sentinel-Z events.
 * A customer is approximated by card1 + addr1 + purchaser email domain (a common proxy,
 * since the competition has no customer ID). TransactionDT (seconds) → timestamp;
 * TransactionAmt → amount; DeviceInfo (identity table) → device; ProductCD → note.
 */
export async function loadIEEE(dir, { sample = 0.3, maxRows = Infinity } = {}) {
  const txFile = fs.statSync(dir).isDirectory() ? path.join(dir, 'train_transaction.csv') : dir;
  const idFile = path.join(path.dirname(txFile), 'train_identity.csv');
  const devices = new Map();
  if (fs.existsSync(idFile)) {
    for await (const r of rows(idFile)) if (r.DeviceInfo) devices.set(r.TransactionID, r.DeviceInfo);
  }
  const events = [];
  let seen = 0, n = 0;
  for await (const r of rows(txFile)) {
    seen++;
    const user = `card${r.card1 || 'x'}-addr${r.addr1 || 'x'}-${r.P_emaildomain || 'noemail'}`;
    if (!keepCustomer(user, sample)) continue;
    const fraud = r.isFraud === '1';
    events.push({
      ts: BASE + Number(r.TransactionDT) * 1000,
      user,
      event: 'transfer',
      amount: Number(r.TransactionAmt),
      device: devices.get(r.TransactionID) || '',
      note: `product ${r.ProductCD || '?'}`,
      label: fraud ? 'card_fraud' : 'normal',
      case: fraud ? `ieee-${user}` : undefined
    });
    if (++n >= maxRows) break;
  }
  events.sort((a, b) => a.ts - b.ts);
  return { events, seen, dataset: 'IEEE-CIS Fraud Detection', source: path.basename(txFile), devices: devices.size };
}

export const DATASETS = { paysim: loadPaySim, ieee: loadIEEE };
