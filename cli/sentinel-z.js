#!/usr/bin/env node
/**
 * Sentinel-Z command line. Runs entirely on the machine it is started on:
 * a laptop, a server, or Linux on IBM Z / LinuxONE (s390x). No network calls,
 * except an optional local LLM on localhost for written explanations.
 *
 *   sentinel-z generate [--out file.csv] [--seed 7] [--users 80]
 *   sentinel-z analyze <events.csv|json> [--train-days 14 | --train-until ISO]
 *                      [--sensitivity 99.5] [--out report.json] [--explain]
 */
import fs from 'node:fs';
import { webcrypto } from 'node:crypto';
import path from 'node:path';
import { generateScenario, ATTACK_TYPES } from '../core/generator.js';
import { analyze, parseCSV, toCSV } from '../core/pipeline.js';
import { randomKey } from '../core/privacy.js';
import { explainLocally, isLocalUrl } from './llm.js';
import { injectAttack, SIM_ATTACKS } from '../core/simulator.js';
import { DATASETS } from './datasets.js';

// Node 18 does not expose Web Crypto as a global; the shared core uses globalThis.crypto.
if (!globalThis.crypto?.getRandomValues) Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true });

const args = process.argv.slice(2);
const cmd = args[0];
const opt = (name, def) => { const i = args.indexOf('--' + name); return i >= 0 && args[i + 1] && !args[i + 1].startsWith('--') ? args[i + 1] : def; };
const flag = (name) => args.includes('--' + name);
const c = process.stdout.isTTY ? { b: (s) => `\x1b[1m${s}\x1b[0m`, dim: (s) => `\x1b[2m${s}\x1b[0m`, red: (s) => `\x1b[31m${s}\x1b[0m`, yel: (s) => `\x1b[33m${s}\x1b[0m`, grn: (s) => `\x1b[32m${s}\x1b[0m` } : { b: String, dim: String, red: String, yel: String, grn: String };
const pct = (v) => (v * 100).toFixed(1) + '%';

function help() {
  console.log(`
${c.b('Sentinel-Z')}  privacy-preserving anomaly detection for banking security logs

Usage
  sentinel-z generate [--out data/sample-events.csv] [--seed 7] [--users 80]
  sentinel-z analyze <file.csv|file.json> [options]
  sentinel-z simulate [--type account_takeover] [--customer 3] [--day 2]
  sentinel-z benchmark paysim <PS_..._log.csv> [--sample 0.05] [--out benchmarks/paysim.json]
  sentinel-z benchmark ieee <folder with train_transaction.csv> [--sample 0.3] [--out benchmarks/ieee.json]

Analyze options
  --train-days N       Use the first N days as normal behaviour (default: first 70% of the time span)
  --train-until ISO    Or give the exact end of the baseline window
  --sensitivity P      Alert threshold as a percentile of baseline risk (default 99.5)
  --tz-offset MIN      Local time zone offset in minutes (default 330 = IST)
  --out report.json    Save the pseudonymised report
  --explain            Write a short analyst summary with a LOCAL LLM (Ollama, e.g. IBM Granite)
  --llm-url URL        Local LLM endpoint (default http://127.0.0.1:11434). Only localhost/private addresses are allowed.
  --llm-model NAME     Model name (default granite3.3:2b)

Simulate types
  ${Object.keys(SIM_ATTACKS).join(', ')}

Privacy key
  Set SENTINEL_KEY (16+ characters) to keep pseudonyms stable between runs.
  Without it a random key is used for this run only and never written anywhere.
`);
}

async function main() {
  if (!cmd || cmd === 'help' || flag('help')) return help();

  if (cmd === 'generate') {
    const out = opt('out', 'data/sample-events.csv');
    const sc = generateScenario({ seed: Number(opt('seed', 7)), users: Number(opt('users', 80)) });
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, toCSV(sc.events));
    const attacks = sc.events.filter((e) => e.label !== 'normal').length;
    console.log(`Wrote ${sc.events.length.toLocaleString()} events (${attacks} labelled attack events) to ${out}`);
    console.log(c.dim(`Baseline ends ${new Date(sc.trainUntil).toISOString()}  →  analyze with --train-days 14`));
    return;
  }

  if (cmd === 'benchmark') {
    const name = args[1], file = args[2];
    const loader = DATASETS[name];
    if (!loader) throw new Error(`Unknown dataset "${name || ''}". Use: paysim or ieee`);
    if (!file || !fs.existsSync(file)) throw new Error(`Not found: ${file || '(none)'}. Download the dataset from Kaggle first (see README, "Benchmarks on public datasets").`);
    const sample = Number(opt('sample', name === 'paysim' ? 0.05 : 0.3));
    const t0 = Date.now();
    console.log(c.dim(`Reading ${file} (customer sample rate ${sample}) …`));
    const d = await loader(file, { sample, maxRows: Number(opt('max-rows', Infinity)) });
    const positives = d.events.filter((e) => e.label !== 'normal').length;
    console.log(`${d.dataset}: read ${d.seen.toLocaleString()} rows, kept ${d.events.length.toLocaleString()} events from ${new Set(d.events.map((e) => e.user)).size.toLocaleString()} customers (${positives.toLocaleString()} fraud events) in ${((Date.now() - t0) / 1000).toFixed(1)} s`);
    const trainFrac = Number(opt('train-frac', 0.5));
    const first = d.events.reduce((m, e) => Math.min(m, e.ts), Infinity), last = d.events.reduce((m, e) => Math.max(m, e.ts), -Infinity);
    const r = analyze(d.events, { secret: process.env.SENTINEL_KEY || randomKey(), trainUntil: first + (last - first) * trainFrac, sensitivity: Number(opt('sensitivity', 99.5)), tzOffsetMinutes: 0 });
    const e = r.evaluation;
    if (!e) throw new Error('No labelled events in the evaluation window.');
    console.log(`\n${c.b('Benchmark on ' + d.dataset)}  ${c.dim(`baseline first ${Math.round(trainFrac * 100)}% of time, evaluated on ${r.meta.test.toLocaleString()} later events, ${r.meta.ms} ms`)}`);
    console.log(`ROC-AUC ${e.auc.toFixed(3)}  ·  precision ${pct(e.precision)}  ·  recall ${pct(e.recall)}  ·  F1 ${e.f1.toFixed(3)}  ·  false-alarm rate ${pct(e.fp / Math.max(1, e.negatives))}`);
    console.log(`Fraud events ${e.positives.toLocaleString()} of ${(e.positives + e.negatives).toLocaleString()}  ·  fraudulent customers flagged ${e.attacks.caught}/${e.attacks.total}`);
    for (const [k, v] of Object.entries(e.ablation)) console.log(c.dim(`  ${k.padEnd(7)} ROC-AUC ${v.auc.toFixed(3)} · precision ${pct(v.precision)} · recall ${pct(v.recall)}`));
    const reasons = {};
    for (const a of r.alerts) for (const x of a.reasons) reasons[x.code] = (reasons[x.code] || 0) + 1;
    console.log(c.dim('  Top alert reasons: ' + Object.entries(reasons).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([k, v]) => `${k} ${v}`).join(', ')));
    const out = opt('out', `benchmarks/${name}.json`);
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, JSON.stringify({
      dataset: d.dataset, source: d.source, generated: new Date().toISOString(), node: process.version, platform: `${process.platform}/${process.arch}`,
      rowsRead: d.seen, customerSampleRate: sample, eventsKept: d.events.length, fraudEvents: positives, trainFraction: trainFrac,
      threshold: r.meta.threshold, evaluatedEvents: r.meta.test, runtimeMs: r.meta.ms,
      metrics: { rocAuc: e.auc, precision: e.precision, recall: e.recall, f1: e.f1, tp: e.tp, fp: e.fp, fn: e.fn, tn: e.tn, fraudCustomersFlagged: e.attacks },
      ablation: Object.fromEntries(Object.entries(e.ablation).map(([k, v]) => [k, { rocAuc: v.auc, precision: v.precision, recall: v.recall, f1: v.f1 }])),
      topReasons: reasons
    }, null, 2));
    console.log(`\nSaved metrics (no raw data) to ${out}`);
    return;
  }

  if (cmd === 'simulate') {
    const type = opt('type', 'account_takeover');
    const sc = generateScenario({ seed: 7 });
    const inj = injectAttack(sc, { type, customer: Number(opt('customer', 3)), day: Number(opt('day', 2)) });
    const r = analyze(inj.events, { secret: process.env.SENTINEL_KEY || randomKey(), trainUntil: sc.trainUntil, keepRows: true });
    const hit = r.rows.filter((x) => x.case === 'sim-1');
    const caught = hit.filter((x) => x.severity).length;
    console.log(`\n${c.b('Simulated ' + SIM_ATTACKS[type].name)}  ${c.dim(SIM_ATTACKS[type].desc)}`);
    for (const x of hit) console.log(`  ${x.severity ? c.red((x.severity.toUpperCase()).padEnd(9)) : c.dim('missed   ')} risk ${x.score.toFixed(2)}  ${x.event.padEnd(12)} ${x.reasons[0]?.text || ''}`);
    console.log(caught ? c.grn(`\nDetected: ${caught}/${hit.length} events alerted (threshold ${r.meta.threshold.toFixed(3)})`) : c.yel(`\nNot detected (peak risk ${Math.max(...hit.map((x) => x.score)).toFixed(2)}, threshold ${r.meta.threshold.toFixed(3)})`));
    return;
  }

  if (cmd === 'analyze') {
    const file = args[1];
    if (!file || !fs.existsSync(file)) throw new Error(`File not found: ${file || '(none)'}. Try: sentinel-z generate`);
    const text = fs.readFileSync(file, 'utf8');
    const rows = file.toLowerCase().endsWith('.json') ? JSON.parse(text) : parseCSV(text);
    const secret = process.env.SENTINEL_KEY || randomKey();
    if (process.env.SENTINEL_KEY && process.env.SENTINEL_KEY.length < 16) throw new Error('SENTINEL_KEY must be at least 16 characters.');

    let trainUntil = opt('train-until');
    if (!trainUntil && opt('train-days')) {
      const first = Math.min(...rows.map((r) => Date.parse(r.timestamp ?? r.ts)).filter(Number.isFinite));
      trainUntil = first + Number(opt('train-days')) * 86400000;
    }
    const r = analyze(rows, { secret, trainUntil, sensitivity: Number(opt('sensitivity', 99.5)), tzOffsetMinutes: Number(opt('tz-offset', 330)) });
    const m = r.meta;

    console.log(`\n${c.b('Sentinel-Z report')}  ${c.dim(`${m.ms} ms on ${process.platform}/${process.arch}`)}`);
    console.log(`Events ${m.events.toLocaleString()}  ·  users ${m.users}  ·  baseline ${m.train.toLocaleString()}  ·  checked ${m.test.toLocaleString()}${m.rejected ? c.yel(`  ·  ${m.rejected} invalid rows skipped`) : ''}`);
    console.log(`Privacy: ${Object.entries(r.audit.tokenized).map(([k, v]) => `${v} ${k}s`).join(', ')} pseudonymised; ${Object.entries(r.audit.redacted).map(([k, v]) => `${v} ${k}`).join(', ') || 'no PII'} redacted in notes.`);
    console.log(`\n${c.b(`${r.incidents.length} incidents`)} from ${r.alerts.length} alerts (threshold ${m.threshold.toFixed(3)})\n`);
    for (const inc of r.incidents.slice(0, 12)) {
      const sev = inc.severity === 'critical' ? c.red('CRITICAL') : inc.severity === 'high' ? c.yel('HIGH    ') : 'MEDIUM  ';
      console.log(`${sev} ${inc.user}  ${new Date(inc.start).toISOString().slice(0, 16).replace('T', ' ')}  risk ${inc.score.toFixed(2)}  ${c.dim(`${inc.alerts.length} event(s)`)}`);
      for (const reason of inc.reasons.slice(0, 3)) console.log(`         • ${reason.text}`);
    }
    if (r.incidents.length > 12) console.log(c.dim(`… and ${r.incidents.length - 12} more (see --out report)`));

    if (r.evaluation) {
      const e = r.evaluation;
      console.log(`\n${c.b('Evaluation on labelled data')}`);
      console.log(`ROC-AUC ${e.auc.toFixed(3)}  ·  precision ${pct(e.precision)}  ·  recall ${pct(e.recall)}  ·  F1 ${e.f1.toFixed(3)}  ·  attacks caught ${c.grn(`${e.attacks.caught}/${e.attacks.total}`)}`);
      for (const [type, v] of Object.entries(e.byType)) console.log(`  ${(ATTACK_TYPES[type] || type).padEnd(36)} ${v.caught}/${v.total} events`);
      console.log(c.dim(`  model only: recall ${pct(e.ablation.model.recall)} · rules only: recall ${pct(e.ablation.rules.recall)} · hybrid: recall ${pct(e.ablation.hybrid.recall)}`));
    }

    if (flag('explain')) {
      const url = opt('llm-url', 'http://127.0.0.1:11434');
      if (!isLocalUrl(url)) throw new Error('Refusing to send data to a non-local LLM. Use a localhost or private-network address.');
      console.log(`\n${c.b('Analyst summary')} ${c.dim(`(local model ${opt('llm-model', 'granite3.3:2b')} at ${url})`)}`);
      console.log(await explainLocally(r.incidents.slice(0, 5), { url, model: opt('llm-model', 'granite3.3:2b') }));
    }

    const out = opt('out');
    if (out) {
      const report = { generated: new Date().toISOString(), meta: r.meta, audit: r.audit, incidents: r.incidents.map((i) => ({ ...i, alerts: i.alerts.map(({ x, note, ...a }) => a) })), evaluation: r.evaluation && { ...r.evaluation, roc: undefined }, shareable: r.shareable };
      fs.writeFileSync(out, JSON.stringify(report, null, 2));
      console.log(`\nSaved pseudonymised report to ${out}`);
    }
    return;
  }

  help();
  process.exitCode = 1;
}

main().catch((e) => { console.error(c.red('Error: ') + e.message); process.exitCode = 1; });
