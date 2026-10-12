// One analysis job, shared by the Web Worker and the main-thread fallback.
import { analyze, parseCSV, normalizeEvents } from '../core/pipeline.js';
import { buildProfiles, FEATURES } from '../core/features.js';
import { generateScenario } from '../core/generator.js';
import { mulberry32 } from '../core/rng.js';
import { injectAttack } from '../core/simulator.js';

export function runJob({ demoSeed, text, fileName, trainDays, sensitivity, secret, stream, simulate }) {
  let rows, sim = null;
  if (demoSeed != null) {
    const sc = generateScenario({ seed: demoSeed });
    rows = sc.events;
    if (simulate) { sim = injectAttack(sc, simulate); rows = sim.events; }
  }
  else if (/\.json$/i.test(fileName || '') || /^\s*[[{]/.test(text)) {
    const parsed = JSON.parse(text);
    rows = Array.isArray(parsed) ? parsed : parsed.events;
    if (!Array.isArray(rows)) throw new Error('JSON must be an array of events, or an object with an "events" array.');
  } else rows = parseCSV(text);

  let trainUntil;
  if (trainDays) {
    let first = Infinity;
    for (const r of rows) { const v = r.ts ?? r.timestamp ?? r.time; const t = typeof v === 'number' ? v : Date.parse(v); if (t < first) first = t; }
    if (Number.isFinite(first)) trainUntil = first + trainDays * 86400000;
  }
  const result = analyze(rows, { secret, trainUntil, sensitivity, keepRows: true });
  if (sim) {
    const hit = result.rows.filter((r) => r.case === 'sim-1');
    result.sim = {
      type: simulate.type, target: hit.at(-1)?.user, events: hit,
      caught: hit.filter((r) => r.severity).length, total: hit.length,
      maxScore: Math.max(0, ...hit.map((r) => r.score)), threshold: result.meta.threshold,
      incident: result.incidents.find((i) => i.alerts.some((a) => a.case === 'sim-1')) || null
    };
  }
  if (!stream) return result;

  // Replay sample for the landing-page console (synthetic demo data only):
  // every alert plus a random sample of normal events, in time order.
  const raw = normalizeEvents(rows).events;
  const rand = mulberry32(99);
  const replay = [];
  let tok = 0, pii = 0, alerts = 0;
  result.rows.forEach((r, n) => {
    const e = raw[r.i];
    tok += [e.user, e.ip, e.device, e.account].filter(Boolean).length;
    if (e.note && e.note !== r.note) pii++;
    if (r.severity) alerts++;
    if (!r.severity && rand() >= 0.2) return;
    replay.push({
      ts: r.ts, event: r.event, city: e.city, amount: e.amount, bytes: e.bytes,
      raw: { user: e.user, ip: e.ip, note: e.note },
      safe: { user: r.user, ip: r.ip, note: r.note },
      score: r.score, severity: r.severity, reason: r.reasons[0]?.text || '', reasons: r.reasons.slice(0, 4).map((x) => ({ code: x.code, text: x.text })),
      totals: { events: n + 1, tok, pii, alerts }
    });
  });
  // One worked example for the "How it works" walkthrough: a real account-takeover alert.
  const pickRow = result.rows.find((r) => r.severity && r.label === 'account_takeover' && r.event === 'transfer') || result.rows.find((r) => r.severity);
  let showcase = null;
  if (pickRow) {
    const e = raw[pickRow.i];
    const train = raw.filter((x) => x.ts < result.meta.trainUntil && x.user === e.user);
    const prof = buildProfiles(train).profiles.get(e.user);
    const exact = { alerts: result.alerts.length, incidents: result.incidents.length, events: result.meta.test };
    showcase = {
      raw: { ts: new Date(e.ts).toISOString(), user: e.user, event: e.event, ip: e.ip, device: e.device, city: e.city, amount: e.amount, account: e.account, note: e.note },
      safe: { user: pickRow.user, event: pickRow.event, ip: pickRow.ip, device: pickRow.device, city: pickRow.city, amount: pickRow.amount, note: pickRow.note },
      profile: prof && { usualHour: prof.hourMean, typicalTransfer: Math.round(Math.expm1(prof.amount.mean)), devices: prof.devices.size, cities: [...prof.cities], payees: prof.beneficiaries.size, events: train.length },
      features: Object.fromEntries(FEATURES.map((f, k) => [f, Math.round(pickRow.x[k] * 100) / 100])),
      model: pickRow.model, rules: pickRow.rules, score: pickRow.score, threshold: result.meta.threshold,
      severity: pickRow.severity, reasons: pickRow.reasons.map((x) => ({ code: x.code, w: x.w, text: x.text })),
      exact, shared: { alerts: result.shareable.alerts, incidents: result.shareable.incidents, events: result.shareable.events }
    };
  }
  return { ...result, replay, showcase };
}
