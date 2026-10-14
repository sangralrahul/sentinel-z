/**
 * End-to-end analysis:
 *   raw events → protect (pseudonymise + redact) → baseline profiles → features
 *   → Isolation Forest trained on the baseline window → scores → alerts → incidents
 *   → (if labels exist) honest evaluation metrics.
 *
 * Everything runs locally: in the browser tab, or with Node on IBM Z / LinuxONE.
 */
import { protectEvents, laplaceCount } from './privacy.js';
import { buildProfiles, computeFeatures, explain, FEATURES, setTimezoneOffset } from './features.js';
import { IsolationForest } from './iforest.js';
import { mulberry32 } from './rng.js';

const toMs = (v) => (typeof v === 'number' ? v : Date.parse(v));

/** Normalise loose input rows (from CSV/JSON) into typed events. Invalid rows are counted, not thrown. */
export function normalizeEvents(rows) {
  const events = [], rejected = [];
  rows.forEach((r, i) => {
    const ts = toMs(r.ts ?? r.timestamp ?? r.time);
    const user = r.user ?? r.user_id ?? r.username;
    const event = String(r.event ?? r.type ?? '').toLowerCase();
    if (!Number.isFinite(ts) || !user || !event) { rejected.push(i + 1); return; }
    events.push({
      ts, user: String(user), event,
      ip: r.ip ? String(r.ip) : '', device: r.device ? String(r.device) : '', city: r.city ? String(r.city) : '',
      amount: r.amount !== undefined && r.amount !== '' ? Number(r.amount) : undefined,
      bytes: r.bytes !== undefined && r.bytes !== '' ? Number(r.bytes) : undefined,
      account: r.account ? String(r.account) : '', note: r.note ? String(r.note) : '',
      label: r.label ? String(r.label) : undefined,
      case: r.case ? String(r.case) : undefined,
      // Optional: account balance before the event (e.g. PaySim oldbalanceOrg), enables the 'account drained' signal.
      balance: r.balance !== undefined && r.balance !== '' ? Number(r.balance) : undefined
    });
  });
  events.sort((a, b) => a.ts - b.ts);
  return { events, rejected };
}

function percentile(sorted, p) {
  if (!sorted.length) return 0;
  const i = Math.min(sorted.length - 1, Math.max(0, Math.round((p / 100) * (sorted.length - 1))));
  return sorted[i];
}

export function rocAuc(scores, labels) {
  const pairs = scores.map((s, i) => [s, labels[i]]).sort((a, b) => a[0] - b[0]);
  let pos = 0, neg = 0, rankSum = 0;
  for (let i = 0; i < pairs.length; ) {
    let j = i;
    while (j < pairs.length && pairs[j][0] === pairs[i][0]) j++;
    const avgRank = (i + 1 + j) / 2;
    for (let k = i; k < j; k++) if (pairs[k][1]) { rankSum += avgRank; pos++; } else neg++;
    i = j;
  }
  if (!pos || !neg) return null;
  return (rankSum - (pos * (pos + 1)) / 2) / (pos * neg);
}

export function rocCurve(scores, labels, steps = 60) {
  const P = labels.filter(Boolean).length, N = labels.length - P;
  const ths = [...new Set(scores)].sort((a, b) => b - a);
  const pick = ths.filter((_, i) => i % Math.max(1, Math.floor(ths.length / steps)) === 0);
  const pts = [[0, 0]];
  for (const th of pick) {
    let tp = 0, fp = 0;
    scores.forEach((s, i) => { if (s >= th) labels[i] ? tp++ : fp++; });
    pts.push([fp / (N || 1), tp / (P || 1)]);
  }
  pts.push([1, 1]);
  return pts;
}

/**
 * Run the full analysis.
 * options: secret (privacy key), trainUntil (ms; default = first 70% of the time span),
 * sensitivity (percentile of baseline scores used as the alert threshold, default 99.5),
 * tzOffsetMinutes (default 330 = IST), seed.
 */
export function analyze(rawRows, { secret, trainUntil, sensitivity = 99.5, tzOffsetMinutes = 330, seed = 42, trees = 150, keepRows = false } = {}) {
  const t0 = Date.now();
  setTimezoneOffset(tzOffsetMinutes);
  const { events: normalized, rejected } = normalizeEvents(rawRows);
  if (normalized.length < 50) throw new Error(`Need at least 50 valid events to learn a baseline (got ${normalized.length}).`);

  const { events, audit } = protectEvents(normalized, secret);
  const first = events[0].ts, lastTs = events[events.length - 1].ts;
  const split = trainUntil ? toMs(trainUntil) : first + (lastTs - first) * 0.7;
  const train = events.filter((e) => e.ts < split);
  if (train.length < 30) throw new Error('The training window is too short. Include more history before the period you want to check.');

  const prof = buildProfiles(train);
  const feats = computeFeatures(events, prof);
  const trainX = [], trainIdx = [];
  events.forEach((e, i) => { if (e.ts < split) { trainX.push(feats[i].x); trainIdx.push(i); } });

  // 1. Unsupervised model: how unusual is this behaviour overall?
  const model = new IsolationForest({ trees, sampleSize: 256, seed }).fit(trainX);
  const ifRaw = feats.map((f) => model.score(f.x));
  const ifBase = trainIdx.map((i) => ifRaw[i]).sort((a, b) => a - b);
  const ifLo = percentile(ifBase, 50), ifHi = percentile(ifBase, 99.9);
  const modelPart = ifRaw.map((s) => Math.max(0, Math.min(1, (s - ifLo) / Math.max(1e-6, ifHi - ifLo))));

  // 2. Expert evidence: explainable indicators, combined as independent evidence.
  const reasons = events.map((e, i) => explain(e, feats[i].x, feats[i].ctx));
  const rulePart = reasons.map((rs) => 1 - rs.reduce((p, r) => p * (1 - r.w / 12), 1));

  // 3. Hybrid risk: either strong evidence or a strongly unusual pattern raises risk.
  const hybrid = modelPart.map((m, i) => 1 - (1 - 0.85 * m) * (1 - rulePart[i]));
  const modes = { model: modelPart, rules: rulePart, hybrid };
  const scores = hybrid;
  const baseScores = trainIdx.map((i) => scores[i]).sort((a, b) => a - b);
  const threshold = Math.max(0.5, percentile(baseScores, sensitivity));

  const scored = events.map((e, i) => {
    const rs = reasons[i].slice();
    if (modelPart[i] >= 0.9 && !rs.length) rs.push({ code: 'unusual_pattern', w: 2, text: 'Unusual combination of behaviour for this user' });
    return {
      i, ts: e.ts, user: e.user, event: e.event, city: e.city, ip: e.ip, device: e.device, amount: e.amount, bytes: e.bytes,
      note: e.note, label: e.label, case: e.case, score: scores[i], model: modelPart[i], rules: rulePart[i], x: feats[i].x, reasons: rs, test: e.ts >= split
    };
  });
  const testRows = scored.filter((r) => r.test);

  const severity = (r) => (r.score >= 0.9 || r.reasons.some((x) => x.w >= 8) ? 'critical' : r.score >= 0.75 ? 'high' : 'medium');
  const alerts = testRows.filter((r) => r.score >= threshold).map((r) => ({ ...r, severity: severity(r) })).sort((a, b) => b.score - a.score);

  // Group alerts for the same user within 2 hours into one incident.
  const incidents = [];
  const byUser = new Map();
  for (const a of [...alerts].sort((a, b) => a.ts - b.ts)) {
    const open = byUser.get(a.user);
    if (open && a.ts - open.end <= 2 * 3600000) { open.alerts.push(a); open.end = a.ts; open.score = Math.max(open.score, a.score); }
    else { const inc = { user: a.user, start: a.ts, end: a.ts, score: a.score, alerts: [a] }; incidents.push(inc); byUser.set(a.user, inc); }
  }
  const rank = { critical: 3, high: 2, medium: 1 };
  for (const inc of incidents) {
    inc.severity = inc.alerts.reduce((s, a) => (rank[a.severity] > rank[s] ? a.severity : s), 'medium');
    const seen = new Set();
    inc.reasons = inc.alerts.flatMap((a) => a.reasons).filter((r) => (seen.has(r.code) ? false : seen.add(r.code))).sort((a, b) => b.w - a.w);
  }
  incidents.sort((a, b) => rank[b.severity] - rank[a.severity] || b.score - a.score);

  // Evaluation when labelled data is provided.
  let evaluation = null;
  if (testRows.some((r) => r.label !== undefined)) {
    const y = testRows.map((r) => (r.label && r.label !== 'normal' ? 1 : 0));
    const s = testRows.map((r) => r.score);
    let tp = 0, fp = 0, fn = 0, tn = 0;
    testRows.forEach((r, i) => { const flagged = r.score >= threshold; if (y[i] && flagged) tp++; else if (y[i]) fn++; else if (flagged) fp++; else tn++; });
    const byType = {};
    testRows.forEach((r, i) => { if (!y[i]) return; const t = r.label; byType[t] = byType[t] || { total: 0, caught: 0 }; byType[t].total++; if (r.score >= threshold) byType[t].caught++; });
    const precision = tp + fp ? tp / (tp + fp) : 0, recall = tp + fn ? tp / (tp + fn) : 0;
    // Attack-level detection: an attack counts as caught if any of its events raised an alert.
    const cases = {};
    testRows.forEach((r) => { if (!r.case) return; const c = (cases[r.case] = cases[r.case] || { type: r.label, caught: false }); if (r.score >= threshold) c.caught = true; });
    const caseList = Object.values(cases);
    // Ablation: the same test set scored by each part alone (each at its own baseline threshold).
    const ablation = {};
    for (const [name, arr] of Object.entries(modes)) {
      const base = trainIdx.map((i) => arr[i]).sort((a, b) => a - b);
      const th = Math.max(name === 'model' ? 0.0001 : 0.5, percentile(base, sensitivity));
      const ts = testRows.map((r) => arr[r.i]);
      let a = 0, b = 0, c = 0;
      const typeRecall = {};
      ts.forEach((v, i) => {
        const f = v >= th;
        if (y[i] && f) a++; else if (y[i]) c++; else if (f) b++;
        if (y[i]) { const t = testRows[i].label; typeRecall[t] = typeRecall[t] || { total: 0, caught: 0 }; typeRecall[t].total++; if (f) typeRecall[t].caught++; }
      });
      const P = a + b ? a / (a + b) : 0, R = a + c ? a / (a + c) : 0;
      ablation[name] = { auc: rocAuc(ts, y), precision: P, recall: R, f1: P + R ? (2 * P * R) / (P + R) : 0, byType: typeRecall };
    }
    evaluation = {
      auc: rocAuc(s, y), roc: rocCurve(s, y), tp, fp, fn, tn, precision, recall, f1: precision + recall ? (2 * precision * recall) / (precision + recall) : 0,
      byType, positives: tp + fn, negatives: fp + tn,
      attacks: { total: caseList.length, caught: caseList.filter((c) => c.caught).length },
      ablation
    };
  }

  // Differentially private summary that is safe to share outside the security team.
  const rand = mulberry32(seed + 1);
  const shareable = {
    epsilon: 1,
    events: laplaceCount(testRows.length, 1, rand),
    alerts: laplaceCount(alerts.length, 1, rand),
    incidents: laplaceCount(incidents.length, 1, rand),
    byReason: Object.fromEntries(Object.entries(alerts.flatMap((a) => a.reasons.map((r) => r.code)).reduce((m, c) => ((m[c] = (m[c] || 0) + 1), m), {})).map(([k, v]) => [k, laplaceCount(v, 1, rand)]))
  };

  return {
    meta: { events: events.length, start: first, end: lastTs, train: train.length, test: testRows.length, users: new Set(events.map((e) => e.user)).size, rejected: rejected.length, trainUntil: split, threshold, sensitivity, trees, features: FEATURES, ms: Date.now() - t0 },
    audit, alerts, incidents, evaluation, shareable,
    scores: testRows.map((r) => ({ score: r.score, label: r.label })),
    baseScores,
    // Optional: every checked event with its score (pseudonymised), for live replays.
    rows: keepRows ? testRows.map((r) => ({ ...r, severity: r.score >= threshold ? severity(r) : null })) : undefined
  };
}

/* ── CSV helpers ─────────────────────────────────────────────────────────── */

/** Parse CSV text (RFC 4180: quoted fields, escaped quotes, CRLF). Returns array of objects. */
export function parseCSV(text) {
  const rows = [];
  let row = [], field = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; }
      else field += c;
    } else if (c === '"') q = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.length > 1 || row[0] !== '') rows.push(row);
      row = [];
    } else field += c;
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  if (!rows.length) return [];
  const head = rows[0].map((h) => h.trim().toLowerCase());
  return rows.slice(1).map((r) => Object.fromEntries(head.map((h, i) => [h, (r[i] ?? '').trim()])));
}

export const CSV_COLUMNS = ['timestamp', 'user', 'event', 'ip', 'device', 'city', 'amount', 'bytes', 'account', 'balance', 'note', 'label', 'case'];

export function toCSV(events) {
  const esc = (v) => { const s = v === undefined || v === null ? '' : String(v); return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };
  const lines = [CSV_COLUMNS.join(',')];
  for (const e of events) lines.push([new Date(e.ts).toISOString(), e.user, e.event, e.ip, e.device, e.city, e.amount, e.bytes, e.account, e.balance, e.note, e.label, e.case].map(esc).join(','));
  return lines.join('\n') + '\n';
}
