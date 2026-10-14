/**
 * Sentinel-Z dashboard. Everything runs in this browser tab:
 * the analysis runs in a Web Worker (main-thread fallback), nothing is uploaded.
 */
import { stackedBars, hbars, rocChart, groupedBars, heatmap, timeline } from './charts.js';
import { SIM_ATTACKS } from '../core/simulator.js';
import { startField } from './bg.js';
import { randomKey, createPseudonymizer, redactText } from '../core/privacy.js';
import { sha256, utf8, toHex } from '../core/sha256.js';
import { ATTACK_TYPES } from '../core/generator.js';

document.documentElement.classList.add('js');
const $ = (s, root = document) => root.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = (n) => Number(n).toLocaleString('en-IN');
const pct = (v, d = 1) => (v * 100).toFixed(d) + '%';
const TZ = 330 * 60000, DAY = 86400000;
const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
const istDate = (ts) => { const d = new Date(ts + TZ); return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]}`; };
const istTime = (ts) => new Date(ts + TZ).toISOString().slice(11, 16);
const icon = (id, cls = 'i') => `<svg class="${cls}" aria-hidden="true"><use href="#i-${id}"/></svg>`;

const SEV = {
  critical: { label: 'Critical', icon: 'crit' },
  high: { label: 'High', icon: 'high' },
  medium: { label: 'Medium', icon: 'med' }
};
const sevBadge = (s) => `<span class="sev ${s}">${icon(SEV[s].icon)}${SEV[s].label}</span>`;
const REASON = {
  impossible_travel: 'Impossible travel', brute_force: 'Repeated failed logins', shared_ip: 'IP shared by many accounts',
  large_amount: 'Unusually large transfer', txn_burst: 'Burst of transfers', large_download: 'Unusually large download',
  new_beneficiary: 'New beneficiary', new_device: 'New device', new_city: 'New city', odd_hour: 'Unusual hour',
  unusual_pattern: 'Unusual pattern (model)', account_drained: 'Account emptied'
};
// MITRE ATT&CK techniques for signals that map cleanly. Fraud-only signals have no technique.
const MITRE = {
  brute_force: ['T1110', 'Brute Force'],
  shared_ip: ['T1110.004', 'Credential Stuffing'],
  impossible_travel: ['T1078', 'Valid Accounts'],
  new_device: ['T1078', 'Valid Accounts'],
  large_download: ['T1213', 'Data from Information Repositories']
};
const mitreTag = (code) => {
  const m = MITRE[code];
  return m ? `<a class="att" href="https://attack.mitre.org/techniques/${m[0].replace('.', '/')}/" target="_blank" rel="noopener noreferrer" title="MITRE ATT&CK ${m[0]}: ${m[1]}">${m[0]}</a>` : '';
};
const STATUS = { new: 'New', investigating: 'Investigating', escalated: 'Escalated', resolved: 'Resolved', false_positive: 'False positive' };
const OPEN = new Set(['new', 'investigating', 'escalated']);
const EVENT = { login: 'Login', login_failed: 'Failed login', transfer: 'Transfer', download: 'Download', password_reset: 'Password reset', add_beneficiary: 'Add beneficiary', logout: 'Logout' };

const state = { r: null, source: '', filter: 'all', status: 'all', q: '', shown: 25, key: '', tab: 'overview', triage: new Map() };
const incKey = (inc) => `${inc.user}-${inc.start}`;
const triageOf = (inc) => state.triage.get(incKey(inc)) || { status: 'new', note: '' };

/* ── Theme ─────────────────────────────────────────────────── */
const root = document.documentElement;
const store = { get(k) { try { return localStorage.getItem(k); } catch { return null; } }, set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } } };
function currentTheme() { return root.dataset.theme || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'); }
function applyTheme(t) {
  if (t) root.dataset.theme = t;
  const dark = currentTheme() === 'dark';
  $('#themeBtn').innerHTML = icon(dark ? 'sun' : 'moon');
  $('#themeBtn').setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
}
applyTheme(store.get('sz-theme'));
$('#themeBtn').addEventListener('click', () => { const t = currentTheme() === 'dark' ? 'light' : 'dark'; store.set('sz-theme', t); applyTheme(t); });

/* ── Network monitor: proof that nothing leaves the device ─── */
const net = { external: [] };
function scanResources(list) {
  for (const e of list) {
    try { if (new URL(e.name, location.href).origin !== location.origin) net.external.push(e.name); } catch { /* ignore */ }
  }
  const n = net.external.length;
  $('#netPillText').textContent = `${n} external call${n === 1 ? '' : 's'}`;
  $('#netPill .dot').style.background = n ? 'var(--critical)' : '';
  const big = $('#proofCount');
  if (big) big.textContent = n;
  for (const id of ['#mNet', '#bZero']) { const m = $(id); if (m) m.textContent = n; }
}
scanResources(performance.getEntriesByType('resource'));
if ('PerformanceObserver' in window) new PerformanceObserver((l) => scanResources(l.getEntries())).observe({ type: 'resource', buffered: false });

/* ── Privacy key ───────────────────────────────────────────── */
function setKey(k) {
  state.key = k;
  $('#keyInput').value = k;
  $('#keyFp').textContent = k.length >= 16 ? toHex(sha256(utf8(k))).slice(0, 8) : 'too short';
}
setKey(randomKey());
$('#keyGen').addEventListener('click', () => setKey(randomKey()));
$('#keyInput').addEventListener('input', (e) => setKey(e.target.value));

/* ── Running the analysis ──────────────────────────────────── */
let worker = null, jobId = 0;
const pending = new Map();
function getWorker() {
  if (worker !== null) return worker;
  try {
    worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
    worker.onmessage = (ev) => { const p = pending.get(ev.data.id); if (p) { pending.delete(ev.data.id); ev.data.error ? p.reject(new Error(ev.data.error)) : p.resolve(ev.data.result); } };
    worker.onerror = (ev) => { ev.preventDefault(); worker = false; for (const [id, p] of pending) { pending.delete(id); p.fallback(); } };
  } catch { worker = false; }
  return worker;
}
async function runOnMainThread(job) { const { runJob } = await import('./job.js'); return runJob(job); }
function execute(job) {
  const w = getWorker();
  if (!w) return runOnMainThread(job);
  return new Promise((resolve, reject) => {
    const id = ++jobId;
    pending.set(id, { resolve, reject, fallback: () => runOnMainThread(job).then(resolve, reject) });
    w.postMessage({ id, job });
  });
}

function status(html, kind = '') {
  const s = $('#status');
  s.className = 'status' + (kind ? ' ' + kind : '');
  s.innerHTML = html;
  s.hidden = !html;
}

const TAB_TITLES = { overview: 'Overview', incidents: 'Incidents', sim: 'Attack simulator', quality: 'Model quality', privacy: 'Privacy', how: 'How it works' };
const inApp = () => document.body.classList.contains('in-app');
function enterApp() {
  document.body.classList.add('in-app');
  $('#results').hidden = false;
  if (location.hash !== '#console') history.pushState({ console: true }, '', '#console');
  $('#appMain').scrollTop = 0;
}
function exitApp(fromHistory = false) {
  if (!inApp()) return;
  document.body.classList.remove('in-app');
  $('#results').hidden = true;
  if (!fromHistory && location.hash === '#console') history.back();
}
window.addEventListener('popstate', () => { if (location.hash !== '#console') exitApp(true); else if (state.r) enterApp(); });
$('#appHome').addEventListener('click', () => exitApp());
$('#appKeys').addEventListener('click', () => $('#keys').showModal());

function boot(on, title = 'Opening console', sub = '') {
  const b = $('#boot');
  b.hidden = !on;
  if (on) { $('#bootTitle').textContent = title; $('#bootSub').textContent = sub; }
}

async function run(job, source) {
  if (state.key.length < 16) {
    exitApp();
    status(`${icon('crit')} The privacy key must be at least 16 characters. Press <b>New</b> to generate one.`, 'error');
    $('#analyse').scrollIntoView({ behavior: 'smooth' }); $('#keyInput').focus(); return;
  }
  const buttons = [...document.querySelectorAll('[data-demo]'), $('#demoBtn'), $('#fileInput')];
  buttons.forEach((b) => (b.disabled = true));
  boot(true, job.demoSeed != null ? 'Opening the console' : `Analysing ${source}`, 'Pseudonymising identities and scoring every event on this device…');
  const days = $('#baseline').value;
  try {
    const r = await execute({ ...job, secret: state.key, sensitivity: Number($('#sensitivity').value), trainDays: days === 'auto' ? null : Number(days) });
    state.r = r; state.source = source; state.filter = 'all'; state.status = 'all'; state.q = ''; state.shown = 25; state.triage = new Map();
    status('');
    render();
    enterApp();
    selectTab(job.demoSeed != null && state.tab === 'how' ? 'overview' : state.tab);
    animateNumbers($('#results'));
    toast(`Analysed ${fmt(r.meta.events)} events in ${fmt(r.meta.ms)} ms. Nothing was uploaded.${r.meta.rejected ? ` ${fmt(r.meta.rejected)} invalid rows skipped.` : ''}`);
  } catch (e) {
    exitApp();
    status(`${icon('crit')} ${esc(e.message)}`, 'error');
    $('#analyse').scrollIntoView({ behavior: 'smooth' });
  } finally {
    boot(false);
    buttons.forEach((b) => (b.disabled = false));
  }
}

const runDemo = () => run({ demoSeed: 7 }, 'Synthetic demo bank');
document.querySelectorAll('[data-demo]').forEach((b) => b.addEventListener('click', runDemo));
$('#demoBtn').addEventListener('click', runDemo);
function readFile(file) {
  if (!file) return;
  if (file.size > 50 * 1024 * 1024) { status(`${icon('crit')} That file is larger than 50 MB. For big logs use the command line: <span class="mono">npx sentinel-z analyze file.csv</span>`, 'error'); return; }
  const fr = new FileReader();
  fr.onload = () => run({ text: String(fr.result), fileName: file.name }, file.name);
  fr.onerror = () => status(`${icon('crit')} Could not read that file.`, 'error');
  fr.readAsText(file);
}
$('#fileInput').addEventListener('change', (e) => { readFile(e.target.files[0]); e.target.value = ''; });
const drop = $('#drop');
['dragenter', 'dragover'].forEach((t) => document.addEventListener(t, (e) => { e.preventDefault(); drop.classList.add('over'); }));
document.addEventListener('dragleave', (e) => { if (!e.relatedTarget) drop.classList.remove('over'); });
document.addEventListener('drop', (e) => { e.preventDefault(); drop.classList.remove('over'); readFile(e.dataTransfer?.files?.[0]); });

/* ── Tabs ──────────────────────────────────────────────────── */
const TABS = ['overview', 'incidents', 'sim', 'quality', 'privacy', 'how'];
function selectTab(name) {
  state.tab = name;
  for (const t of TABS) {
    const on = t === name;
    $('#tab-' + t).setAttribute('aria-selected', on);
    $('#tab-' + t).tabIndex = on ? 0 : -1;
    $('#p-' + t).hidden = !on;
  }
  const crumb = $('#rbSection'); if (crumb) crumb.textContent = TAB_TITLES[name];
  const main = $('#appMain'); if (main) main.scrollTop = 0;
  if (state.r) animateNumbers($('#p-' + name));
}
for (const t of TABS) $('#tab-' + t).addEventListener('click', () => selectTab(t));
$('.tabs').addEventListener('keydown', (e) => {
  const i = TABS.indexOf(state.tab);
  const j = e.key === 'ArrowRight' || e.key === 'ArrowDown' ? (i + 1) % TABS.length : e.key === 'ArrowLeft' || e.key === 'ArrowUp' ? (i + TABS.length - 1) % TABS.length : -1;
  if (j >= 0) e.preventDefault();
  if (j >= 0) { selectTab(TABS[j]); $('#tab-' + TABS[j]).focus(); }
});

/* ── Rendering ─────────────────────────────────────────────── */
function render() {
  const r = state.r;
  $('#incCount').textContent = r.incidents.length;
  renderOverview(r);
  renderIncidents(r);
  renderPrivacy(r);
  renderQuality(r);
  renderHow(r);
  renderSim();
  renderRunBar(r);
}

function incidentHTML(inc) {
  const top = inc.reasons[0];
  const types = new Set(inc.alerts.map((a) => a.event));
  return `<details class="inc" data-k="${inc.user}-${inc.start}">
    <summary class="inc-row">
      ${sevBadge(inc.severity)}
      <span class="inc-main"><strong>${esc(top ? top.text : 'Unusual behaviour')}</strong><small><span class="st st-${triageOf(inc).status}">${STATUS[triageOf(inc).status]}</span> <span class="mono">${esc(inc.user)}</span> · ${inc.alerts.length} event${inc.alerts.length > 1 ? 's' : ''} · ${inc.reasons.length} signal${inc.reasons.length > 1 ? 's' : ''} · ${[...types].map((t) => EVENT[t] || t).join(', ')}</small></span>
      <span class="when muted num">${istDate(inc.start)}, ${istTime(inc.start)}</span>
      <span class="risk"><span>Risk <b class="num">${inc.score.toFixed(2)}</b></span><span class="bar"><i style="width:${Math.round(inc.score * 100)}%"></i></span></span>
      ${icon('chev', 'i chev')}
    </summary>
    <div class="inc-detail"></div>
  </details>`;
}

function incidentDetail(inc) {
  const labelled = inc.alerts.some((a) => a.label !== undefined);
  const rows = inc.alerts.map((a) => {
    const size = a.amount !== undefined && !Number.isNaN(a.amount) ? '₹' + fmt(Math.round(a.amount)) : a.bytes !== undefined && !Number.isNaN(a.bytes) ? (a.bytes / 1048576).toFixed(1) + ' MB' : '—';
    const lab = labelled ? `<td>${a.label === 'normal' ? '<span class="muted">Normal</span>' : esc(ATTACK_TYPES[a.label] || a.label)}</td>` : '';
    return `<tr><td class="num">${istDate(a.ts)}, ${istTime(a.ts)}</td><td>${esc(EVENT[a.event] || a.event)}</td><td>${esc(a.city || '—')}</td><td class="r">${size}</td><td class="r">${a.score.toFixed(2)}</td>
      <td><span class="split" title="Model ${a.model.toFixed(2)} · Rules ${a.rules.toFixed(2)}"><i style="flex:${Math.max(0.05, a.model)}"></i><i style="flex:${Math.max(0.05, a.rules)}"></i></span></td>
      <td>${esc(a.reasons[0]?.text || '')}</td>${lab}</tr>`;
  }).join('');
  const tri = triageOf(inc);
  return `<div class="triage" role="group" aria-label="Triage">
      <div class="seg">${Object.entries(STATUS).map(([k, v]) => `<button type="button" data-st="${k}" aria-pressed="${tri.status === k}">${v}</button>`).join('')}</div>
      <input class="note" type="text" maxlength="240" placeholder="Analyst note (stays on this device)" value="${esc(tri.note)}" aria-label="Analyst note">
      <button class="btn secondary sm copy" type="button">${icon('copy')}Copy summary</button>
    </div>
    <div class="reasons">${inc.reasons.map((r) => `<span class="reason">${esc(r.text)}${mitreTag(r.code)}</span>`).join('')}</div>
    <div class="tl-wrap"><div class="tl-h"><strong>Customer activity in the monitoring window</strong><span class="muted">Every event for <span class="mono">${esc(inc.user)}</span>, by risk</span></div><div class="tl"></div></div>
    <div class="table-wrap"><table>
      <thead><tr><th>Time (IST)</th><th>Event</th><th>City</th><th class="r">Amount / size</th><th class="r">Risk</th><th title="Share of the risk from the model (blue) and the rules (orange)">Model · Rules</th><th>Main signal</th>${labelled ? '<th>Ground truth</th>' : ''}</tr></thead>
      <tbody>${rows}</tbody></table></div>
    <p class="muted" style="font-size:12.5px">Identifiers are pseudonyms. Only someone holding the privacy key can re-identify <span class="mono">${esc(inc.user)}</span>, through the bank's own customer records.</p>`;
}

function wireIncidents(container, list) {
  container.querySelectorAll('details.inc').forEach((d, i) => {
    d.addEventListener('toggle', () => {
      const body = $('.inc-detail', d);
      if (!d.open || body.innerHTML) return;
      const inc = list[i];
      body.innerHTML = incidentDetail(inc);
      drawTimeline($('.tl', body), inc);
      body.querySelectorAll('.seg button').forEach((b) => b.addEventListener('click', () => {
        setTriage(inc, { status: b.dataset.st });
        body.querySelectorAll('.seg button').forEach((x) => x.setAttribute('aria-pressed', x === b));
        const chip = $('.st', d);
        chip.className = `st st-${b.dataset.st}`; chip.textContent = STATUS[b.dataset.st];
      }));
      $('.note', body).addEventListener('input', (e) => setTriage(inc, { note: e.target.value }));
      $('.copy', body).addEventListener('click', async (e) => {
        const t = triageOf(inc);
        const text = [`Sentinel-Z incident · ${SEV[inc.severity].label} · risk ${inc.score.toFixed(2)}`, `Customer (pseudonym): ${inc.user}`, `When (IST): ${istDate(inc.start)} ${istTime(inc.start)} – ${istTime(inc.end)}`, `Status: ${STATUS[t.status]}${t.note ? ` · Note: ${t.note}` : ''}`, 'Signals:', ...inc.reasons.map((r) => `- ${r.text}${MITRE[r.code] ? ` [ATT&CK ${MITRE[r.code][0]}]` : ''}`)].join('\n');
        try { await navigator.clipboard.writeText(text); toast('Incident summary copied'); } catch { toast('Copy is not available in this browser'); }
      });
    });
  });
}

function setTriage(inc, patch) {
  state.triage.set(incKey(inc), { ...triageOf(inc), ...patch });
  updateTriageCounts();
}
function updateTriageCounts() {
  const r = state.r; if (!r) return;
  const open = r.incidents.filter((i) => OPEN.has(triageOf(i).status)).length;
  const n = $('#kOpen'); if (n) n.textContent = `${open} open · ${r.incidents.length - open} closed`;
  const pbar = $('#triageBar'); if (pbar) pbar.style.width = `${((r.incidents.length - open) / Math.max(1, r.incidents.length)) * 100}%`;
  const pt = $('#triageTxt'); if (pt) pt.textContent = `${r.incidents.length - open} of ${r.incidents.length} triaged`;
}

function drawTimeline(host, inc) {
  const r = state.r;
  const pts = r.rows.filter((x) => x.user === inc.user).map((x) => ({ ts: x.ts, score: x.score, severity: x.severity, title: `${istDate(x.ts)}, ${istTime(x.ts)} · ${EVENT[x.event] || x.event}${x.city ? ' · ' + x.city : ''}`, reason: x.reasons[0]?.text }));
  timeline(host, pts, { start: r.meta.trainUntil, end: r.meta.end, threshold: r.meta.threshold, fmtTime: istDate });
}

let toastTimer;
function toast(msg) {
  let t = $('#toast');
  if (!t) { t = document.createElement('div'); t.id = 'toast'; t.className = 'toast'; t.setAttribute('role', 'status'); document.body.appendChild(t); }
  t.textContent = msg; t.classList.add('show');
  clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('show'), 2200);
}

function renderOverview(r) {
  const p = $('#p-overview');
  const crit = r.incidents.filter((i) => i.severity === 'critical').length;
  const high = r.incidents.filter((i) => i.severity === 'high').length;
  const users = new Set(r.incidents.map((i) => i.user)).size;
  const e = r.evaluation;
  const last = e
    ? `<div class="kpi good"><span>Attacks caught</span><strong>${e.attacks.caught}/${e.attacks.total}</strong><small>labelled demo attacks, ROC-AUC ${e.auc.toFixed(3)}</small></div>`
    : `<div class="kpi"><span>Analysis time</span><strong>${fmt(r.meta.ms)} ms</strong><small>on this device</small></div>`;
  p.innerHTML = `
    <div class="kpis">
      <div class="kpi"><span>Events checked</span><strong>${fmt(r.meta.test)}</strong><small>after a baseline of ${fmt(r.meta.train)} events</small></div>
      <div class="kpi"><span>Incidents</span><strong>${fmt(r.incidents.length)}</strong><small id="kOpen">from ${fmt(r.alerts.length)} alerts</small></div>
      <div class="kpi"><span>Critical · High</span><strong>${crit} · ${high}</strong><small>${users} of ${r.meta.users} customers affected</small></div>
      ${last}
    </div>
    <div class="grid-2">
      <section class="panel"><div class="panel-h"><h2>Incidents per day</h2><p>Monitoring period, IST</p></div><div id="dayChart"></div></section>
      <section class="panel"><div class="panel-h"><h2>Why alerts fired</h2><p>Alerts per signal</p></div><div id="reasonBars"></div></section>
    </div>
    <div class="grid-2">
      <section class="panel"><div class="panel-h"><h2>When alerts happen</h2><p>Alerts by day and hour, IST</p></div><div id="heat"></div></section>
      <section class="panel"><div class="panel-h"><h2>MITRE ATT&CK techniques</h2><p>Alerts per mapped technique</p></div><div id="attack"></div>
        <div class="tri-prog"><div class="tri-h"><strong>Triage progress</strong><span id="triageTxt" class="muted"></span></div><div class="track"><i id="triageBar"></i></div></div>
      </section>
    </div>
    <section class="panel"><div class="panel-h"><h2>Highest-risk incidents</h2><button class="btn ghost" id="seeAll" type="button">See all ${r.incidents.length} ${icon('chev')}</button></div><div id="topInc"></div></section>`;

  const first = Math.floor((r.meta.trainUntil + TZ) / DAY), lastDay = Math.floor((r.meta.end + TZ) / DAY);
  const days = [];
  for (let d = first; d <= lastDay; d++) days.push({ label: istDate(d * DAY - TZ), values: {} });
  for (const inc of r.incidents) { const k = Math.floor((inc.start + TZ) / DAY) - first; if (days[k]) days[k].values[inc.severity] = (days[k].values[inc.severity] || 0) + 1; }
  stackedBars($('#dayChart'), days, [
    { key: 'critical', name: 'Critical', color: '--critical' },
    { key: 'high', name: 'High', color: '--high' },
    { key: 'medium', name: 'Medium', color: '--medium' }
  ], { yLabel: 'Incidents per day by severity' });

  const counts = {};
  for (const a of r.alerts) for (const x of a.reasons) counts[x.code] = (counts[x.code] || 0) + 1;
  hbars($('#reasonBars'), Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 8).map(([k, v]) => ({ label: REASON[k] || k, value: v })));

  const hours = days.map((d) => ({ label: d.label, values: Array(24).fill(0) }));
  for (const a of r.alerts) { const k = Math.floor((a.ts + TZ) / DAY) - first; const h = new Date(a.ts + TZ).getUTCHours(); if (hours[k]) hours[k].values[h]++; }
  heatmap($('#heat'), hours);
  const tech = {};
  for (const a of r.alerts) { const seen = new Set(); for (const x of a.reasons) { const m = MITRE[x.code]; if (m && !seen.has(m[0])) { seen.add(m[0]); tech[m[0]] = tech[m[0]] || { name: m[1], n: 0 }; tech[m[0]].n++; } } }
  const fraud = r.alerts.filter((a) => a.reasons.some((x) => ['large_amount', 'txn_burst', 'new_beneficiary', 'account_drained'].includes(x.code))).length;
  hbars($('#attack'), [...Object.entries(tech).sort((a, b) => b[1].n - a[1].n).map(([id, v]) => ({ label: `${id} · ${v.name}`, value: v.n })), { label: 'Payment-fraud signals (no ATT&CK ID)', value: fraud }], { color: '--s3' });
  updateTriageCounts();

  const top = r.incidents.slice(0, 5);
  $('#topInc').innerHTML = top.length ? top.map(incidentHTML).join('') : '<p class="empty">No incidents. Everything matched normal behaviour.</p>';
  wireIncidents($('#topInc'), top);
  $('#seeAll').addEventListener('click', () => { selectTab('incidents'); $('#tab-incidents').focus(); });
}

function renderIncidents(r) {
  const p = $('#p-incidents');
  const n = (s) => r.incidents.filter((i) => i.severity === s).length;
  p.innerHTML = `<section class="panel">
    <div class="toolbar">
      <div class="sev-chips" role="group" aria-label="Filter by severity">
        ${['all', 'critical', 'high', 'medium'].map((s) => `<button class="chip-btn" type="button" data-f="${s}" aria-pressed="${state.filter === s}">${s === 'all' ? `All ${r.incidents.length}` : `${SEV[s].label} ${n(s)}`}</button>`).join('')}
      </div>
      <select class="status-filter" id="stFilter" aria-label="Filter by triage status">
        <option value="all">All statuses</option><option value="open">Open</option>${Object.entries(STATUS).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}
      </select>
      <input class="search" id="incSearch" type="search" placeholder="Signal, pseudonym or real customer ID" aria-label="Search incidents" title="A real customer ID or IP is pseudonymised locally with your key, then matched. It is never stored." value="${esc(state.q)}">
    </div>
    <p class="lookup" id="lookupHint" hidden></p>
    <div id="incList"></div>
  </section>`;
  p.querySelectorAll('.chip-btn').forEach((b) => b.addEventListener('click', () => {
    state.filter = b.dataset.f; state.shown = 25;
    p.querySelectorAll('.chip-btn').forEach((x) => x.setAttribute('aria-pressed', x === b));
    drawList();
  }));
  $('#stFilter').value = state.status;
  $('#stFilter').addEventListener('change', (e) => { state.status = e.target.value; state.shown = 25; drawList(); });
  $('#incSearch').addEventListener('input', (e) => { state.q = e.target.value.trim().toLowerCase(); state.shown = 25; drawList(); });
  function drawList() {
    let tokU = '', tokI = '';
    const raw = $('#incSearch').value.trim();
    if (raw.length > 4 && /[@.]/.test(raw) && !/^(usr|ip|dev|acc)_/.test(raw)) { try { const pz = createPseudonymizer(state.key); tokU = pz('user', raw); tokI = pz('ip', raw); } catch { /* key too short */ } }
    const stOk = (i) => state.status === 'all' || (state.status === 'open' ? OPEN.has(triageOf(i).status) : triageOf(i).status === state.status);
    const list = r.incidents.filter((i) => (state.filter === 'all' || i.severity === state.filter) && stOk(i) &&
      (!state.q || i.user === tokU || i.alerts.some((a) => a.ip === tokI) || i.user.toLowerCase().includes(state.q) || i.reasons.some((x) => x.text.toLowerCase().includes(state.q) || (REASON[x.code] || '').toLowerCase().includes(state.q) || (MITRE[x.code]?.[0] || '').toLowerCase() === state.q)));
    const hint = $('#lookupHint');
    if (hint) hint.hidden = !tokU;
    if (tokU) hint.innerHTML = `${icon('key')} Looked up <b>${esc(raw)}</b> as <span class="mono">${tokU}</span> using your key. The real ID is not stored.`;
    const shown = list.slice(0, state.shown);
    const box = $('#incList');
    box.innerHTML = shown.length ? shown.map(incidentHTML).join('') + (list.length > shown.length ? `<div class="empty"><button class="btn secondary sm" id="more" type="button">Show ${Math.min(25, list.length - shown.length)} more of ${list.length - shown.length}</button></div>` : '') : '<p class="empty">No incidents match.</p>';
    wireIncidents(box, shown);
    const more = $('#more', box);
    if (more) more.addEventListener('click', () => { state.shown += 25; drawList(); });
  }
  drawList();
}

function download(name, obj) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' }));
  const a = Object.assign(document.createElement('a'), { href: url, download: name });
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function renderPrivacy(r) {
  const p = $('#p-privacy');
  const t = r.audit.tokenized, red = r.audit.redacted;
  const exact = { events: r.meta.test, alerts: r.alerts.length, incidents: r.incidents.length };
  const reasonExact = {};
  for (const a of r.alerts) for (const x of a.reasons) reasonExact[x.code] = (reasonExact[x.code] || 0) + 1;
  p.innerHTML = `
    <div class="proof"><div class="big" id="proofCount">${net.external.length}</div><div><strong>Requests to other servers since this page opened</strong><span>Counted live by the browser's Resource Timing API. The site is also served with a Content-Security-Policy (<span class="mono">connect-src 'self'</span>) that blocks the page from sending data to any other server.</span></div></div>
    <div class="grid-2">
      <section class="panel"><div class="panel-h"><h2>What was protected</h2><p>Counts only, no values are kept</p></div>
        <div class="stat-list">
          <div><span>Rows processed</span><b>${fmt(r.audit.rows)}</b></div>
          <div><span>Customer IDs → <span class="mono">usr_</span> pseudonyms</span><b>${fmt(t.user || 0)}</b></div>
          <div><span>IP addresses → <span class="mono">ip_</span> pseudonyms</span><b>${fmt(t.ip || 0)}</b></div>
          <div><span>Devices → <span class="mono">dev_</span> pseudonyms</span><b>${fmt(t.device || 0)}</b></div>
          <div><span>Account numbers → <span class="mono">acc_</span> pseudonyms</span><b>${fmt(t.account || 0)}</b></div>
          ${Object.entries(red).map(([k, v]) => `<div><span>${esc({ email: 'Emails', phone: 'Phone numbers', card: 'Card numbers', aadhaar: 'Aadhaar numbers', pan: 'PAN numbers', ip: 'IPs in text' }[k] || k)} masked in notes</span><b>${fmt(v)}</b></div>`).join('') || '<div><span>Personal data found in notes</span><b>0</b></div>'}
        </div>
      </section>
      <section class="panel"><div class="panel-h"><h2>Try the privacy layer</h2><p>Uses your current key</p></div>
        <div class="example">
          <label for="tryId">Any identifier</label>
          <input id="tryId" class="search" style="width:100%;margin:0" value="priya.sharma@bank.example">
          <code id="tryTok"></code>
          <label for="tryNote" style="margin-top:8px">Free-text note</label>
          <input id="tryNote" class="search" style="width:100%;margin:0" value="Customer called from +91 98765 43210 about card 4111 1111 1111 1111">
          <code id="tryRed"></code>
        </div>
      </section>
    </div>
    <section class="panel"><div class="panel-h"><h2>Shareable summary</h2><p>Laplace noise, ε = 1. Safe to send to auditors or other teams.</p></div>
      <div class="table-wrap"><table>
        <thead><tr><th>Metric</th><th class="r">Exact (stays inside)</th><th class="r">Shared value</th></tr></thead>
        <tbody>
          <tr><td>Events checked</td><td class="r">${fmt(exact.events)}</td><td class="r">${fmt(r.shareable.events)}</td></tr>
          <tr><td>Alerts</td><td class="r">${fmt(exact.alerts)}</td><td class="r">${fmt(r.shareable.alerts)}</td></tr>
          <tr><td>Incidents</td><td class="r">${fmt(exact.incidents)}</td><td class="r">${fmt(r.shareable.incidents)}</td></tr>
          ${Object.entries(r.shareable.byReason).sort((a, b) => (reasonExact[b[0]] || 0) - (reasonExact[a[0]] || 0)).map(([k, v]) => `<tr><td>Alerts with “${esc(REASON[k] || k)}”</td><td class="r">${fmt(reasonExact[k] || 0)}</td><td class="r">${fmt(v)}</td></tr>`).join('')}
        </tbody></table></div>
      <div class="actions" style="margin-top:14px">
        <button class="btn primary sm" id="dlReport" type="button">${icon('download')}Pseudonymised report (JSON)</button>
        <button class="btn secondary sm" id="dlShare" type="button">${icon('download')}Shareable summary (JSON)</button>
      </div>
    </section>`;
  const pz = () => { try { return createPseudonymizer(state.key); } catch { return null; } };
  const upd = () => {
    const f = pz();
    $('#tryTok').textContent = f ? `→ ${f('user', $('#tryId').value) || '(empty)'}` : '→ key too short';
    $('#tryRed').textContent = '→ ' + redactText($('#tryNote').value).text;
  };
  $('#tryId').addEventListener('input', upd); $('#tryNote').addEventListener('input', upd); $('#keyInput').addEventListener('input', upd);
  upd();
  $('#dlReport').addEventListener('click', exportReport);
  $('#dlShare').addEventListener('click', () => download('sentinel-z-shareable-summary.json', { generated: new Date().toISOString(), mechanism: 'Laplace, sensitivity 1', ...r.shareable }));
}

function renderQuality(r) {
  const p = $('#p-quality');
  const e = r.evaluation;
  if (!e) {
    p.innerHTML = `<section class="panel"><p class="empty">Model quality needs labelled data. Add a <span class="mono">label</span> column (<span class="mono">normal</span> or the attack name) to your file, or run the demo scenario.</p></section>`;
    return;
  }
  const ab = e.ablation;
  p.innerHTML = `
    <p class="callout">Measured on the events after the baseline window, against the labels in the data. The demo bank is synthetic, so these numbers show the method works as designed. They are not a claim about live traffic. The insider-misuse attack has no dedicated rule on purpose, to test what the unsupervised model finds on its own.</p>
    <div class="kpis">
      <div class="kpi"><span>ROC-AUC</span><strong>${e.auc.toFixed(3)}</strong><small>1.0 is perfect ranking</small></div>
      <div class="kpi"><span>Precision</span><strong>${pct(e.precision)}</strong><small>${e.tp} of ${e.tp + e.fp} alerts were attacks</small></div>
      <div class="kpi"><span>Recall</span><strong>${pct(e.recall)}</strong><small>${e.tp} of ${e.positives} attack events flagged</small></div>
      <div class="kpi good"><span>Attacks caught</span><strong>${e.attacks.caught}/${e.attacks.total}</strong><small>at least one alert per attack</small></div>
    </div>
    <section class="panel whatif">
      <div class="panel-h"><h2>What-if: move the alert threshold</h2><p>Preview only. To apply, change “Alert sensitivity” and run again.</p></div>
      <div class="wi-row">
        <div class="wi-ctl">
          <label for="wiRange">Threshold <b id="wiVal" class="mono"></b></label>
          <input type="range" id="wiRange" min="0.30" max="0.99" step="0.005">
          <div class="wi-scale muted"><span>More alerts</span><button class="btn ghost sm" id="wiReset" type="button">Reset to ${r.meta.threshold.toFixed(3)}</button><span>Fewer alerts</span></div>
        </div>
        <div class="wi-out">
          <div><span>Alerts</span><b id="wiAlerts"></b></div>
          <div><span>Precision</span><b id="wiP"></b></div>
          <div><span>Recall</span><b id="wiR"></b></div>
          <div><span>False alarms</span><b id="wiFp"></b></div>
          <div><span>Missed attack events</span><b id="wiFn"></b></div>
        </div>
      </div>
    </section>
    <div class="grid-2">
      <section class="panel"><div class="panel-h"><h2>Recall by attack type</h2><p>Each part alone vs. the hybrid</p></div><div id="typeChart"></div></section>
      <section class="panel"><div class="panel-h"><h2>ROC curve</h2><p>Hybrid score · dot = current threshold</p></div><div id="rocChart" style="max-width:340px;margin:0 auto"></div></section>
    </div>
    <div class="grid-2">
      <section class="panel"><div class="panel-h"><h2>Model vs. rules vs. hybrid</h2><p>Same events, each at its own threshold</p></div>
        <div class="table-wrap"><table><thead><tr><th>Scorer</th><th class="r">ROC-AUC</th><th class="r">Precision</th><th class="r">Recall</th><th class="r">F1</th></tr></thead><tbody>
          ${[['Isolation Forest only', ab.model], ['Rules only', ab.rules], ['Hybrid (used)', ab.hybrid]].map(([n, v]) => `<tr><td>${n}</td><td class="r">${v.auc.toFixed(3)}</td><td class="r">${pct(v.precision)}</td><td class="r">${pct(v.recall)}</td><td class="r">${v.f1.toFixed(3)}</td></tr>`).join('')}
        </tbody></table></div>
      </section>
      <section class="panel"><div class="panel-h"><h2>Confusion matrix</h2><p>Threshold ${r.meta.threshold.toFixed(3)}</p></div>
        <div class="cm">
          <div class="h"></div><div class="h">Flagged</div><div class="h">Not flagged</div>
          <div class="h">Attack</div><div><b>${fmt(e.tp)}</b>caught</div><div><b>${fmt(e.fn)}</b>missed</div>
          <div class="h">Normal</div><div><b>${fmt(e.fp)}</b>false alarms</div><div><b>${fmt(e.tn)}</b>correctly quiet</div>
        </div>
        <p class="muted" style="font-size:13px;margin-top:12px">False-alarm rate ${pct(e.fp / Math.max(1, e.negatives), 2)} of normal events · F1 ${e.f1.toFixed(3)}</p>
      </section>
    </div>`;
  const types = Object.keys(ab.hybrid.byType);
  groupedBars($('#typeChart'), types.map((t) => ({
    label: ATTACK_TYPES[t] || t,
    values: Object.fromEntries(['model', 'rules', 'hybrid'].map((k) => [k, ab[k].byType[t] ? ab[k].byType[t].caught / ab[k].byType[t].total : 0])),
    detail: Object.fromEntries(['model', 'rules', 'hybrid'].map((k) => [k, ab[k].byType[t] ? `${ab[k].byType[t].caught}/${ab[k].byType[t].total}` : '0/0']))
  })), [
    { key: 'model', name: 'Isolation Forest only', color: '--s1' },
    { key: 'rules', name: 'Rules only', color: '--s2' },
    { key: 'hybrid', name: 'Hybrid', color: '--s3' }
  ]);
  rocChart($('#rocChart'), e.roc, e.auc, { marker: [e.fp / Math.max(1, e.negatives), e.recall] });
  const ys = r.scores.map((x) => (x.label && x.label !== 'normal' ? 1 : 0));
  const range = $('#wiRange');
  let rocTimer;
  const upd = () => {
    const th = Number(range.value);
    let tp = 0, fp = 0, fn = 0, tn = 0;
    r.scores.forEach((x, i) => { const f = x.score >= th; if (ys[i] && f) tp++; else if (ys[i]) fn++; else if (f) fp++; else tn++; });
    const P = tp + fp ? tp / (tp + fp) : 0, R = tp + fn ? tp / (tp + fn) : 0;
    $('#wiVal').textContent = th.toFixed(3);
    $('#wiAlerts').textContent = fmt(tp + fp); $('#wiP').textContent = pct(P); $('#wiR').textContent = pct(R);
    $('#wiFp').textContent = fmt(fp); $('#wiFn').textContent = fmt(fn);
    range.style.setProperty('--fill', `${((th - 0.3) / 0.69) * 100}%`);
    clearTimeout(rocTimer);
    rocTimer = setTimeout(() => rocChart($('#rocChart'), e.roc, e.auc, { marker: [fp / Math.max(1, fp + tn), R] }), 60);
  };
  range.value = r.meta.threshold.toFixed(3);
  range.addEventListener('input', upd);
  $('#wiReset').addEventListener('click', () => { range.value = r.meta.threshold.toFixed(3); upd(); });
  upd();
}

function renderHow(r) {
  const p = $('#p-how');
  const F = [
    ['hour_dev', 'Hours away from the customer\'s usual time of activity'],
    ['amount_z', 'How many standard deviations a transfer is above their normal'],
    ['new_device', 'Device never seen for this customer in the baseline'],
    ['new_city', 'City never seen for this customer in the baseline'],
    ['travel_speed', 'Speed needed to get from the previous city (km/h)'],
    ['fails_10m', 'Failed logins in the last 10 minutes'],
    ['ip_users_1h', 'Different customers seen on the same IP in the last hour'],
    ['txn_10m', 'Transfers in the last 10 minutes'],
    ['new_beneficiary', 'Payment to an account never paid before'],
    ['bytes_z', 'Download size compared with their normal']
  ];
  p.innerHTML = `
    <section class="panel"><div class="panel-h"><h2>Pipeline</h2><p>${fmt(r.meta.ms)} ms for ${fmt(r.meta.events)} events in this run</p></div>
      <div class="flow">
        <div class="step"><b>01</b><strong>Protect</strong><span>Identifiers become HMAC-SHA256 pseudonyms. PII in notes is masked. Raw values are dropped.</span></div>
        <div class="step"><b>02</b><strong>Learn normal</strong><span>Per-customer baseline from the first window: hours, amounts, devices, cities, payees.</span></div>
        <div class="step"><b>03</b><strong>Score</strong><span>An Isolation Forest (${r.meta.trees} trees) rates how unusual each event is. Rules add known attack evidence.</span></div>
        <div class="step"><b>04</b><strong>Explain</strong><span>Every alert carries plain-English reasons. Alerts are grouped into incidents per customer.</span></div>
        <div class="step"><b>05</b><strong>Share safely</strong><span>Pseudonymised report for the security team; noisy counts (ε = 1) for everyone else.</span></div>
      </div>
    </section>
    <div class="grid-2">
      <section class="panel"><div class="panel-h"><h2>Behaviour features</h2><p>Computed per event, from pseudonymised data</p></div>
        <div class="table-wrap"><table><thead><tr><th>Feature</th><th>Meaning</th></tr></thead><tbody>
          ${F.map(([k, v]) => `<tr><td class="mono">${k}</td><td>${v}</td></tr>`).join('')}
        </tbody></table></div>
        <p class="muted" style="font-size:13px;margin-top:12px">Risk = 1 − (1 − 0.85 × model) × (1 − rules). Alert threshold = the ${r.meta.sensitivity}th percentile of baseline risk (now ${r.meta.threshold.toFixed(3)}).</p>
      </section>
      <section class="panel"><div class="panel-h"><h2>Run it on IBM Z / LinuxONE</h2><p>Same engine, no dependencies</p></div>
        <div class="example">
          <span>Command line (Node 18+, any architecture including s390x)</span>
<pre class="cmd">git clone https://github.com/sangralrahul/sentinel-z
cd sentinel-z
npm test
npm run demo
SENTINEL_KEY=your-long-secret node cli/sentinel-z.js analyze logs.csv --out report.json</pre>
          <span>Container (multi-arch image, builds on s390x)</span>
<pre class="cmd">docker build -t sentinel-z .
docker run --rm -p 5173:5173 sentinel-z</pre>
          <span>Optional analyst summary from a local IBM Granite model</span>
<pre class="cmd">ollama pull granite3.3:2b
node cli/sentinel-z.js analyze logs.csv --explain</pre>
        </div>
      </section>
    </div>`;
}


/* ── Motion helpers ────────────────────────────────────────── */
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

/** Count every number inside .kpi strong / .metric b up from zero, keeping its format. */
function animateNumbers(scope) {
  if (reduced || !scope) return;
  scope.querySelectorAll('.kpi strong, .numbers b, .cm b').forEach((node) => {
    const text = node.dataset.final || node.textContent;
    node.dataset.final = text;
    const parts = [];
    text.replace(/\d[\d,]*(?:\.\d+)?/g, (m) => { parts.push(m); return m; });
    if (!parts.length) return;
    const t0 = performance.now(), dur = 1100;
    const step = (now) => {
      const p = Math.min(1, (now - t0) / dur), e = 1 - Math.pow(1 - p, 3);
      let k = 0;
      node.textContent = text.replace(/\d[\d,]*(?:\.\d+)?/g, (m) => {
        const v = Number(m.replace(/,/g, '')) * e, dec = (m.split('.')[1] || '').length;
        k++;
        return m.includes(',') ? Math.round(v).toLocaleString('en-IN') : v.toFixed(dec);
      });
      if (p < 1) requestAnimationFrame(step); else node.textContent = text;
    };
    requestAnimationFrame(step);
  });
}

/** Fade sections in as they scroll into view. */
const io = 'IntersectionObserver' in window ? new IntersectionObserver((entries) => {
  for (const en of entries) if (en.isIntersecting) { en.target.classList.add('in'); io.unobserve(en.target); }
}, { rootMargin: '0px 0px -8% 0px' }) : null;
document.querySelectorAll('.reveal').forEach((n) => (io ? io.observe(n) : n.classList.add('in')));

/** Soft spotlight that follows the pointer on cards. */
document.querySelectorAll('.card-x').forEach((c) => c.addEventListener('pointermove', (e) => {
  const r = c.getBoundingClientRect();
  c.style.setProperty('--mx', `${e.clientX - r.left}px`);
  c.style.setProperty('--my', `${e.clientY - r.top}px`);
}));

/* ── Live replay console ───────────────────────────────────── */
const HEX = '0123456789abcdef';
function scramble(node, to, dur = 650) {
  if (reduced) { node.textContent = to; return; }
  const t0 = performance.now();
  const step = (now) => {
    const p = Math.min(1, (now - t0) / dur), k = Math.floor(p * to.length);
    let out = to.slice(0, k);
    for (let i = k; i < to.length; i++) out += to[i] === '_' ? '_' : HEX[(Math.random() * 16) | 0];
    node.textContent = out;
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
function setStat(id, v) {
  const n = $(id);
  const next = fmt(v);
  if (n.textContent !== next) { n.textContent = next; n.classList.remove('bump'); void n.offsetWidth; n.classList.add('bump'); }
}
function short(s, n = 26) { return s.length > n ? s.slice(0, n - 1) + '…' : s; }

/* Hero background field and word-by-word headline reveal. */
let field = null;
try { const cv = $('#field'); if (cv && cv.getContext) field = startField(cv, { reduced }); } catch { /* canvas unavailable */ }
(function splitHeadline() {
  const h = $('h1.words'); if (!h || reduced) return;
  let i = 0, second = false;
  h.classList.add('js-split');
  const walk = (node) => {
    for (const n of [...node.childNodes]) {
      if (n.nodeName === 'BR') { second = true; continue; }
      if (n.nodeType === 3) {
        const frag = document.createDocumentFragment();
        n.textContent.split(/(\s+)/).forEach((part) => {
          if (!part) return;
          if (/^\s+$/.test(part)) { frag.appendChild(document.createTextNode(part)); return; }
          const sp = document.createElement('span'); sp.className = second ? 'w w2' : 'w'; sp.textContent = part; sp.style.animationDelay = `${80 + i++ * 70}ms`; frag.appendChild(sp);
        });
        n.replaceWith(frag);
      }
    }
  };
  walk(h);
})();

/* Hero product shot: a live replay of the synthetic bank inside a console mock. */
function startConsole(replay) {
  const box = $('#cStream'), detail = $('#pDetail');
  box.innerHTML = '';
  let i = 0, visible = true;
  const history = [];
  const showAlert = (e) => {
    field?.pulse(e.severity);
    const sev = e.severity === 'critical' ? 'crit' : 'high';
    history.unshift(e); history.length = Math.min(history.length, 4);
    detail.innerHTML = `<div class="d-card">
        <span class="d-k">Latest alert</span>
        <span class="d-sev ${sev}">${icon(e.severity === 'critical' ? 'crit' : 'high')}${SEV[e.severity].label}</span>
        <h4>${esc(e.reason || 'Unusual combination of behaviour')}</h4>
        <div class="d-gauge"><i></i><b style="left:${(state.wThreshold || 0.78) * 100}%"></b></div>
        <div class="d-meta">
          <div><span>Customer</span><b>${esc(e.safe.user)}</b></div>
          <div><span>Risk</span><b>${e.score.toFixed(2)}</b></div>
          <div><span>Signals</span><b>${e.reasons.length}</b></div>
          <div><span>ATT&amp;CK</span><b>${[...new Set(e.reasons.map((x) => MITRE[x.code]?.[0]).filter(Boolean))].join(', ') || 'Fraud pattern'}</b></div>
        </div>
      </div>
      <div class="d-hist"><span class="d-k">Recent</span>${history.slice(1).map((h) => `<span><i class="${h.severity === 'critical' ? '' : 'h'}"></i>${esc(h.reason || 'Unusual behaviour')}</span>`).join('')}</div>`;
    requestAnimationFrame(() => { const g = $('.d-gauge i', detail); if (g) g.style.width = `${Math.round(e.score * 100)}%`; });
  };
  const tick = () => {
    if (document.hidden || !visible) return;
    if (i >= replay.length) { i = 0; box.innerHTML = ''; }
    const e = replay[i++];
    const sev = e.severity === 'critical' ? ' crit' : e.severity ? ' high' : '';
    const row = document.createElement('div');
    row.className = 's-row' + sev;
    const size = e.amount != null && !Number.isNaN(e.amount) ? `₹${fmt(Math.round(e.amount))}` : e.bytes != null && !Number.isNaN(e.bytes) ? `${(e.bytes / 1048576).toFixed(1)} MB` : '';
    row.innerHTML = `<span class="t">${istTime(e.ts)}</span><span class="ev">${esc(EVENT[e.event] || e.event)}</span>
      <span class="who raw">${esc(short(e.raw.user, 30))}</span><span class="wh">${esc(e.city || '—')}${size ? ' · ' + size : ''}</span>
      <span class="rk"><span class="bar"><i></i></span><span class="sc">${e.score.toFixed(2)}</span></span>`;
    box.prepend(row);
    while (box.children.length > 14) box.lastElementChild.remove();
    setTimeout(() => {
      const who = $('.who', row);
      who.classList.replace('raw', 'safe');
      scramble(who, e.safe.user);
      $('.bar i', row).style.width = Math.round(Math.max(0.03, e.score) * 100) + '%';
      if (e.severity) showAlert(e);
    }, reduced ? 0 : 600);
    setStat('#cScanned', e.totals.events); setStat('#cTokens', e.totals.tok); setStat('#cPii', e.totals.pii); setStat('#cAlerts', e.totals.alerts);
    $('#pAlertsSide').textContent = e.totals.alerts;
  };
  for (let k = 0; k < 8; k++) tick();
  setInterval(tick, reduced ? 3000 : 1100);
  if ('IntersectionObserver' in window) new IntersectionObserver(([en]) => { visible = en.isIntersecting; }).observe(box);
}

/* Bento: live pseudonymisation with the session key. */
const SAMPLES = [
  { user: 'priya.sharma4@bank.example', ip: '10.65.198.180', note: 'Call +91 98765 43210 re card 4111 1111 1111 1111' },
  { user: 'arjun.mehta22@bank.example', ip: '103.21.4.7', note: 'Aadhaar 2345 6789 0123 verified, mail arjun@corp.example' },
  { user: 'meera.iyer51@bank.example', ip: '45.155.205.99', note: 'Rent to Isha, PAN ABCDE1234F, ph 98111-22334' }
];
function startPseudoDemo() {
  let k = 0;
  const show = () => {
    let pz; try { pz = createPseudonymizer(state.key); } catch { return; }
    const smp = SAMPLES[k++ % SAMPLES.length];
    $('#bRawUser').textContent = smp.user; $('#bRawIp').textContent = smp.ip; $('#bRawNote').textContent = smp.note;
    scramble($('#bSafeUser'), pz('user', smp.user), 800);
    scramble($('#bSafeIp'), pz('ip', smp.ip), 800);
    $('#bSafeNote').textContent = redactText(smp.note).text;
  };
  show();
  setInterval(() => { if (!document.hidden && !inApp()) show(); }, 4200);
}

/* "How it works": step-through walkthrough driven by a real alert from the warm-up run. */
function startSteps(sc) {
  const btns = [...document.querySelectorAll('.step-list button')];
  const hr = (h) => `${String(Math.floor(h)).padStart(2, '0')}:${String(Math.round((h % 1) * 60)).padStart(2, '0')}`;
  const J = (o, cls = 's') => Object.entries(o).filter(([, v]) => v !== undefined && v !== '').map(([k2, v]) => `  <span class="c">"${k2}"</span>: <span class="${cls}">${esc(JSON.stringify(v))}</span>`).join(',\n');
  const views = [
    ['step-1-protect.json', `<span class="c">// raw event, as it arrives (synthetic)</span>\n{\n${J(sc.raw, 'y')}\n}\n\n<span class="c">// what the engine keeps</span>\n{\n${J(sc.safe)}\n}`],
    ['step-2-baseline.json', `<span class="c">// learned from ${sc.profile.events} events in the 14-day baseline</span>\n<span class="c">// customer ${esc(sc.safe.user)}</span>\n{\n  <span class="c">"usual_hour_ist"</span>: <span class="s">"${hr(sc.profile.usualHour)}"</span>,\n  <span class="c">"typical_transfer"</span>: <span class="s">"₹${fmt(sc.profile.typicalTransfer)}"</span>,\n  <span class="c">"known_devices"</span>: <span class="s">${sc.profile.devices}</span>,\n  <span class="c">"known_cities"</span>: <span class="s">${esc(JSON.stringify(sc.profile.cities))}</span>,\n  <span class="c">"known_payees"</span>: <span class="s">${sc.profile.payees}</span>\n}`],
    ['step-3-score.json', `<span class="c">// 10 behaviour features for this event</span>\n{\n${J(sc.features)}\n}\n\n<span class="c">// Isolation Forest (150 trees) + rules</span>\nmodel  = <span class="s">${sc.model.toFixed(3)}</span>\nrules  = <span class="s">${sc.rules.toFixed(3)}</span>\nrisk   = 1 − (1 − 0.85·model)(1 − rules) = <span class="r">${sc.score.toFixed(3)}</span>\nthreshold (99.5th pct of baseline)    = <span class="s">${sc.threshold.toFixed(3)}</span>`],
    ['step-4-explain.json', `{\n  <span class="c">"severity"</span>: <span class="r">"${sc.severity}"</span>,\n  <span class="c">"customer"</span>: <span class="s">"${esc(sc.safe.user)}"</span>,\n  <span class="c">"reasons"</span>: [\n${sc.reasons.map((x) => `    <span class="s">${esc(JSON.stringify(x.text))}</span>${MITRE[x.code] ? `  <span class="c">// ATT&amp;CK ${MITRE[x.code][0]}</span>` : ''}`).join(',\n')}\n  ]\n}`],
    ['step-5-share.json', `<span class="c">// exact counts stay with the security team</span>\n{\n${J(sc.exact)}\n}\n\n<span class="c">// shared outside the team: Laplace noise, ε = 1</span>\n{\n${J(sc.shared, 'g')}\n}`]
  ];
  let cur = 0, timer;
  const go = (n, user) => {
    cur = n;
    btns.forEach((b, j) => b.setAttribute('aria-selected', j === n));
    $('#svTitle').textContent = views[n][0];
    const body = $('#svBody'); body.innerHTML = views[n][1]; body.style.animation = 'none'; void body.offsetWidth; body.style.animation = '';
    const pr = $('#svProg'); pr.classList.remove('run'); void pr.offsetWidth;
    clearTimeout(timer);
    if (!user && !reduced) { pr.classList.add('run'); timer = setTimeout(() => go((cur + 1) % views.length), 7000); }
  };
  btns.forEach((b, j) => b.addEventListener('click', () => go(j, true)));
  go(0);
}

/* Product shot tilts flat as it scrolls into view; nav gets a hairline once scrolled. */
const shot = $('#shot');
function onScroll() {
  $('.nav-bar').classList.toggle('scrolled', scrollY > 8);
  if (!shot || reduced) return;
  const r = shot.getBoundingClientRect();
  const p = Math.min(1, Math.max(0, (innerHeight - r.top) / (innerHeight * 0.9)));
  shot.style.setProperty('--tilt', `${(14 * (1 - p)).toFixed(2)}deg`);
}
addEventListener('scroll', onScroll, { passive: true });
onScroll();
document.querySelectorAll('.tile').forEach((c) => c.addEventListener('pointermove', (e) => {
  const r = c.getBoundingClientRect();
  c.style.setProperty('--mx', `${e.clientX - r.left}px`);
  c.style.setProperty('--my', `${e.clientY - r.top}px`);
}));

/** Warm-up: analyse the demo bank once in the background to drive the product shot, numbers and walkthrough. */
(async () => {
  startPseudoDemo();
  try {
    const r = await execute({ demoSeed: 7, secret: state.key, sensitivity: 99.5, trainDays: 14, stream: true });
    state.wThreshold = r.meta.threshold;
    $('#mAuc').textContent = r.evaluation.auc.toFixed(3);
    $('#mCaught').textContent = `${r.evaluation.attacks.caught}/${r.evaluation.attacks.total}`;
    $('#mMs').textContent = `${fmt(r.meta.ms)} ms`;
    animateNumbers($('.numbers'));
    startConsole(r.replay);
    if (r.showcase) startSteps(r.showcase);
  } catch (e) {
    $('#cState').textContent = 'Replay unavailable: ' + e.message;
  }
  if (location.hash === '#console') runDemo();
})();


/* ── Red-team simulator ────────────────────────────────────── */
const simState = { type: 'impossible_travel', customer: 11, day: 2 };
function renderSim() {
  const p = $('#p-sim');
  p.innerHTML = `
    <section class="panel">
      <div class="panel-h"><h2>Red-team simulator</h2><p>Inject one attack into the synthetic bank and watch the detector respond. Real data is never used here.</p></div>
      <div class="sim-grid" role="radiogroup" aria-label="Attack to simulate">
        ${Object.entries(SIM_ATTACKS).map(([k, v]) => `<button type="button" class="sim-card" role="radio" data-k="${k}" aria-checked="${simState.type === k}"><strong>${v.name}</strong><span>${v.desc}</span></button>`).join('')}
      </div>
      <div class="sim-ctl">
        <div class="field"><label for="simCust">Target customer</label><select id="simCust">${Array.from({ length: 80 }, (_, i) => `<option value="${i}" ${i === simState.customer ? 'selected' : ''}>Synthetic customer ${String(i + 1).padStart(2, '0')}</option>`).join('')}</select></div>
        <div class="field"><label for="simDay">When</label><select id="simDay">${Array.from({ length: 7 }, (_, i) => `<option value="${i}" ${i === simState.day ? 'selected' : ''}>Monitoring day ${i + 1}</option>`).join('')}</select></div>
        <button class="btn primary" id="simRun" type="button">${icon('play')}Launch simulated attack</button>
      </div>
    </section>
    <div id="simOut"></div>`;
  p.querySelectorAll('.sim-card').forEach((b) => b.addEventListener('click', () => {
    simState.type = b.dataset.k;
    p.querySelectorAll('.sim-card').forEach((x) => x.setAttribute('aria-checked', x === b));
  }));
  $('#simCust').addEventListener('change', (e) => (simState.customer = Number(e.target.value)));
  $('#simDay').addEventListener('change', (e) => (simState.day = Number(e.target.value)));
  $('#simRun').addEventListener('click', runSim);
}

async function runSim() {
  const out = $('#simOut'), btn = $('#simRun');
  if (state.key.length < 16) { toast('Set a privacy key of at least 16 characters first'); return; }
  btn.disabled = true;
  out.innerHTML = `<section class="panel sim-run"><span class="spinner"></span><div><strong>Injecting ${esc(SIM_ATTACKS[simState.type].name.toLowerCase())}…</strong><span class="muted">Re-learning baselines and scoring 6,000 events on this device</span></div></section>`;
  try {
    const t0 = performance.now();
    const r = await execute({ demoSeed: 7, secret: state.key, sensitivity: Number($('#sensitivity').value), trainDays: 14, simulate: { ...simState } });
    const ms = Math.round(performance.now() - t0);
    const s = r.sim, caught = s.caught > 0, inc = s.incident;
    const sev = inc ? inc.severity : null;
    const reasons = [...new Map(s.events.flatMap((e) => e.reasons).map((x) => [x.code, x])).values()].sort((a, b) => b.w - a.w);
    out.innerHTML = `
      <section class="panel verdict ${caught ? 'caught' : 'missed'}">
        <div class="v-main">
          <div class="v-ic">${icon(caught ? 'check' : 'crit')}</div>
          <div><span class="eyebrow">${esc(SIM_ATTACKS[s.type].name)} · ${esc(s.target || '')}</span>
            <h2>${caught ? `Detected: ${s.caught} of ${s.total} attack event${s.total > 1 ? 's' : ''} raised alerts` : 'Not detected at this sensitivity'}</h2>
            <p class="muted">${caught ? `Grouped into ${sev ? SEV[sev].label.toLowerCase() : ''} incident${inc ? ` with ${inc.alerts.length} alert${inc.alerts.length > 1 ? 's' : ''}` : ''}. Analysis took ${fmt(ms)} ms on this device.` : `Highest risk was ${s.maxScore.toFixed(2)}, below the threshold of ${s.threshold.toFixed(2)}. Subtle insider activity is the hardest case, and we show it honestly.`}</p>
          </div>
          ${sev ? sevBadge(sev) : ''}
        </div>
        <div class="gauge" aria-label="Peak risk ${s.maxScore.toFixed(2)} against threshold ${s.threshold.toFixed(2)}">
          <div class="g-track"><i style="--to:${(s.maxScore * 100).toFixed(1)}%"></i><b style="left:${(s.threshold * 100).toFixed(1)}%"><span>threshold ${s.threshold.toFixed(2)}</span></b></div>
          <div class="g-lab"><span>0</span><span>Peak risk <b class="mono">${s.maxScore.toFixed(2)}</b></span><span>1</span></div>
        </div>
        ${reasons.length ? `<div class="reasons">${reasons.map((x) => `<span class="reason">${esc(x.text)}${mitreTag(x.code)}</span>`).join('')}</div>` : ''}
        <div class="table-wrap"><table><thead><tr><th>Time (IST)</th><th>Event</th><th>City</th><th class="r">Risk</th><th>Result</th></tr></thead><tbody>
          ${s.events.map((e) => `<tr><td class="num">${istDate(e.ts)}, ${istTime(e.ts)}</td><td>${esc(EVENT[e.event] || e.event)}</td><td>${esc(e.city || '—')}</td><td class="r">${e.score.toFixed(2)}</td><td>${e.severity ? sevBadge(e.severity) : '<span class="muted">Below threshold</span>'}</td></tr>`).join('')}
        </tbody></table></div>
      </section>`;
  } catch (e) {
    out.innerHTML = `<div class="status error">${icon('crit')} ${esc(e.message)}</div>`;
  } finally { btn.disabled = false; }
}

/* ── Run bar, export, print, shortcuts ─────────────────────── */
function exportReport() {
  const r = state.r; if (!r) return;
  download('sentinel-z-report.json', {
    generated: new Date().toISOString(), source: state.source, meta: r.meta, audit: r.audit,
    incidents: r.incidents.map((i) => ({ ...i, triage: triageOf(i), alerts: i.alerts.map(({ x, note, i: _i, test, ...a }) => a) })),
    evaluation: r.evaluation && { ...r.evaluation, roc: undefined }
  });
  toast('Pseudonymised report downloaded');
}
function renderRunBar(r) {
  const fp = $('#keyFp').textContent;
  $('#appSource').innerHTML = `<b>${esc(state.source)}</b><span>${fmt(r.meta.events)} events · ${fmt(r.meta.users)} customers</span><span>key ${esc(fp)} · ${fmt(r.meta.ms)} ms</span>`;
  $('#runBar').innerHTML = `
    <div class="rb-l"><div><span class="crumb muted">${esc(state.source)} <span aria-hidden="true">/</span></span> <strong id="rbSection">${TAB_TITLES[state.tab]}</strong></div></div>
    <div class="rb-r">
      <span class="rb-meta mono muted">threshold ${r.meta.threshold.toFixed(3)}</span>
      <button class="btn secondary sm" id="rbExport" type="button">${icon('download')}<span class="hide-sm">Export</span></button>
      <button class="btn secondary sm" id="rbPrint" type="button">${icon('print')}<span class="hide-sm">Print report</span></button>
    </div>`;
  $('#rbExport').addEventListener('click', exportReport);
  $('#rbPrint').addEventListener('click', printReport);
}
function printReport() {
  $('#printMeta').textContent = `${state.source} · generated ${new Date().toLocaleString('en-IN')} · ${state.r.incidents.length} incidents · identities pseudonymised`;
  window.print();
}
$('#keysClose').addEventListener('click', () => $('#keys').close());
document.addEventListener('keydown', (e) => {
  if (e.target.closest('input, select, textarea') || e.metaKey || e.ctrlKey || e.altKey) return;
  const k = e.key.toLowerCase();
  if (e.key === '?') { e.preventDefault(); const d = $('#keys'); d.open ? d.close() : d.showModal(); return; }
  if (e.key === 'Escape' && inApp() && !$('#keys').open) { exitApp(); return; }
  if (k === 'd') { runDemo(); return; }
  if (!inApp() || !state.r) return;
  const n = Number(e.key);
  if (n >= 1 && n <= TABS.length) { selectTab(TABS[n - 1]); $('#tab-' + TABS[n - 1]).focus(); }
  else if (e.key === '/') { e.preventDefault(); selectTab('incidents'); $('#incSearch').focus(); }
  else if (k === 'e') exportReport();
  else if (k === 'p') printReport();
});
