/**
 * Behavioural features for security events.
 *
 * Each user gets a baseline profile from the training window (usual hours, usual
 * transfer size, known devices, cities and beneficiaries). Every event is then
 * described by how far it departs from that baseline, plus short time-window
 * counters that catch bursts (brute force, credential stuffing, mule transfers).
 *
 * All identifiers here are already pseudonymised tokens; raw values are never needed.
 */
import { distanceKm } from './geo.js';

export const FEATURES = [
  'hour_dev', 'amount_z', 'new_device', 'new_city', 'travel_speed',
  'fails_10m', 'ip_users_1h', 'txn_10m', 'new_beneficiary', 'bytes_z'
];

const MIN = 60 * 1000;
const HOUR = 60 * MIN;

// Hours are read in the bank's local time zone (default IST, UTC+05:30).
let TZ_MIN = 330;
export function setTimezoneOffset(minutes) { TZ_MIN = Number(minutes) || 0; }
const hourOf = (ts) => { const d = new Date(ts + TZ_MIN * 60000); return d.getUTCHours() + d.getUTCMinutes() / 60; };
const circDist = (a, b) => { const d = Math.abs(a - b) % 24; return Math.min(d, 24 - d); };

function circularMean(hours) {
  let s = 0, c = 0;
  for (const h of hours) { const a = (h / 24) * 2 * Math.PI; s += Math.sin(a); c += Math.cos(a); }
  let m = (Math.atan2(s, c) / (2 * Math.PI)) * 24;
  if (m < 0) m += 24;
  return m;
}
function meanStd(xs) {
  if (!xs.length) return { mean: 0, std: 0 };
  const mean = xs.reduce((a, b) => a + b, 0) / xs.length;
  const v = xs.reduce((a, b) => a + (b - mean) ** 2, 0) / xs.length;
  return { mean, std: Math.sqrt(v) };
}

/** Build one baseline profile per user from training events. */
export function buildProfiles(trainEvents) {
  const by = new Map();
  for (const e of trainEvents) {
    if (!by.has(e.user)) by.set(e.user, []);
    by.get(e.user).push(e);
  }
  const profiles = new Map();
  const allAmounts = [], allBytes = [];
  for (const [user, evs] of by) {
    const ok = evs.filter((e) => e.event !== 'login_failed');
    const hours = ok.map((e) => hourOf(e.ts));
    const mu = hours.length ? circularMean(hours) : 12;
    const hourStd = hours.length ? Math.sqrt(hours.reduce((a, h) => a + circDist(h, mu) ** 2, 0) / hours.length) : 4;
    const amounts = evs.filter((e) => e.event === 'transfer').map((e) => Math.log1p(+e.amount || 0));
    const bytes = evs.filter((e) => e.event === 'download').map((e) => Math.log1p(+e.bytes || 0));
    allAmounts.push(...amounts); allBytes.push(...bytes);
    profiles.set(user, {
      hourMean: mu, hourStd,
      amount: meanStd(amounts), amountN: amounts.length,
      bytes: meanStd(bytes), bytesN: bytes.length,
      devices: new Set(ok.map((e) => e.device).filter(Boolean)),
      cities: new Set(ok.map((e) => e.city).filter(Boolean)),
      beneficiaries: new Set(evs.filter((e) => e.event === 'transfer').map((e) => e.account).filter(Boolean))
    });
  }
  const global = { amount: meanStd(allAmounts), bytes: meanStd(allBytes) };
  return { profiles, global };
}

/**
 * Compute a feature vector and a human-readable context for every event.
 * Events must be sorted by time. Returns [{ x: number[], ctx }].
 */
export function computeFeatures(events, { profiles, global }) {
  const failsByUser = new Map(), txnByUser = new Map(), lastByUser = new Map(), ipSeen = new Map();
  const out = [];
  const prune = (arr, t, win) => { while (arr.length && arr[0] < t - win) arr.shift(); };

  for (const e of events) {
    const t = e.ts, p = profiles.get(e.user);
    const ctx = { hour: hourOf(t) };

    // 1. Time of day versus this user's habit.
    const hourMean = p ? p.hourMean : 12, hourStd = p ? Math.max(1.5, p.hourStd) : 6;
    const hourDev = Math.min(6, circDist(ctx.hour, hourMean) / hourStd);
    ctx.usualHour = hourMean;

    // 2. Transfer size versus this user's (or everyone's) usual size.
    let amountZ = 0;
    if (e.event === 'transfer') {
      const st = p && p.amountN >= 3 ? p.amount : global.amount;
      const typical = Math.expm1(st.mean);
      amountZ = Math.max(0, Math.min(8, (Math.log1p(+e.amount || 0) - st.mean) / Math.max(0.35, st.std)));
      ctx.typicalAmount = typical;
    }

    // 3-4. Novel device or city for this user.
    const isLogin = e.event === 'login' || e.event === 'login_failed';
    const newDevice = p && e.device && !p.devices.has(e.device) ? 1 : 0;
    const newCity = p && e.city && !p.cities.has(e.city) ? 1 : 0;

    // 5. Travel speed from the user's previous event (impossible travel).
    let speed = 0;
    const last = lastByUser.get(e.user);
    if (last && e.city && last.city && last.city !== e.city && t - last.ts < 24 * HOUR) {
      const km = distanceKm(last.city, e.city);
      if (km) {
        const hrs = Math.max((t - last.ts) / HOUR, 1 / 60);
        const kmh = km / hrs;
        speed = Math.log10(1 + kmh);
        ctx.travel = { from: last.city, to: e.city, km: Math.round(km), minutes: Math.round((t - last.ts) / MIN), kmh: Math.round(kmh) };
      }
    }

    // 6. Failed logins for this user in the last 10 minutes.
    if (!failsByUser.has(e.user)) failsByUser.set(e.user, []);
    const fails = failsByUser.get(e.user);
    prune(fails, t, 10 * MIN);
    if (e.event === 'login_failed') fails.push(t);
    const fails10 = fails.length;

    // 7. Distinct users seen on the same IP in the last hour (credential stuffing).
    let ipUsers = 0;
    if (e.ip) {
      if (!ipSeen.has(e.ip)) ipSeen.set(e.ip, new Map());
      const m = ipSeen.get(e.ip);
      m.set(e.user, t);
      for (const [u, ts] of m) if (ts < t - HOUR) m.delete(u);
      ipUsers = m.size;
    }

    // 8. Transfers by this user in the last 10 minutes (mule / card testing bursts).
    if (!txnByUser.has(e.user)) txnByUser.set(e.user, []);
    const txns = txnByUser.get(e.user);
    prune(txns, t, 10 * MIN);
    if (e.event === 'transfer') txns.push(t);

    // 9. Transfer to a beneficiary this user has never paid before.
    const newBen = e.event === 'transfer' && p && e.account && !p.beneficiaries.has(e.account) ? 1 : 0;

    // 10. Download size versus usual (data exfiltration).
    let bytesZ = 0;
    if (e.event === 'download') {
      const st = p && p.bytesN >= 3 ? p.bytes : global.bytes;
      bytesZ = Math.max(0, Math.min(8, (Math.log1p(+e.bytes || 0) - st.mean) / Math.max(0.35, st.std)));
      ctx.typicalBytes = Math.expm1(st.mean);
    }

    if (e.event !== 'login_failed') lastByUser.set(e.user, { city: e.city, ts: t });
    ctx.isLogin = isLogin;
    out.push({ x: [hourDev, amountZ, newDevice, newCity, speed, fails10, ipUsers, txns.length, newBen, bytesZ], ctx });
  }
  return out;
}

const inr = (v) => '₹' + Math.round(v).toLocaleString('en-IN');
const hhmm = (h) => `${String(Math.floor(h)).padStart(2, '0')}:${String(Math.round((h % 1) * 60) % 60).padStart(2, '0')}`;
const mb = (b) => (b / 1e6 >= 1 ? (b / 1e6).toFixed(1) + ' MB' : Math.round(b / 1e3) + ' KB');

/**
 * Plain-English reasons for an event, strongest first. Each reason has a code
 * (stable, for filtering) and a weight (for ordering).
 */
export function explain(event, x, ctx) {
  const r = [];
  const [hourDev, amountZ, newDevice, newCity, speed, fails, ipUsers, txns, newBen, bytesZ] = x;
  if (ctx.travel && ctx.travel.kmh >= 900) r.push({ code: 'impossible_travel', w: 10, text: `Impossible travel: ${ctx.travel.from} → ${ctx.travel.to}, ${ctx.travel.km.toLocaleString('en-IN')} km in ${ctx.travel.minutes} min` });
  if (fails >= 4) r.push({ code: 'brute_force', w: 8, text: `${fails} failed logins in 10 minutes` });
  if (ipUsers >= 5) r.push({ code: 'shared_ip', w: 8, text: `Same IP used by ${ipUsers} accounts in 1 hour` });
  if (amountZ >= 3) r.push({ code: 'large_amount', w: 7, text: `Transfer of ${inr(+event.amount)} is ${Math.max(2, Math.round(+event.amount / Math.max(1, ctx.typicalAmount)))}× the usual ${inr(ctx.typicalAmount)}` });
  if (txns >= 4) r.push({ code: 'txn_burst', w: 7, text: `${txns} transfers in 10 minutes` });
  if (bytesZ >= 3) r.push({ code: 'large_download', w: 7, text: `Download of ${mb(+event.bytes)}, ${Math.max(2, Math.round(+event.bytes / Math.max(1, ctx.typicalBytes)))}× the usual size` });
  if (newBen) r.push({ code: 'new_beneficiary', w: 5, text: 'Payment to a new beneficiary' });
  if (newDevice) r.push({ code: 'new_device', w: 5, text: 'New device for this user' });
  if (newCity) r.push({ code: 'new_city', w: 4, text: `First activity from ${event.city}` });
  if (hourDev >= 3) r.push({ code: 'odd_hour', w: 3, text: `Unusual time ${hhmm(ctx.hour)} (usually around ${hhmm(ctx.usualHour)})` });
  return r.sort((a, b) => b.w - a.w);
}
