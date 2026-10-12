/**
 * Synthetic banking security log with labelled attacks.
 *
 * No real customer data is used anywhere in this project. This generator creates a
 * realistic population (habits, devices, home cities, payees) and then injects six
 * attack types into the final days, each event labelled so detection quality can be
 * measured honestly (ROC-AUC, precision, recall).
 *
 * It also injects legitimate surprises (a real trip, a new phone, a one-off big
 * payment) so the evaluation includes realistic false-positive pressure.
 */
import { mulberry32, gauss, pick } from './rng.js';
import { CITIES } from './geo.js';

const DOMESTIC = ['Mumbai', 'Delhi', 'Bengaluru', 'Hyderabad', 'Chennai', 'Kolkata', 'Pune', 'Ahmedabad', 'Jaipur', 'Lucknow', 'Kochi', 'Chandigarh', 'Bhopal', 'Patna', 'Guwahati', 'Indore'];
const FOREIGN = ['Dubai', 'Singapore', 'London', 'Frankfurt', 'New York', 'Lagos', 'Moscow', 'São Paulo'];
const FIRST = ['Aarav', 'Diya', 'Vihaan', 'Ananya', 'Arjun', 'Isha', 'Kabir', 'Meera', 'Rohan', 'Saanvi', 'Aditya', 'Kavya', 'Ishaan', 'Riya', 'Dev', 'Nisha', 'Yash', 'Pooja', 'Kunal', 'Sneha'];
const LAST = ['Sharma', 'Patel', 'Iyer', 'Reddy', 'Das', 'Khan', 'Singh', 'Nair', 'Gupta', 'Mehta', 'Joshi', 'Bose'];
const DEVICES = ['Android', 'iPhone', 'Windows', 'MacBook', 'Linux'];

const MIN = 60000, HOUR = 60 * MIN, DAY = 24 * HOUR;

export const ATTACK_TYPES = {
  account_takeover: 'Account takeover',
  impossible_travel: 'Impossible travel',
  credential_stuffing: 'Credential stuffing',
  brute_force: 'Brute force',
  mule_transfers: 'Mule / rapid transfers',
  data_exfiltration: 'Data exfiltration',
  insider_misuse: 'Insider misuse (no dedicated rule)'
};

export function generateScenario({ users = 80, days = 21, attackDays = 7, seed = 7, start = Date.UTC(2026, 8, 14, 0, 0) } = {}) {
  const rand = mulberry32(seed);
  const ip = () => `10.${Math.floor(rand() * 250)}.${Math.floor(rand() * 250)}.${1 + Math.floor(rand() * 250)}`;
  const pubIp = () => `${[45, 91, 103, 185, 196][Math.floor(rand() * 5)]}.${Math.floor(rand() * 250)}.${Math.floor(rand() * 250)}.${1 + Math.floor(rand() * 250)}`;
  const acct = () => String(Math.floor(1e11 + rand() * 9e11));
  const istToUtc = (dayStart, h) => dayStart + (h - 5.5) * HOUR; // habits are in IST

  const people = [];
  for (let i = 0; i < users; i++) {
    const first = pick(rand, FIRST), last = pick(rand, LAST);
    people.push({
      id: `${first.toLowerCase()}.${last.toLowerCase()}${i}@bank.example`,
      name: `${first} ${last}`,
      city: pick(rand, DOMESTIC),
      devices: [`${pick(rand, DEVICES)}-${Math.floor(rand() * 9000 + 1000)}`].concat(rand() < 0.5 ? [`${pick(rand, DEVICES)}-${Math.floor(rand() * 9000 + 1000)}`] : []),
      ip: ip(),
      hour: 8 + rand() * 13, // usual active hour, 08:00–21:00 IST
      hourSpread: 0.8 + rand() * 1.6,
      amount: Math.exp(7.5 + rand() * 2.2), // typical transfer ₹1.8k–₹16k
      payees: Array.from({ length: 3 + Math.floor(rand() * 4) }, acct),
      activity: 1 + rand() * 2.5,
      downloads: rand() < 0.4
    });
  }

  const events = [];
  let caseNo = 0, caseId = '';
  const push = (e, label = 'normal') => events.push({ ...e, label, ...(label !== 'normal' ? { case: caseId } : {}) });
  const newCase = (type) => { caseId = `${type}-${++caseNo}`; };
  const trainDays = days - attackDays;

  // Normal behaviour every day.
  for (let d = 0; d < days; d++) {
    const dayStart = start + d * DAY;
    for (const u of people) {
      const sessions = Math.max(0, Math.round(u.activity + gauss(rand) * 0.8));
      for (let s = 0; s < sessions; s++) {
        const h = Math.min(23.5, Math.max(6, u.hour + gauss(rand) * u.hourSpread));
        let t = istToUtc(dayStart, h);
        const device = pick(rand, u.devices);
        if (rand() < 0.04) push({ ts: t - 2 * MIN, user: u.id, event: 'login_failed', ip: u.ip, device, city: u.city, note: 'Wrong password' });
        push({ ts: t, user: u.id, event: 'login', ip: u.ip, device, city: u.city });
        if (rand() < 0.55) {
          t += (2 + rand() * 6) * MIN;
          const amount = Math.round(u.amount * Math.exp(gauss(rand) * 0.45));
          push({ ts: t, user: u.id, event: 'transfer', ip: u.ip, device, city: u.city, amount, account: pick(rand, u.payees), note: rand() < 0.2 ? `Rent to ${pick(rand, FIRST)}, ref ${u.id}` : '' });
        }
        if (u.downloads && rand() < 0.3) {
          t += (1 + rand() * 4) * MIN;
          push({ ts: t, user: u.id, event: 'download', ip: u.ip, device, city: u.city, bytes: Math.round(Math.exp(12.5 + gauss(rand) * 0.5)), note: 'Monthly statement' });
        }
      }
    }
  }

  // Attacks and legitimate surprises in the last `attackDays`.
  const victims = [...people].sort(() => rand() - 0.5);
  let vi = 0;
  const nextVictim = () => victims[vi++ % victims.length];
  const attackStart = start + trainDays * DAY;
  const at = (dayOffset, istHour) => istToUtc(attackStart + dayOffset * DAY, istHour);

  for (let k = 0; k < 5; k++) { // account takeover: new device, foreign IP, odd hour, big payment to a new payee
    newCase('ato');
    const u = nextVictim(), t = at(k % attackDays, 2 + rand() * 2.5), dev = `Android-${Math.floor(rand() * 9000 + 1000)}`, aip = pubIp(), city = pick(rand, DOMESTIC.filter((c) => c !== u.city));
    push({ ts: t, user: u.id, event: 'login', ip: aip, device: dev, city }, 'account_takeover');
    push({ ts: t + 4 * MIN, user: u.id, event: 'transfer', ip: aip, device: dev, city, amount: Math.round(u.amount * (12 + rand() * 20)), account: acct(), note: `Urgent payment, call 98${Math.floor(10000000 + rand() * 89999999)}` }, 'account_takeover');
  }
  for (let k = 0; k < 5; k++) { // impossible travel: home login, then abroad minutes later
    newCase('travel');
    const u = nextVictim(), t = at((k + 2) % attackDays, u.hour), dev = pick(rand, u.devices);
    push({ ts: t, user: u.id, event: 'login', ip: u.ip, device: dev, city: u.city });
    push({ ts: t + (20 + rand() * 40) * MIN, user: u.id, event: 'login', ip: pubIp(), device: `Windows-${Math.floor(rand() * 9000 + 1000)}`, city: pick(rand, FOREIGN) }, 'impossible_travel');
  }
  for (let k = 0; k < 2; k++) { // credential stuffing: one IP tries many accounts
    newCase('stuffing');
    const aip = pubIp(), t0 = at(1 + k * 3, 1 + rand() * 3), city = pick(rand, FOREIGN);
    for (let j = 0; j < 14; j++) {
      const u = people[Math.floor(rand() * people.length)];
      const t = t0 + j * (1 + rand() * 3) * MIN;
      push({ ts: t, user: u.id, event: rand() < 0.85 ? 'login_failed' : 'login', ip: aip, device: 'Linux-bot', city }, 'credential_stuffing');
    }
  }
  for (let k = 0; k < 4; k++) { // brute force on one account, then success
    newCase('brute');
    const u = nextVictim(), t0 = at((k + 1) % attackDays, rand() * 24), aip = pubIp(), city = pick(rand, DOMESTIC);
    for (let j = 0; j < 7; j++) push({ ts: t0 + j * 40000, user: u.id, event: 'login_failed', ip: aip, device: 'Windows-0001', city }, 'brute_force');
    push({ ts: t0 + 7 * 40000, user: u.id, event: 'login', ip: aip, device: 'Windows-0001', city }, 'brute_force');
  }
  for (let k = 0; k < 4; k++) { // mule transfers: many quick payments to new payees
    newCase('mule');
    const u = nextVictim(), t0 = at((k + 3) % attackDays, u.hour + 1), dev = pick(rand, u.devices);
    for (let j = 0; j < 6; j++) push({ ts: t0 + j * 90000, user: u.id, event: 'transfer', ip: u.ip, device: dev, city: u.city, amount: Math.round(9000 + rand() * 40000), account: acct() }, 'mule_transfers');
  }
  for (let k = 0; k < 4; k++) { // data exfiltration: huge download at night
    newCase('exfil');
    const u = people.filter((p) => p.downloads)[k] || nextVictim(), t = at((k + 4) % attackDays, 1 + rand() * 3);
    push({ ts: t, user: u.id, event: 'download', ip: pubIp(), device: pick(rand, u.devices), city: u.city, bytes: Math.round(4e8 + rand() * 1.5e9), note: `Export all records for ${u.name}` }, 'data_exfiltration');
  }

  for (let k = 0; k < 4; k++) { // insider misuse: off-hours session on a known device, several mid-size downloads and an above-usual payment
    newCase('insider');
    const u = people.filter((p) => p.downloads)[k + 6] || nextVictim(), t0 = at((k + 2) % attackDays, 0.5 + rand() * 2), dev = pick(rand, u.devices);
    push({ ts: t0, user: u.id, event: 'login', ip: u.ip, device: dev, city: u.city }, 'insider_misuse');
    for (let j = 0; j < 3; j++) push({ ts: t0 + (2 + j * 3) * MIN, user: u.id, event: 'download', ip: u.ip, device: dev, city: u.city, bytes: Math.round(Math.exp(13.6 + rand() * 0.6)) }, 'insider_misuse');
    push({ ts: t0 + 14 * MIN, user: u.id, event: 'transfer', ip: u.ip, device: dev, city: u.city, amount: Math.round(u.amount * 2.6), account: pick(rand, u.payees) }, 'insider_misuse');
  }

  // Legitimate surprises (labelled normal): real trips, new phones, one-off big payments.
  for (let k = 0; k < 6; k++) {
    const u = nextVictim(), d = rand() * attackDays, h = u.hour;
    const kind = k % 3;
    if (kind === 0) push({ ts: at(d, h), user: u.id, event: 'login', ip: ip(), device: pick(rand, u.devices), city: pick(rand, DOMESTIC.filter((c) => c !== u.city)) });
    if (kind === 1) push({ ts: at(d, h), user: u.id, event: 'login', ip: u.ip, device: `iPhone-${Math.floor(rand() * 9000 + 1000)}`, city: u.city });
    if (kind === 2) push({ ts: at(d, h), user: u.id, event: 'transfer', ip: u.ip, device: pick(rand, u.devices), city: u.city, amount: Math.round(u.amount * 4), account: pick(rand, u.payees) });
  }

  events.sort((a, b) => a.ts - b.ts);
  return { events, trainUntil: attackStart, people: people.length, customers: people, cities: Object.keys(CITIES).length };
}
