/**
 * Red-team simulator: injects one crafted attack into a synthetic scenario so an
 * analyst can see, live, whether the detector catches it and why.
 * Works only on generated (synthetic) customers; nothing here touches real data.
 */
const MIN = 60000, HOUR = 60 * MIN, DAY = 24 * HOUR;

export const SIM_ATTACKS = {
  impossible_travel: { name: 'Impossible travel', desc: 'Normal login at home, then a login from London 25 minutes later on an unknown laptop.' },
  account_takeover: { name: 'Account takeover', desc: 'New phone from a foreign IP at 03:10, then a large payment to a never-seen payee.' },
  brute_force: { name: 'Brute-force login', desc: 'Nine wrong passwords in five minutes from one IP, then a successful login.' },
  credential_stuffing: { name: 'Credential stuffing', desc: 'One bot IP tries 10 different customers in 15 minutes, then gets into the target.' },
  mule_transfers: { name: 'Mule transfers', desc: 'Seven quick payments to brand-new accounts in under ten minutes.' },
  data_exfiltration: { name: 'Data exfiltration', desc: 'A 1.8 GB export downloaded at 02:30, hundreds of times the usual size.' },
  low_and_slow: { name: 'Low-and-slow insider', desc: 'Slightly larger downloads late in the evening on a known device. Deliberately subtle: may be missed.' }
};

/**
 * @param scenario  result of generateScenario()
 * @param options   { type, customer (index), day (0-based within monitoring window), seed }
 * @returns { events, injected: number, target: string, at: ms }
 */
export function injectAttack(scenario, { type, customer = 0, day = 2 } = {}) {
  if (!SIM_ATTACKS[type]) throw new Error(`Unknown attack type: ${type}`);
  const people = scenario.customers;
  if (!people?.length) throw new Error('The simulator needs a generated scenario.');
  // Pick a customer untouched by the scenario's own attacks, so the result reflects only the injected one.
  const hit = new Set(scenario.events.filter((e) => e.label && e.label !== 'normal').map((e) => e.user));
  const start = ((customer % people.length) + people.length) % people.length;
  let u = people[start];
  for (let k = 0; k < people.length && hit.has(u.id); k++) u = people[(start + k + 1) % people.length];
  const dayStart = scenario.trainUntil + Math.max(0, Math.min(6, day)) * DAY;
  const ist = (h) => dayStart + (h - 5.5) * HOUR;
  const label = 'simulated', kase = 'sim-1';
  const ev = [];
  const add = (e) => ev.push({ ...e, label, case: kase });
  const dev = u.devices[0];
  const newAcct = (k) => String(900000000000 + k * 7919);

  switch (type) {
    case 'impossible_travel': {
      const t = ist(Math.min(21, u.hour));
      ev.push({ ts: t, user: u.id, event: 'login', ip: u.ip, device: dev, city: u.city, label: 'normal' });
      add({ ts: t + 25 * MIN, user: u.id, event: 'login', ip: '185.220.101.7', device: 'Windows-7731', city: 'London' });
      break;
    }
    case 'account_takeover': {
      const t = ist(3.16);
      add({ ts: t, user: u.id, event: 'login', ip: '196.52.43.12', device: 'Android-0420', city: 'Lagos' });
      add({ ts: t + 3 * MIN, user: u.id, event: 'transfer', ip: '196.52.43.12', device: 'Android-0420', city: 'Lagos', amount: Math.round(u.amount * 30), account: newAcct(1), note: 'Urgent, call +91 98111 22334' });
      break;
    }
    case 'brute_force': {
      const t = ist(13.5);
      for (let j = 0; j < 9; j++) add({ ts: t + j * 33000, user: u.id, event: 'login_failed', ip: '45.155.205.99', device: 'Linux-bot', city: 'Delhi' });
      add({ ts: t + 9 * 33000, user: u.id, event: 'login', ip: '45.155.205.99', device: 'Linux-bot', city: 'Delhi' });
      break;
    }
    case 'credential_stuffing': {
      const t = ist(2);
      for (let j = 0; j < 10; j++) {
        const v = people[(people.indexOf(u) + 1 + j * 7) % people.length];
        add({ ts: t + j * 80000, user: v.id, event: 'login_failed', ip: '91.92.250.4', device: 'Linux-bot', city: 'Moscow' });
      }
      add({ ts: t + 15 * MIN, user: u.id, event: 'login', ip: '91.92.250.4', device: 'Linux-bot', city: 'Moscow' });
      break;
    }
    case 'mule_transfers': {
      const t = ist(Math.min(22, u.hour + 0.5));
      for (let j = 0; j < 7; j++) add({ ts: t + j * 80000, user: u.id, event: 'transfer', ip: u.ip, device: dev, city: u.city, amount: 24000 + j * 3100, account: newAcct(10 + j) });
      break;
    }
    case 'data_exfiltration': {
      add({ ts: ist(2.5), user: u.id, event: 'download', ip: u.ip, device: dev, city: u.city, bytes: 1.8e9, note: `Full export requested by ${u.id}` });
      break;
    }
    case 'low_and_slow': {
      const t = ist(Math.min(23, u.hour + 2.5));
      for (let j = 0; j < 2; j++) add({ ts: t + j * 9 * MIN, user: u.id, event: 'download', ip: u.ip, device: dev, city: u.city, bytes: Math.round(Math.exp(13.1)) });
      break;
    }
  }
  const injected = ev.filter((e) => e.label === label).length;
  return { events: scenario.events.concat(ev).sort((a, b) => a.ts - b.ts), injected, target: u.id, at: ev[0].ts };
}
