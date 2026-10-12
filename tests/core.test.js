// Run with: npm test  (Node's built-in test runner, no dependencies)
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { sha256, hmacSha256, toHex, utf8 } from '../core/sha256.js';
import { createPseudonymizer, redactText, luhnValid, laplaceCount, protectEvents } from '../core/privacy.js';
import { IsolationForest } from '../core/iforest.js';
import { mulberry32, gauss } from '../core/rng.js';
import { distanceKm } from '../core/geo.js';
import { generateScenario } from '../core/generator.js';
import { analyze, parseCSV, toCSV, normalizeEvents, rocAuc } from '../core/pipeline.js';

const KEY = 'test-secret-key-0123456789';

test('SHA-256 and HMAC match Node crypto', () => {
  for (const s of ['', 'abc', 'Sentinel-Z', 'x'.repeat(55), 'y'.repeat(64), 'ज़ेड'.repeat(100)]) {
    assert.equal(toHex(sha256(utf8(s))), createHash('sha256').update(s).digest('hex'));
    assert.equal(toHex(hmacSha256(KEY, s)), createHmac('sha256', KEY).update(s).digest('hex'));
  }
  const longKey = 'k'.repeat(100);
  assert.equal(toHex(hmacSha256(longKey, 'msg')), createHmac('sha256', longKey).update('msg').digest('hex'));
});

test('pseudonymisation is stable, key-dependent and one-way', () => {
  const p1 = createPseudonymizer(KEY), p2 = createPseudonymizer('another-secret-key-987654');
  assert.equal(p1('user', 'asha@bank.example'), p1('user', 'asha@bank.example'));
  assert.notEqual(p1('user', 'asha@bank.example'), p2('user', 'asha@bank.example'));
  assert.notEqual(p1('user', 'x'), p1('ip', 'x'));
  assert.match(p1('user', 'asha@bank.example'), /^usr_[0-9a-f]{12}$/);
  assert.ok(!p1('user', 'asha@bank.example').includes('asha'));
  assert.throws(() => createPseudonymizer('short'), /at least 16/);
});

test('PII redaction masks real identifiers and leaves ordinary numbers', () => {
  const r = redactText('Mail asha@bank.example, call +91 9876543210, card 4111 1111 1111 1111, Aadhaar 2345 6789 0123, PAN ABCDE1234F, ip 10.2.3.4');
  assert.equal(r.text, 'Mail [EMAIL], call [PHONE], card [CARD], Aadhaar [AADHAAR], PAN [PAN], ip [IP]');
  assert.deepEqual(r.found, { email: 1, phone: 1, card: 1, aadhaar: 1, pan: 1, ip: 1 });
  assert.equal(redactText('Invoice 1234567890123 total 450').text, 'Invoice 1234567890123 total 450'); // fails Luhn
  assert.equal(redactText('Call +91 98765 43210 or 98765-43210').text, 'Call [PHONE] or [PHONE]');
  assert.ok(luhnValid('4111111111111111'));
  assert.ok(!luhnValid('4111111111111112'));
});

test('Laplace noise is unbiased on average', () => {
  const rand = mulberry32(1);
  let sum = 0;
  for (let i = 0; i < 4000; i++) sum += laplaceCount(100, 1, rand);
  assert.ok(Math.abs(sum / 4000 - 100) < 0.2);
});

test('protectEvents removes raw identifiers and reports counts only', () => {
  const { events, audit } = protectEvents([
    { user: 'asha@bank.example', ip: '10.0.0.1', device: 'Pixel-1', account: '123456789012', note: 'call 9876543210' }
  ], KEY);
  const s = JSON.stringify(events);
  for (const raw of ['asha', '10.0.0.1', 'Pixel-1', '123456789012', '9876543210']) assert.ok(!s.includes(raw), raw);
  assert.deepEqual(audit.tokenized, { user: 1, ip: 1, device: 1, account: 1 });
  assert.deepEqual(audit.redacted, { phone: 1 });
});

test('Isolation Forest scores outliers above inliers', () => {
  const rand = mulberry32(3);
  const X = Array.from({ length: 500 }, () => [gauss(rand), gauss(rand)]);
  const f = new IsolationForest({ seed: 1 }).fit(X);
  assert.ok(f.score([6, 6]) > 0.65);
  assert.ok(f.score([0, 0]) < 0.5);
  assert.throws(() => new IsolationForest().fit([]));
});

test('distances between cities', () => {
  assert.ok(Math.abs(distanceKm('Mumbai', 'Delhi') - 1150) < 30);
  assert.equal(distanceKm('Mumbai', 'Mumbai'), 0);
  assert.equal(distanceKm('Mumbai', 'Atlantis'), null);
});

test('ROC-AUC on simple cases', () => {
  assert.equal(rocAuc([0.1, 0.2, 0.8, 0.9], [0, 0, 1, 1]), 1);
  assert.equal(rocAuc([0.9, 0.8, 0.2, 0.1], [0, 0, 1, 1]), 0);
  assert.equal(rocAuc([0.5, 0.5], [0, 1]), 0.5);
});

test('CSV parsing handles quotes, commas, CRLF and round-trips', () => {
  const rows = parseCSV('timestamp,user,event,note\r\n2026-10-01T10:00:00Z,a,login,"hello, ""world"""\r\n');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].note, 'hello, "world"');
  const sc = generateScenario({ users: 10, days: 6, attackDays: 2 });
  const back = normalizeEvents(parseCSV(toCSV(sc.events))).events;
  assert.equal(back.length, sc.events.length);
  assert.equal(back[5].user, sc.events[5].user);
});

test('invalid rows are rejected, too little data is explained', () => {
  const { events, rejected } = normalizeEvents([{ timestamp: 'nope', user: 'a', event: 'login' }, { timestamp: '2026-01-01T00:00:00Z', user: 'a', event: 'login' }]);
  assert.equal(events.length, 1);
  assert.deepEqual(rejected, [1]);
  assert.throws(() => analyze([{ timestamp: '2026-01-01T00:00:00Z', user: 'a', event: 'login' }], { secret: KEY }), /at least 50/);
});

test('end to end: detects every attack campaign, explains alerts, leaks nothing', () => {
  for (const seed of [7, 11]) {
    const sc = generateScenario({ seed });
    const r = analyze(sc.events, { secret: KEY, trainUntil: sc.trainUntil });
    const e = r.evaluation;
    assert.ok(e.auc > 0.98, `AUC ${e.auc}`);
    assert.ok(e.recall > 0.85, `recall ${e.recall}`);
    assert.ok(e.precision > 0.7, `precision ${e.precision}`);
    assert.equal(e.attacks.caught, e.attacks.total);
    // The hybrid catches more than either part alone.
    assert.ok(e.ablation.hybrid.recall >= e.ablation.model.recall);
    assert.ok(e.ablation.hybrid.recall >= e.ablation.rules.recall);
    // Every alert carries at least one plain-English reason.
    assert.ok(r.alerts.every((a) => a.reasons.length > 0));
    // No raw identifiers anywhere in the output.
    const out = JSON.stringify(r);
    assert.ok(!out.includes('@bank.example'));
    assert.ok(!/\b10\.\d+\.\d+\.\d+\b/.test(out));
  }
});

test('results are reproducible for the same seed', () => {
  const sc = generateScenario({ seed: 5, users: 30 });
  const a = analyze(sc.events, { secret: KEY, trainUntil: sc.trainUntil });
  const b = analyze(sc.events, { secret: KEY, trainUntil: sc.trainUntil });
  assert.equal(a.alerts.length, b.alerts.length);
  assert.equal(a.evaluation.auc, b.evaluation.auc);
});

test('red-team simulator: obvious attacks are caught, targets are clean customers', async () => {
  const { injectAttack, SIM_ATTACKS } = await import('../core/simulator.js');
  for (const type of Object.keys(SIM_ATTACKS).filter((t) => t !== 'low_and_slow')) {
    const sc = generateScenario({ seed: 7 });
    const inj = injectAttack(sc, { type, customer: 3, day: 2 });
    assert.ok(inj.injected > 0);
    assert.ok(!sc.events.some((e) => e.user === inj.target && e.label !== 'normal'), 'target untouched by scenario attacks');
    const r = analyze(inj.events, { secret: KEY, trainUntil: sc.trainUntil, keepRows: true });
    assert.ok(r.rows.some((x) => x.case === 'sim-1' && x.severity), `${type} should be detected`);
  }
  assert.throws(() => injectAttack(generateScenario({ users: 10, days: 6, attackDays: 2 }), { type: 'nope' }), /Unknown attack/);
});

test('CLI runs end to end without SENTINEL_KEY (random key path)', async () => {
  const { execFileSync } = await import('node:child_process');
  const env = { ...process.env }; delete env.SENTINEL_KEY;
  const out = execFileSync(process.execPath, ['cli/sentinel-z.js', 'analyze', 'data/sample-events.csv', '--train-days', '14'], { env, encoding: 'utf8' });
  assert.match(out, /attacks caught 26\/26/);
  assert.ok(!out.includes('@bank.example'));
});
