/**
 * Privacy layer: "Innovation Without Exposure".
 *
 * 1. Pseudonymisation: identifiers (user, IP, device, account) are replaced with
 *    keyed HMAC-SHA256 tokens. The same input always maps to the same token under
 *    one key, so behaviour can still be modelled, but the original value cannot be
 *    recovered without the key, and the key never leaves the machine.
 * 2. Redaction: free-text fields are scanned for PII (emails, phone numbers, card
 *    numbers that pass the Luhn check, Aadhaar, PAN, IP addresses) and masked.
 * 3. Differential privacy: counts in shareable summaries get Laplace noise.
 */
import { hmacSha256, toHex } from './sha256.js';

const PREFIX = { user: 'usr', ip: 'ip', device: 'dev', account: 'acc' };

/** Create a pseudonymiser bound to a secret key. */
export function createPseudonymizer(secret) {
  if (!secret || String(secret).length < 16) throw new Error('Privacy key must be at least 16 characters.');
  const cache = new Map();
  return function pseudonymize(kind, value) {
    if (value === undefined || value === null || value === '') return '';
    const id = kind + '\u0000' + value;
    let tok = cache.get(id);
    if (!tok) {
      tok = (PREFIX[kind] || kind) + '_' + toHex(hmacSha256(secret, id)).slice(0, 12);
      cache.set(id, tok);
    }
    return tok;
  };
}

/** Random 32-character key from a cryptographically secure source. */
export function randomKey() {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  return toHex(bytes);
}

/** Luhn checksum, used to avoid masking random digit strings as card numbers. */
export function luhnValid(digits) {
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return digits.length >= 13 && sum % 10 === 0;
}

const PATTERNS = [
  { type: 'email', re: /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g },
  { type: 'card', re: /\b(?:\d[ -]?){13,19}\b/g, check: (m) => luhnValid(m.replace(/\D/g, '')) },
  { type: 'aadhaar', re: /\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b/g },
  { type: 'pan', re: /\b[A-Z]{5}\d{4}[A-Z]\b/g },
  { type: 'phone', re: /(?:\+91[ -]?)?\b[6-9]\d{4}[ -]?\d{5}\b/g },
  { type: 'ip', re: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g }
];

/**
 * Mask PII inside free text. Returns { text, found } where found counts matches by type.
 * Order matters: cards are checked before Aadhaar/phone so a card number is not split.
 */
export function redactText(input) {
  let text = String(input ?? '');
  const found = {};
  for (const p of PATTERNS) {
    text = text.replace(p.re, (m) => {
      if (p.check && !p.check(m)) return m;
      found[p.type] = (found[p.type] || 0) + 1;
      return `[${p.type.toUpperCase()}]`;
    });
  }
  return { text, found };
}

/**
 * Laplace mechanism for counting queries (sensitivity 1).
 * `rand` is injectable so tests and reproducible reports can use a seeded RNG.
 */
export function laplaceCount(trueCount, epsilon = 1, rand = Math.random) {
  const u = rand() - 0.5;
  const noise = -(1 / epsilon) * Math.sign(u) * Math.log(1 - 2 * Math.abs(u));
  return Math.max(0, Math.round(trueCount + noise));
}

/**
 * Pseudonymise and redact a list of raw events.
 * Returns the safe events plus an audit of what was protected (counts only, no values).
 */
export function protectEvents(rawEvents, secret) {
  const pseudo = createPseudonymizer(secret);
  const audit = { tokenized: { user: 0, ip: 0, device: 0, account: 0 }, redacted: {}, rows: rawEvents.length };
  const uniq = { user: new Set(), ip: new Set(), device: new Set(), account: new Set() };
  const safe = rawEvents.map((e) => {
    const out = { ...e };
    for (const kind of ['user', 'ip', 'device', 'account']) {
      if (e[kind]) { uniq[kind].add(e[kind]); out[kind] = pseudo(kind, e[kind]); }
    }
    if (e.note) {
      const r = redactText(e.note);
      out.note = r.text;
      for (const [k, v] of Object.entries(r.found)) audit.redacted[k] = (audit.redacted[k] || 0) + v;
    }
    return out;
  });
  for (const kind of Object.keys(uniq)) audit.tokenized[kind] = uniq[kind].size;
  return { events: safe, audit };
}
