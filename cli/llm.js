/**
 * Optional written explanations from a LOCAL language model (Ollama API),
 * for example IBM Granite running on the same LinuxONE / IBM Z machine.
 *
 * Only pseudonymised incident data is sent, and only to localhost or a private
 * network address. Cloud endpoints are refused by design.
 */
const PRIVATE = [/^127\./, /^10\./, /^192\.168\./, /^172\.(1[6-9]|2\d|3[01])\./, /^localhost$/, /^\[?::1\]?$/];

export function isLocalUrl(url) {
  try { const host = new URL(url).hostname; return PRIVATE.some((re) => re.test(host)); } catch { return false; }
}

export async function explainLocally(incidents, { url = 'http://127.0.0.1:11434', model = 'granite3.3:2b', timeoutMs = 60000 } = {}) {
  if (!isLocalUrl(url)) throw new Error('Only local LLM endpoints are allowed.');
  const facts = incidents.map((inc, i) => `${i + 1}. ${inc.severity.toUpperCase()} · user ${inc.user} · ${inc.reasons.map((r) => r.text).join('; ')}`).join('\n');
  const prompt = `You are a bank security analyst. Summarise these incidents for the on-call team in under 120 words.
For each, say the likely attack and one next step. Users are pseudonyms; do not guess real identities.

${facts}`;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(new URL('/api/generate', url), { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ model, prompt, stream: false, options: { temperature: 0.2 } }), signal: ctrl.signal });
    if (!res.ok) throw new Error(`LLM returned ${res.status}`);
    const data = await res.json();
    return (data.response || '').trim();
  } catch (e) {
    return `(Local LLM not reachable: ${e.message}. Install Ollama and run \`ollama pull ${model}\`. The detection results above do not need it.)`;
  } finally {
    clearTimeout(timer);
  }
}
