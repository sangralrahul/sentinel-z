/**
 * Small dependency-free SVG charts with hover tooltips.
 * Colours come from CSS custom properties so light and dark themes both work.
 */
const NS = 'http://www.w3.org/2000/svg';
const el = (tag, attrs = {}, parent) => {
  const n = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
  if (parent) parent.appendChild(n);
  return n;
};
const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

/** Axis maximum and tick count with round tick steps (1, 2 or 5 × 10^n). */
function niceScale(v, target = 4) {
  if (v <= 0) return { max: 1, ticks: 1 };
  const raw = v / target, p = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 5, 10].map((m) => m * p).find((s) => s >= raw);
  const st = Math.max(step, v < target ? 1 : step);
  const ticks = Math.ceil(v / st);
  return { max: ticks * st, ticks };
}

function tooltip(host) {
  const tip = document.createElement('div');
  tip.className = 'tip';
  tip.hidden = true;
  host.appendChild(tip);
  return {
    show(html, x, y) { tip.innerHTML = html; tip.hidden = false; const w = host.clientWidth; tip.style.left = Math.min(Math.max(x, 70), w - 70) + 'px'; tip.style.top = y + 'px'; },
    hide() { tip.hidden = true; }
  };
}

/** Rounded top only (4px), flat on the baseline. */
function barPath(x, y, w, h, r = 4) {
  if (h <= 0) return '';
  r = Math.min(r, w / 2, h);
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`;
}

/**
 * Stacked bars. data: [{label, values:{key:n}}], series: [{key, name, color}]
 */
export function stackedBars(host, data, series, { height = 220, yLabel = '' } = {}) {
  host.innerHTML = '';
  host.classList.add('chart');
  const W = 640, H = height, m = { t: 12, r: 8, b: 26, l: 34 };
  const iw = W - m.l - m.r, ih = H - m.t - m.b;
  const totals = data.map((d) => series.reduce((s, k) => s + (d.values[k.key] || 0), 0));
  const { max, ticks } = niceScale(Math.max(1, ...totals));
  const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': yLabel }, host);
  const g = el('g', { class: 'grid' }, svg);
  for (let i = 0; i <= ticks; i++) {
    const v = (max / ticks) * i, y = m.t + ih - (v / max) * ih;
    el('line', { x1: m.l, x2: W - m.r, y1: y, y2: y }, g);
    const t = el('text', { x: m.l - 6, y: y + 4, 'text-anchor': 'end' }, svg); t.textContent = Number.isInteger(v) ? v : v.toFixed(1);
  }
  const band = iw / data.length, bw = Math.min(36, band * 0.62);
  const tip = tooltip(host);
  data.forEach((d, i) => {
    const x = m.l + band * i + (band - bw) / 2;
    let acc = 0;
    const col = el('g', { class: 'col', style: `transform-origin:${x + bw / 2}px ${m.t + ih}px;animation-delay:${i * 45}ms` }, svg);
    const visible = series.filter((s) => d.values[s.key]);
    visible.forEach((s, j) => {
      const v = d.values[s.key];
      const h = (v / max) * ih;
      const y = m.t + ih - ((acc + v) / max) * ih;
      const gap = j > 0 ? 2 : 0; // 2px surface gap between stacked segments
      const top = j === visible.length - 1;
      if (top) el('path', { d: barPath(x, y, bw, h - gap), fill: `var(${s.color})` }, col);
      else el('rect', { x, y, width: bw, height: Math.max(0, h - gap), fill: `var(${s.color})` }, col);
      acc += v;
    });
    if (data.length <= 14 || i % Math.ceil(data.length / 10) === 0) {
      const t = el('text', { x: x + bw / 2, y: H - 8, 'text-anchor': 'middle' }, svg); t.textContent = d.label;
    }
    const hit = el('rect', { x: m.l + band * i, y: m.t, width: band, height: ih, fill: 'transparent' }, svg);
    hit.addEventListener('mouseenter', () => {
      const rows = series.map((s) => `<div>${esc(s.name)}: <b>${d.values[s.key] || 0}</b></div>`).join('');
      const scale = host.clientWidth / W;
      tip.show(`<b>${esc(d.title || d.label)}</b>${rows}`, (x + bw / 2) * scale, (m.t + ih - (totals[i] / max) * ih) * scale);
    });
    hit.addEventListener('mouseleave', tip.hide);
  });
  el('line', { x1: m.l, x2: W - m.r, y1: m.t + ih, y2: m.t + ih, stroke: 'var(--line-strong)' }, svg);
  legend(host, series);
}

/** Horizontal bars as HTML rows (label · bar · value). */
export function hbars(host, rows, { color = '--s1', format = (v) => v } = {}) {
  const max = Math.max(1, ...rows.map((r) => r.value));
  host.innerHTML = rows.map((r) => `<div class="hbar" title="${esc(r.label)}: ${format(r.value)}"><span>${esc(r.label)}</span><div class="track"><div class="fill" style="width:${(r.value / max) * 100}%;background:var(${color})"></div></div><span class="v">${format(r.value)}</span></div>`).join('') || '<p class="empty">Nothing to show.</p>';
}

/** ROC curve with the chance diagonal and a crosshair tooltip. */
export function rocChart(host, pts, auc, { marker } = {}) {
  host.innerHTML = '';
  host.classList.add('chart');
  const S = 300, m = { t: 10, r: 12, b: 34, l: 40 }, iw = S - m.l - m.r, ih = S - m.t - m.b;
  const X = (v) => m.l + v * iw, Y = (v) => m.t + ih - v * ih;
  const svg = el('svg', { viewBox: `0 0 ${S} ${S}`, role: 'img', 'aria-label': `ROC curve, area under curve ${auc.toFixed(3)}` }, host);
  const g = el('g', { class: 'grid' }, svg);
  for (let i = 0; i <= 4; i++) {
    const v = i / 4;
    el('line', { x1: X(0), x2: X(1), y1: Y(v), y2: Y(v) }, g);
    el('line', { x1: X(v), x2: X(v), y1: Y(0), y2: Y(1) }, g);
    const a = el('text', { x: X(v), y: S - m.b + 16, 'text-anchor': 'middle' }, svg); a.textContent = v;
    const b = el('text', { x: m.l - 6, y: Y(v) + 4, 'text-anchor': 'end' }, svg); b.textContent = v;
  }
  const xl = el('text', { x: X(0.5), y: S - 4, 'text-anchor': 'middle' }, svg); xl.textContent = 'False positive rate';
  const yl = el('text', { x: 10, y: Y(0.5), 'text-anchor': 'middle', transform: `rotate(-90 10 ${Y(0.5)})` }, svg); yl.textContent = 'True positive rate';
  el('line', { x1: X(0), y1: Y(0), x2: X(1), y2: Y(1), stroke: 'var(--line-strong)', 'stroke-dasharray': '4 4' }, svg);
  const d = pts.map(([x, y], i) => `${i ? 'L' : 'M'}${X(x).toFixed(1)},${Y(y).toFixed(1)}`).join('');
  el('path', { d, class: 'draw', pathLength: 1, fill: 'none', stroke: 'var(--s1)', 'stroke-width': 2, 'stroke-linejoin': 'round' }, svg);
  if (marker) el('circle', { cx: X(marker[0]), cy: Y(marker[1]), r: 5, fill: 'var(--s1)', stroke: 'var(--surface)', 'stroke-width': 2 }, svg);
  const tip = tooltip(host);
  const cross = el('line', { y1: Y(0), y2: Y(1), stroke: 'var(--muted)', 'stroke-width': 1, visibility: 'hidden' }, svg);
  const dot = el('circle', { r: 4, fill: 'var(--s1)', stroke: 'var(--surface)', 'stroke-width': 2, visibility: 'hidden' }, svg);
  const hit = el('rect', { x: X(0), y: Y(1), width: iw, height: ih, fill: 'transparent' }, svg);
  hit.addEventListener('mousemove', (ev) => {
    const r = svg.getBoundingClientRect(), scale = r.width / S;
    const fx = Math.max(0, Math.min(1, ((ev.clientX - r.left) / scale - m.l) / iw));
    let best = pts[0];
    for (const p of pts) if (Math.abs(p[0] - fx) < Math.abs(best[0] - fx)) best = p;
    cross.setAttribute('x1', X(best[0])); cross.setAttribute('x2', X(best[0])); cross.setAttribute('visibility', 'visible');
    dot.setAttribute('cx', X(best[0])); dot.setAttribute('cy', Y(best[1])); dot.setAttribute('visibility', 'visible');
    tip.show(`False alarms <b>${(best[0] * 100).toFixed(2)}%</b><br>Attacks caught <b>${(best[1] * 100).toFixed(1)}%</b>`, X(best[0]) * scale, Y(best[1]) * scale);
  });
  hit.addEventListener('mouseleave', () => { tip.hide(); cross.setAttribute('visibility', 'hidden'); dot.setAttribute('visibility', 'hidden'); });
}

/**
 * Grouped horizontal bars: per category, one bar per series (values 0..1).
 * rows: [{label, values:{key:v}, detail:{key:'3/5'}}]
 */
export function groupedBars(host, rows, series) {
  host.innerHTML = '';
  host.classList.add('chart');
  const W = 640, rowH = 16 * series.length + 18, m = { t: 6, r: 44, b: 22, l: 210 };
  const H = m.t + rows.length * rowH + m.b, iw = W - m.l - m.r;
  const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Recall by attack type' }, host);
  const g = el('g', { class: 'grid' }, svg);
  for (let i = 0; i <= 4; i++) {
    const x = m.l + (iw * i) / 4;
    el('line', { x1: x, x2: x, y1: m.t, y2: H - m.b }, g);
    const t = el('text', { x, y: H - 6, 'text-anchor': 'middle' }, svg); t.textContent = `${i * 25}%`;
  }
  const tip = tooltip(host);
  rows.forEach((r, i) => {
    const y0 = m.t + i * rowH + 8;
    const lab = el('text', { x: m.l - 10, y: y0 + (series.length * 16) / 2 + 2, 'text-anchor': 'end' }, svg);
    lab.textContent = r.label.length > 32 ? r.label.slice(0, 31) + '…' : r.label;
    lab.setAttribute('style', 'fill:var(--ink-2);font-size:12px');
    series.forEach((s, j) => {
      const v = r.values[s.key] || 0, y = y0 + j * 16, w = Math.max(v * iw, 1);
      el('path', { d: `M${m.l},${y}H${m.l + w - Math.min(3, w)}Q${m.l + w},${y} ${m.l + w},${y + 3}V${y + 9}Q${m.l + w},${y + 12} ${m.l + w - Math.min(3, w)},${y + 12}H${m.l}Z`, class: 'gbar', style: `transform-origin:${m.l}px ${y}px;animation-delay:${(i * series.length + j) * 30}ms`, fill: `var(${s.color})` }, svg);
      const hit = el('rect', { x: m.l, y: y - 2, width: iw, height: 16, fill: 'transparent' }, svg);
      hit.addEventListener('mouseenter', () => {
        const scale = host.clientWidth / W;
        tip.show(`<b>${esc(r.label)}</b><br>${esc(s.name)}: <b>${Math.round(v * 100)}%</b> (${r.detail?.[s.key] || ''} events)`, (m.l + w) * scale, y * scale);
      });
      hit.addEventListener('mouseleave', tip.hide);
    });
  });
  legend(host, series);
}

function legend(host, series) {
  const lg = document.createElement('div');
  lg.className = 'legend';
  lg.innerHTML = series.map((s) => `<span><i style="background:var(${s.color})"></i>${esc(s.name)}</span>`).join('');
  host.appendChild(lg);
}

/**
 * Heat map: rows × 24 hours, counts shaded on one hue (light → dark).
 * rows: [{label, values: number[24]}]
 */
export function heatmap(host, rows, { unit = 'alerts' } = {}) {
  host.innerHTML = '';
  host.classList.add('chart');
  const cw = 22, ch = 22, gap = 2, m = { t: 4, r: 4, b: 22, l: 54 };
  const W = m.l + 24 * (cw + gap) + m.r, H = m.t + rows.length * (ch + gap) + m.b;
  const max = Math.max(1, ...rows.flatMap((r) => r.values));
  const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': `Heat map of ${unit} by day and hour` }, host);
  const tip = tooltip(host);
  rows.forEach((r, i) => {
    const y = m.t + i * (ch + gap);
    const t = el('text', { x: m.l - 8, y: y + ch / 2 + 4, 'text-anchor': 'end' }, svg); t.textContent = r.label;
    r.values.forEach((v, h) => {
      const x = m.l + h * (cw + gap);
      const share = v ? 18 + Math.round((v / max) * 82) : 0;
      const cell = el('rect', { x, y, width: cw, height: ch, rx: 3, class: 'hm', style: `fill:${v ? `color-mix(in srgb, var(--s1) ${share}%, var(--surface))` : 'var(--surface-2)'};animation-delay:${(i * 24 + h) * 4}ms` }, svg);
      cell.addEventListener('mouseenter', () => {
        const scale = host.clientWidth / W;
        tip.show(`<b>${esc(r.label)}, ${String(h).padStart(2, '0')}:00–${String(h).padStart(2, '0')}:59</b><br>${v} ${unit}`, (x + cw / 2) * scale, y * scale);
        cell.setAttribute('stroke', 'var(--ink)');
      });
      cell.addEventListener('mouseleave', () => { tip.hide(); cell.removeAttribute('stroke'); });
    });
  });
  for (let h = 0; h < 24; h += 3) {
    const t = el('text', { x: m.l + h * (cw + gap) + cw / 2, y: H - 6, 'text-anchor': 'middle' }, svg); t.textContent = String(h).padStart(2, '0');
  }
  const lg = document.createElement('div');
  lg.className = 'legend hm-legend';
  lg.innerHTML = `<span>Fewer</span>${[0, 25, 50, 75, 100].map((p) => `<i style="background:${p ? `color-mix(in srgb, var(--s1) ${18 + Math.round(p * 0.82)}%, var(--surface))` : 'var(--surface-2)'}"></i>`).join('')}<span>More ${unit} (max ${max})</span>`;
  host.appendChild(lg);
}

/**
 * Customer timeline: every event in the monitoring window as a dot (x = time, y = risk),
 * with the alert threshold as a dashed line. Alerts use severity colours.
 */
export function timeline(host, points, { start, end, threshold, fmtTime = String } = {}) {
  host.innerHTML = '';
  host.classList.add('chart');
  const W = Math.max(320, Math.round(host.clientWidth || 640)), H = 170, m = { t: 14, r: 10, b: 22, l: 34 }, iw = W - m.l - m.r, ih = H - m.t - m.b;
  const X = (t) => m.l + ((t - start) / Math.max(1, end - start)) * iw, Y = (v) => m.t + ih - v * ih;
  const svg = el('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': 'Risk of every event for this customer over time' }, host);
  const g = el('g', { class: 'grid' }, svg);
  for (const v of [0, 0.5, 1]) {
    el('line', { x1: m.l, x2: W - m.r, y1: Y(v), y2: Y(v) }, g);
    const t = el('text', { x: m.l - 6, y: Y(v) + 4, 'text-anchor': 'end' }, svg); t.textContent = v;
  }
  el('line', { x1: m.l, x2: W - m.r, y1: Y(threshold), y2: Y(threshold), stroke: 'var(--critical)', 'stroke-dasharray': '4 4', 'stroke-width': 1 }, svg);
  const tl = el('text', { x: W - m.r, y: Y(threshold) - 5, 'text-anchor': 'end' }, svg); tl.textContent = `alert threshold ${threshold.toFixed(2)}`;
  const days = Math.round((end - start) / 864e5);
  for (let d = 0; d <= days; d++) {
    const t = el('text', { x: X(start + d * 864e5), y: H - 6, 'text-anchor': 'middle' }, svg); t.textContent = fmtTime(start + d * 864e5);
  }
  const tip = tooltip(host);
  const sorted = [...points].sort((a, b) => (a.severity ? 1 : 0) - (b.severity ? 1 : 0));
  sorted.forEach((p, i) => {
    const color = p.severity === 'critical' ? 'var(--critical)' : p.severity === 'high' ? 'var(--high)' : p.severity === 'medium' ? 'var(--medium)' : 'var(--line-strong)';
    const c = el('circle', { cx: X(p.ts), cy: Y(p.score), r: p.severity ? 6 : 4, fill: color, stroke: 'var(--surface)', 'stroke-width': 2, class: 'dot', style: `animation-delay:${i * 12}ms` }, svg);
    c.addEventListener('mouseenter', () => {
      const scale = host.clientWidth / W;
      tip.show(`<b>${esc(p.title)}</b><br>Risk <b>${p.score.toFixed(2)}</b>${p.reason ? `<br>${esc(p.reason)}` : ''}`, X(p.ts) * scale, Y(p.score) * scale);
    });
    c.addEventListener('mouseleave', tip.hide);
  });
}
