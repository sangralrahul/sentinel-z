/**
 * Hero background: a perspective field of points flowing towards the viewer,
 * like a stream of events. Each alert in the live replay sends a coloured
 * ripple across the field, so the background reflects what the detector sees.
 * Canvas 2D only, ~2.5k points (fewer are actually on screen), paused when hidden or off screen.
 */
export function startField(canvas, { reduced = false } = {}) {
  const ctx = canvas.getContext('2d', { alpha: true });
  const COLS = 96, ROWS = 26, SPACING = 1;
  const ripples = [];
  let lastScan = 0, w = 0, h = 0, dpr = 1, t = 0, last = performance.now(), running = true, mx = 0, my = 0, tx = 0, ty = 0;

  const resize = () => {
    dpr = Math.min(2, devicePixelRatio || 1);
    const r = canvas.getBoundingClientRect();
    w = r.width; h = r.height;
    canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  };
  resize();
  addEventListener('resize', resize);
  addEventListener('pointermove', (e) => { tx = (e.clientX / innerWidth - 0.5); ty = (e.clientY / innerHeight - 0.5); }, { passive: true });

  /** Send a ripple: severity 'critical' (red) or 'high' (amber). */
  const pulse = (severity = 'critical') => {
    ripples.push({
      gx: (Math.random() - 0.5) * 16, gz: 5 + Math.random() * 10,
      born: t, color: severity === 'critical' ? [235, 87, 87] : severity === 'high' ? [242, 153, 74] : [96, 150, 255]
    });
    if (ripples.length > 8) ripples.shift();
  };

  const draw = (now) => {
    // Cap at ~40 fps: smooth enough for a slow drift, half the work on modest devices.
    if (now - last < 24 && running && !reduced) { requestAnimationFrame(draw); return; }
    const dt = Math.min(64, now - last); last = now;
    if (!reduced) t += dt / 1000;
    // Ambient blue ripple every few seconds: events being scanned. Alerts add red/amber ones.
    if (!reduced && t - lastScan > 2.6) { lastScan = t; pulse('scan'); }
    mx += (tx - mx) * 0.04; my += (ty - my) * 0.04;
    ctx.clearRect(0, 0, w, h);
    const horizon = h * (0.36 + my * 0.02), cx = w / 2 + mx * 30, fov = h * 0.3;
    const flow = (t * 0.55) % SPACING;
    const hot = [];
    ctx.fillStyle = 'rgb(205,214,235)';
    for (let zr = 0; zr < ROWS; zr++) {
      const z = zr * SPACING - flow + 1.1;           // depth; rows drift towards the viewer
      const scale = fov / z;
      const depth = zr / ROWS;
      const fade = Math.min(1, (ROWS - zr) / 6) * Math.min(1, (zr + 1 - flow) / 2);
      for (let c = 0; c < COLS; c++) {
        const x = (c - COLS / 2 + 0.5) * 0.5;
        const sx = cx + x * scale;
        if (sx < -6 || sx > w + 6) continue;
        const wave = Math.sin(x * 0.55 + t * 0.7) * 0.5 + Math.cos(z * 0.35 - t * 0.5) * 0.5;
        const sy = horizon + (1.6 - wave * 0.22) * scale;
        if (sy > h + 6) continue;
        let glow = 0, col = null;
        for (const rp of ripples) {
          const age = t - rp.born;
          if (age > 3) continue;
          const d = Math.hypot(x - rp.gx, (z + flow) - rp.gz);
          const ring = Math.abs(d - age * 4.2);
          if (ring < 0.7) { const k = (1 - ring / 0.7) * (1 - age / 3); if (k > glow) { glow = k; col = rp.color; } }
        }
        const a = Math.min(1, (0.07 + 0.42 * (1 - depth) + glow * 0.9) * fade);
        if (a < 0.015) continue;
        const size = Math.max(0.7, scale * 0.014) * (1 + glow * 1.6);
        if (col) { hot.push(sx, sy, size, a, col); continue; }
        ctx.globalAlpha = a;
        ctx.fillRect(sx - size / 2, sy - size / 2, size, size);
      }
    }
    for (let k = 0; k < hot.length; k += 5) {
      const sx = hot[k], sy = hot[k + 1], size = hot[k + 2], c = hot[k + 4];
      ctx.globalAlpha = hot[k + 3]; ctx.fillStyle = `rgb(${c[0]},${c[1]},${c[2]})`;
      ctx.fillRect(sx - size / 2, sy - size / 2, size, size);
    }
    ctx.globalAlpha = 1;
    for (let i = ripples.length - 1; i >= 0; i--) if (t - ripples[i].born > 3) ripples.splice(i, 1);
    if (running && !reduced) requestAnimationFrame(draw);
  };

  const io = new IntersectionObserver(([en]) => {
    const was = running;
    running = en.isIntersecting && !document.hidden;
    if (running && !was && !reduced) { last = performance.now(); requestAnimationFrame(draw); }
  });
  io.observe(canvas);
  document.addEventListener('visibilitychange', () => {
    const was = running;
    running = !document.hidden;
    if (running && !was && !reduced) { last = performance.now(); requestAnimationFrame(draw); }
  });
  requestAnimationFrame(draw);
  return { pulse };
}
