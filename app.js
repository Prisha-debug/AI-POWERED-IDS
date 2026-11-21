/* ---------- live data ---------- */
const PROBES = []; // disabled – was causing lag. Rely only on PerformanceObserver for real traffic.
let pi = 0, net = {};

function startApp() {
  $$('.tab').forEach(b => b.onclick = () => {
    $$('.tab').forEach(x => x.classList.toggle('on', x === b));
    $$('.view').forEach(v => v.classList.toggle('hidden', v.id !== 'v-' + b.dataset.tab));
    // redraw after layout so hidden canvases get real width
    requestAnimationFrame(() => setTimeout(draw, 50));
  });

  try {
    new PerformanceObserver(l => {
      if (S.on) l.getEntries().forEach(ingest);
    }).observe({ type: 'resource', buffered: true });
  } catch {}

  // one-time machine info only
  fetch('https://www.cloudflare.com/cdn-cgi/trace', { cache: 'no-store' })
    .then(r => r.text())
    .then(t => {
      net.trace = Object.fromEntries(t.trim().split('\n').map(l => l.split('=')));
      vitals();
    }).catch(() => {});

  // much lighter intervals
  setInterval(vitals, 5000);
  setInterval(draw, 2500);           // was 1000
  navigator.getBattery?.().then(b => { net.bat = b; vitals(); });
  addEventListener('online', vitals);
  addEventListener('offline', vitals);
  renderRules();
  vitals();
}

function probe() { /* disabled to stop lag */ }

function ingest(e) {
  if (!/^https?:/.test(e.name)) return;
  let host;
  try { host = new URL(e.name).host; } catch { return; }
  push({
    host,
    type: e.initiatorType,
    proto: e.nextHopProtocol || '—',
    bytes: e.transferSize || e.encodedBodySize || 0,
    dur: Math.round(e.duration),
    url: e.name,
    t: {
      dns: Math.round(e.domainLookupEnd - e.domainLookupStart),
      connect: Math.round(e.connectEnd - e.connectStart),
      wait: Math.round(e.responseStart - e.requestStart)
    }
  });
}

function stats() {
  const d = S.base, n = d.length;
  const m = d.reduce((a, b) => a + b, 0) / (n || 1);
  const sd = Math.sqrt(d.reduce((a, b) => a + (b - m) ** 2, 0) / (n || 1));
  return { n, m, sd };
}

function push(f) {
  const { n, m, sd } = stats();
  f.id = 'F-' + (S.c.n + S.c.s + S.c.c + 1);
  f.time = new Date().toLocaleTimeString();
  const z = n < 8 ? 0 : Math.abs(f.dur - m) / (sd || 1);
  f.score = f.fail ? 1 : +Math.min(1, .1 + z / 5).toFixed(2);

  const rule = S.rules.find(r =>
    r.field === 'host' ? f.host.includes(r.val) : f[r.field] > Number(r.val)
  );
  f.tag = f.tag || (f.fail ? 'Request failed' : rule ? rule.name : '');
  f.status = (f.score >= S.thr + .15 || f.tag) ? 'HIGH' :
             f.score >= S.thr ? 'SUSPICIOUS' : 'NORMAL';

  if (!f.sim && !f.fail) {
    S.base.push(f.dur);
    if (S.base.length > 40) S.base.shift();
    // keep last 60 scores for the new overview chart
    S.lat.push(f.score);               // reuse S.lat array for scores
    if (S.lat.length > 60) S.lat.shift();
  }

  S.c[f.status === 'NORMAL' ? 'n' : f.status === 'HIGH' ? 'c' : 's']++;
  S.hosts[f.host] = (S.hosts[f.host] || 0) + 1;
  S.flows.unshift(f);
  if (S.flows.length > 200) S.flows.pop();
  if (f.status === 'HIGH') alertItem(f);
}

function inject(k) {
  const P = {
    flood:  { host: '203.0.113.45', type: 'simulated', bytes: 900,    dur: 4800, tag: 'Request flood' },
    exfil:  { host: '198.51.100.7', type: 'simulated', bytes: 8400000, dur: 6100, tag: 'Large upload' },
    beacon: { host: '45.33.32.156', type: 'simulated', bytes: 420,    dur: 900,  tag: 'Beaconing' }
  }[k];
  push({ ...P, proto: 'sim', url: '(simulated) ' + P.host, sim: true });
  draw();
}

function toggle() {
  S.on = !S.on;
  $('#pause').textContent = S.on ? 'Pause' : 'Resume';
  $('#live-dot').classList.toggle('off', !S.on);
}
function setThr(v) { S.thr = +v; $('#thr-v').textContent = v; }

/* ---------- views ---------- */
const med = a => {
  if (!a.length) return 0;
  const s = [...a].sort((x, y) => x - y);
  return s[s.length >> 1];
};

function vitals() {
  const c = navigator.connection || {}, h = performance.memory, t = net.trace || {}, b = net.bat;
  const rows = [
    ['Connection', navigator.onLine ? 'online' : 'offline'],
    ['Link type', c.effectiveType || 'n/a'],
    ['Downlink', c.downlink ? c.downlink + ' Mbps' : 'n/a'],
    ['Browser RTT', c.rtt != null ? c.rtt + ' ms' : 'n/a'],
    ['CPU threads', navigator.hardwareConcurrency || 'n/a'],
    ['Memory', navigator.deviceMemory ? '≥ ' + navigator.deviceMemory + ' GB' : 'n/a'],
    ['JS heap', h ? (h.usedJSHeapSize / 1048576).toFixed(0) + ' MB' : 'n/a'],
    ['Battery', b ? Math.round(b.level * 100) + '%' + (b.charging ? ' (charging)' : '') : 'n/a'],
    ['Public IP', t.ip || 'n/a'],
    ['Region', t.loc ? t.loc + ' · ' + (t.colo || '') : 'n/a'],
    ['Time zone', Intl.DateTimeFormat().resolvedOptions().timeZone]
  ];
  $('#vitals').innerHTML = rows.map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join('');
}

function draw() {
  const t = S.c.n + S.c.s + S.c.c;
  $('#k-total').textContent = t.toLocaleString();
  $('#k-n').textContent = S.c.n.toLocaleString();
  $('#k-s').textContent = S.c.s;
  $('#k-c').textContent = S.c.c;
  $('#k-lat').textContent = S.lat.length ? med(S.lat).toFixed(2) : '–';

  const top = Object.entries(S.hosts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const mx = top[0]?.[1] || 1;
  $('#hosts').innerHTML = top.map(([h, n]) =>
    `<li><span>${esc(h)}</span><i style="width:${n / mx * 100}%"></i>${n}</li>`
  ).join('') || '<li class="muted">Waiting for traffic…</li>';

  const { n, m, sd } = stats();
  $('#b-mean').textContent = n ? m.toFixed(0) + ' ms' : '–';
  $('#b-sd').textContent = n ? sd.toFixed(0) + ' ms' : '–';
  $('#b-n').textContent = n;

  // only draw visible charts
  if (!$('#v-overview').classList.contains('hidden')) {
    line($('#c-score'), S.lat);   // scores 0–1
  }
  if (!$('#v-engine').classList.contains('hidden')) {
    scatter($('#c-sc'));
  }
  renderTable();
  renderBlocked();
}

/* ---------- canvas charts ---------- */
const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

function setup(c) {
  if (!c) return null;
  const r = devicePixelRatio || 1;
  let w = c.clientWidth;
  // when tab was hidden, clientWidth can be 0 – force a reasonable size
  if (w < 10) w = c.parentElement?.clientWidth - 32 || 400;
  const h = +c.getAttribute('height') || 210;
  c.width = w * r;
  c.height = h * r;
  const x = c.getContext('2d');
  x.setTransform(r, 0, 0, r, 0, 0);   // cleaner than scale()
  x.clearRect(0, 0, w, h);
  x.font = '11px "IBM Plex Mono", monospace';
  return { x, w, h };
}

function line(c, d) {
  const s = setup(c);
  if (!s) return;
  const { x, w, h } = s, p = 30;
  x.strokeStyle = css('--line');
  x.fillStyle = css('--fade');

  // scores are 0–1
  const mx = Math.max(1, ...d) * 1.05 || 1;
  for (let i = 0; i <= 3; i++) {
    const y = h - p - (h - p - 8) * i / 3;
    x.beginPath();
    x.moveTo(p + 10, y);
    x.lineTo(w, y);
    x.stroke();
    x.fillText((mx * i / 3).toFixed(1), 0, y + 4);
  }
  if (d.length < 2) {
    x.fillText('Collecting samples…', p + 20, h / 2);
    return;
  }
  x.beginPath();
  d.forEach((v, i) => {
    const X = p + 10 + (w - p - 14) * i / Math.max(59, d.length - 1);
    const Y = h - p - (h - p - 8) * v / mx;
    i ? x.lineTo(X, Y) : x.moveTo(X, Y);
  });
  x.strokeStyle = css('--brown');
  x.lineWidth = 2;
  x.stroke();
}

function scatter(c) {
  const s = setup(c);
  if (!s) return;
  const { x, w, h } = s, p = 40;
  const f = S.flows.slice(0, 120);

  x.strokeStyle = css('--line');
  x.fillStyle = css('--fade');
  x.strokeRect(p, 8, w - p - 10, h - p - 10);
  x.fillText('bytes (log) →', w - 110, h - 6);
  x.fillText('ms ↑', 4, 16);

  if (!f.length) {
    x.fillText('No requests yet — open a few tabs or use the test buttons', p + 20, h / 2);
    return;
  }

  const my = Math.max(50, ...f.map(a => a.dur)) * 1.15;
  const lg = v => Math.log10(Math.max(v, 1) + 9);
  const mxb = Math.max(3.5, ...f.map(a => lg(a.bytes)));

  f.forEach(a => {
    const color = a.status === 'HIGH' ? '--bad' :
                  a.status === 'SUSPICIOUS' ? '--warn' : '--ok';
    x.fillStyle = css(color);
    x.globalAlpha = 0.8;
    x.beginPath();
    const X = p + 6 + (w - p - 20) * (lg(a.bytes) / mxb);
    const Y = h - p - 4 - (h - p - 18) * (a.dur / my);
    x.arc(X, Y, 5, 0, Math.PI * 2);
    x.fill();
  });
  x.globalAlpha = 1;
}

addEventListener('resize', () => requestAnimationFrame(draw));
boot();
