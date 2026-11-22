/* Sentinel — auth + live browser telemetry */
const $ = s => document.querySelector(s);
const $$ = s => [...document.querySelectorAll(s)];
const LS = localStorage;
const esc = s => String(s).replace(/[&<>"]/g, c => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'
}[c]));

const S = {
  flows: [],
  lat: [],          // now stores anomaly scores (0–1)
  blocked: [],
  thr: 0.65,
  on: true,
  c: { n: 0, s: 0, c: 0 },
  hosts: {},
  base: [],
  rules: [
    { id: 'R-1', name: 'Slow response', field: 'dur', val: '2000' },
    { id: 'R-2', name: 'Large transfer', field: 'bytes', val: '1000000' }
  ]
};

/* ---------- auth ---------- */
const users = () => JSON.parse(LS.getItem('sn_users') || '{}');

async function hash(p, salt) {
  try {
    const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(salt + p));
    return [...new Uint8Array(d)].map(x => x.toString(16).padStart(2, '0')).join('');
  } catch {
    return btoa(salt + p);
  }
}

function authMode(m) {
  $('#f-in').classList.toggle('hidden', m !== 'in');
  $('#f-up').classList.toggle('hidden', m !== 'up');
  $('#t-in').classList.toggle('on', m === 'in');
  $('#t-up').classList.toggle('on', m === 'up');
}

async function signUp(e) {
  e.preventDefault();
  const em = $('#up-email').value.trim().toLowerCase();
  const p = $('#up-pass').value;
  const u = users();
  if (p !== $('#up-pass2').value) return ($('#up-err').textContent = 'Passwords do not match.');
  if (u[em]) return ($('#up-err').textContent = 'An account with this email already exists.');
  const salt = crypto.getRandomValues(new Uint32Array(4)).join('-');
  u[em] = { name: $('#up-name').value.trim(), salt, h: await hash(p, salt) };
  LS.setItem('sn_users', JSON.stringify(u));
  LS.setItem('sn_session', em);
  boot();
}

async function signIn(e) {
  e.preventDefault();
  const em = $('#in-email').value.trim().toLowerCase();
  const u = users()[em];
  if (!u || u.h !== await hash($('#in-pass').value, u.salt))
    return ($('#in-err').textContent = 'Email or password is incorrect.');
  LS.setItem('sn_session', em);
  boot();
}

function signOut() {
  LS.removeItem('sn_session');
  location.reload();
}

let started = false;
function boot() {
  const em = LS.getItem('sn_session');
  const u = em && users()[em];
  $('#auth').classList.toggle('hidden', !!u);
  $('#app').classList.toggle('hidden', !u);
  if (u) {
    $('#who').textContent = u.name;
    if (!started) {
      started = true;
      startApp();
    }
  }
}

/* ---------- live data ---------- */
const PROBES = [
  'https://www.cloudflare.com/cdn-cgi/trace',
'https://dns.google/resolve?name=example.com',
'https://www.google.com/generate_204',
'https://api.github.com/zen'
];
let pi = 0, net = {};

function startApp() {
  $$('.tab').forEach(b => {
    b.onclick = () => {
      $$('.tab').forEach(x => x.classList.toggle('on', x === b));
      $$('.view').forEach(v => v.classList.toggle('hidden', v.id !== 'v-' + b.dataset.tab));
      requestAnimationFrame(() => setTimeout(draw, 40));
    };
  });
  
  try {
    new PerformanceObserver(l => {
      if (S.on) l.getEntries().forEach(ingest);
    }).observe({ type: 'resource' });
  } catch {}
  
  fetch(PROBES[0], { cache: 'no-store' })
  .then(r => r.text())
  .then(t => {
    net.trace = Object.fromEntries(t.trim().split('\n').map(l => l.split('=')));
    vitals();
  })
  .catch(() => {});
  
  setInterval(probe, 2000);
  setInterval(vitals, 3000);
  setInterval(draw, 1000);
  
  navigator.getBattery?.().then(b => { net.bat = b; vitals(); });
  addEventListener('online', vitals);
  addEventListener('offline', vitals);
  
  renderRules();
  vitals();
  probe();
}

function probe() {
  if (!S.on) return;
  const u = PROBES[pi++ % PROBES.length];
  fetch(u + (u.includes('?') ? '&' : '?') + '_=' + Date.now(), {
    mode: 'no-cors',
    cache: 'no-store'
  }).catch(() => {
    push({
      host: new URL(u).host,
         type: 'fetch',
         proto: '—',
         bytes: 0,
         dur: 0,
         url: u,
         fail: true
    });
  });
}

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
  f.score = f.fail ? 1 : +Math.min(1, 0.1 + z / 5).toFixed(2);
  
  const rule = S.rules.find(r =>
  r.field === 'host' ? f.host.includes(r.val) : f[r.field] > Number(r.val)
  );
  f.tag = f.tag || (f.fail ? 'Request failed' : rule ? rule.name : '');
  
  f.status =
  f.score >= S.thr + 0.15 || f.tag ? 'HIGH' :
  f.score >= S.thr ? 'SUSPICIOUS' : 'NORMAL';
  
  if (!f.sim && !f.fail) {
    S.base.push(f.dur);
    if (S.base.length > 40) S.base.shift();
    
    // store the SCORE (not duration) for the overview chart
    S.lat.push(f.score);
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

function setThr(v) {
  S.thr = +v;
  $('#thr-v').textContent = v;
}

/* ---------- views ---------- */
const med = a => {
  if (!a.length) return 0;
  const s = [...a].sort((x, y) => x - y);
  return s[s.length >> 1];
};

function vitals() {
  const c = navigator.connection || {};
  const h = performance.memory;
  const t = net.trace || {};
  const b = net.bat;
  
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
  
  // KPI now shows median anomaly score
  $('#k-lat').textContent = S.lat.length ? med(S.lat).toFixed(2) : '–';
  
  const top = Object.entries(S.hosts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  const mx = top[0]?.[1] || 1;
  $('#hosts').innerHTML = top
  .map(([h, n]) => `<li><span>${esc(h)}</span><i style="width:${n / mx * 100}%"></i>${n}</li>`)
  .join('') || '<li class="muted">Waiting for traffic…</li>';
  
  const { n, m, sd } = stats();
  $('#b-mean').textContent = n ? m.toFixed(0) + ' ms' : '–';
  $('#b-sd').textContent = n ? sd.toFixed(0) + ' ms' : '–';
  $('#b-n').textContent = n;
  
  // Overview chart → anomaly scores
  line($('#c-score'), S.lat);
  
  // Detection page chart
  scatter($('#c-sc'));
  
  renderTable();
  renderBlocked();
}

function renderTable() {
  const q = $('#q').value.toLowerCase();
  const s = $('#sev').value;
  $('#tbody').innerHTML = S.flows
  .filter(f => (s === 'ALL' || f.status === s) && (f.host + f.type + f.tag).toLowerCase().includes(q))
  .slice(0, 25)
  .map(f => `
  <tr>
  <td>${f.time}</td>
  <td>${esc(f.host)}</td>
  <td>${esc(f.type)}</td>
  <td>${esc(f.proto)}</td>
  <td>${f.bytes.toLocaleString()}</td>
  <td>${f.dur}</td>
  <td class="${f.status}">${f.score}</td>
  <td><span class="tag ${f.status}">${f.status === 'HIGH' ? 'CRITICAL' : f.status}${f.sim ? ' · SIM' : ''}</span></td>
  <td><button class="ghost" onclick="inspect('${f.id}')">Inspect</button></td>
  </tr>`).join('');
}

function inspect(id) {
  const f = S.flows.find(x => x.id === id);
  if (!f) return;
  $('#modal-body').innerHTML = `
  <h3>${esc(f.host)}</h3>
  <p class="muted">${f.id} · ${f.time}${f.sim ? ' · simulated event' : ''}</p>
  <pre>${esc(JSON.stringify(f, null, 2))}</pre>`;
  $('#modal').showModal();
}

function alertItem(f) {
  const a = $('#alerts');
  if (a.querySelector('p')) a.innerHTML = '';
  const d = document.createElement('div');
  d.className = 'alert';
  d.innerHTML = `
  <b>${esc(f.tag || 'Anomalous timing')}</b> · ${esc(f.host)}<br>
  <small style="margin:0">${f.time} · score ${f.score}</small><br>
  <button class="ghost" onclick="block('${esc(f.host)}','${esc(f.tag || 'Anomaly')}')">Block host</button>`;
  a.prepend(d);
  while (a.children.length > 8) a.lastChild.remove();
}

function block(host, reason) {
  if (S.blocked.some(b => b.host === host)) return;
  S.blocked.push({ host, reason, hosts: `0.0.0.0 ${host}` });
  renderBlocked();
}

function renderBlocked() {
  if (!S.blocked.length) return;
  $('#qbody').innerHTML = S.blocked.map(b => `
  <tr>
  <td>${esc(b.host)}</td>
  <td>${esc(b.reason)}</td>
  <td>${esc(b.hosts)}</td>
  <td><span class="tag HIGH">LISTED</span></td>
  </tr>`).join('');
}

function exportReport() {
  const a = document.createElement('a');
  a.href = 'data:application/json,' + encodeURIComponent(JSON.stringify(S.blocked, null, 2));
  a.download = 'sentinel_report.json';
  a.click();
}

function addRule(e) {
  e.preventDefault();
  S.rules.push({
    id: 'R-' + (S.rules.length + 1),
               name: $('#r-name').value,
               field: $('#r-field').value,
               val: $('#r-val').value
  });
  e.target.reset();
  renderRules();
}

function renderRules() {
  const L = { dur: 'time (ms) >', bytes: 'bytes >', host: 'host contains' };
  $('#rbody').innerHTML = S.rules.map(r => `
  <tr>
  <td>${r.id}</td>
  <td>${esc(r.name)}</td>
  <td>${L[r.field]} ${esc(r.val)}</td>
  <td><button class="ghost" onclick="S.rules=S.rules.filter(x=>x.id!=='${r.id}');renderRules()">Remove</button></td>
  </tr>`).join('');
}

/* ---------- canvas charts ---------- */
const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

function setup(c, fixedH = 210) {
  if (!c) return null;
  
  c.style.width = '100%';
  c.style.height = fixedH + 'px';
  c.style.maxHeight = fixedH + 'px';
  c.style.display = 'block';
  
  const r = window.devicePixelRatio || 1;
  const w = Math.max(c.clientWidth || 400, 300);
  const h = fixedH;
  
  if (c.width !== Math.floor(w * r) || c.height !== Math.floor(h * r)) {
    c.width = Math.floor(w * r);
    c.height = Math.floor(h * r);
  }
  
  const x = c.getContext('2d');
  x.setTransform(r, 0, 0, r, 0, 0);
  x.clearRect(0, 0, w, h);
  x.font = '11px "IBM Plex Mono", monospace';
  return { x, w, h };
}

// Overview – Anomaly Score line chart (0 → 1)
function line(c, d) {
  if (!c) return;
  const s = setup(c, 210);
  if (!s) return;
  const { x, w, h } = s;
  const p = 32;
  
  x.strokeStyle = css('--line');
  x.fillStyle = css('--fade');
  
  // fixed scale 0 → 1
  const mx = 1.05;
  for (let i = 0; i <= 4; i++) {
    const y = h - p - ((h - p - 8) * i) / 4;
    x.beginPath();
    x.moveTo(p + 8, y);
    x.lineTo(w - 4, y);
    x.stroke();
    x.fillText((i / 4).toFixed(1), 2, y + 4);
  }
  
  if (d.length < 2) {
    x.fillText('Collecting scores…', p + 20, h / 2);
    return;
  }
  
  x.beginPath();
  d.forEach((v, i) => {
    const X = p + 8 + ((w - p - 16) * i) / Math.max(59, d.length - 1);
    const Y = h - p - ((h - p - 8) * v) / mx;
    i ? x.lineTo(X, Y) : x.moveTo(X, Y);
  });
  x.strokeStyle = css('--brown');
  x.lineWidth = 2.2;
  x.stroke();
}

// Detection page – Score Distribution histogram
function scatter(c) {
  if (!c) return;
  const s = setup(c, 260);
  if (!s) return;
  const { x, w, h } = s;
  
  const pad = { top: 20, right: 14, bottom: 38, left: 36 };
  const plotW = w - pad.left - pad.right;
  const plotH = h - pad.top - pad.bottom;
  
  const buckets = [0, 0, 0, 0, 0];
  const labels = ['0.0–0.2', '0.2–0.4', '0.4–0.6', '0.6–0.8', '0.8–1.0'];
  
  S.flows.slice(0, 150).forEach(f => {
    const score = Math.min(1, Math.max(0, f.score || 0));
    const idx = Math.min(4, Math.floor(score * 5));
    buckets[idx]++;
  });
  
  const maxCount = Math.max(1, ...buckets);
  
  x.strokeStyle = css('--line');
  x.fillStyle = css('--fade');
  
  for (let i = 0; i <= 4; i++) {
    const y = pad.top + (plotH * i) / 4;
    x.beginPath();
    x.moveTo(pad.left, y);
    x.lineTo(w - pad.right, y);
    x.stroke();
    x.fillText(Math.round(maxCount * (1 - i / 4)), 4, y + 4);
  }
  
  const gap = 12;
  const barW = (plotW - gap * 4) / 5;
  
  buckets.forEach((count, i) => {
    const barH = (count / maxCount) * plotH;
    const X = pad.left + i * (barW + gap);
    const Y = pad.top + plotH - barH;
    
    let color = css('--ok');
    if (i === 3) color = css('--warn');
    if (i === 4) color = css('--bad');
    
    x.fillStyle = color;
    x.globalAlpha = 0.85;
    x.fillRect(X, Y, barW, barH);
    x.globalAlpha = 1;
    
    if (count > 0) {
      x.fillStyle = css('--ink');
      x.fillText(count, X + barW / 2 - 5, Y - 6);
    }
    
    x.fillStyle = css('--fade');
    x.fillText(labels[i], X, h - 12);
  });
  
  if (S.flows.length === 0) {
    x.fillStyle = css('--fade');
    x.fillText('Waiting for traffic…', pad.left + 20, h / 2);
  }
}

addEventListener('resize', () => requestAnimationFrame(draw));
boot();
