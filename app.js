/* SentinelAI — Light Theme SOC & Plotly Logic */

let streamActive = true;
let sensitivityThreshold = 0.65;
let flowHistory = [];
let quarantinedIPs = [];
let totalFlows = 1248;
let normalFlows = 1180;
let suspiciousFlows = 42;
let criticalFlows = 26;

let activeRules = [
    { id: 'RULE-01', name: 'SYN Flood Volumetric Pattern', proto: 'TCP', condition: 'Packets > 150 & Flags == SYN', status: 'ACTIVE' },
    { id: 'RULE-02', name: 'SSH Brute Force Attempt', proto: 'TCP', condition: 'Port == 22 & Packets > 40', status: 'ACTIVE' },
    { id: 'RULE-03', name: 'DNS Tunneling Exfiltration', proto: 'UDP', condition: 'Port == 53 & Bytes > 1500', status: 'ACTIVE' }
];

document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
    initPlots();
    initTopologyCanvas();
    startTelemetryStream();
    renderRulesTable();
});

function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
    document.querySelectorAll('.nav-tab').forEach(el => el.classList.remove('active-tab'));
    
    document.getElementById(`view-${tabId}`).classList.remove('hidden');
    document.getElementById(`tab-${tabId}`).classList.add('active-tab');
}

function startTelemetryStream() {
    setInterval(() => {
        if (!streamActive) return;
        processFlow(generateRandomFlow());
    }, 1200);
}

function toggleStream() {
    streamActive = !streamActive;
    document.getElementById('stream-status').innerText = streamActive ? 'ACTIVE' : 'PAUSED';
}

function generateRandomFlow(forcedType = null) {
    const ips = ['192.168.1.105', '192.168.1.112', '10.0.4.22'];
    const extIps = ['185.220.101.5', '45.33.32.156', '198.51.100.42'];
    
    let proto = 'TCP';
    let srcIp = extIps[Math.floor(Math.random() * extIps.length)];
    let dstIp = ips[Math.floor(Math.random() * ips.length)];
    let dstPort = [80, 443, 22, 53][Math.floor(Math.random() * 4)];
    let packets = Math.floor(Math.random() * 30) + 2;
    let bytes = packets * 120;
    let attackTag = 'NORMAL';

    if (forcedType === 'syn_flood' || (!forcedType && Math.random() < 0.15)) {
        packets = Math.floor(Math.random() * 300) + 150;
        attackTag = 'SYN Flood Attack';
    } else if (forcedType === 'port_scan') {
        dstPort = Math.floor(Math.random() * 1000) + 20;
        attackTag = 'Port Scan';
    } else if (forcedType === 'ssh_brute') {
        dstPort = 22;
        packets = 60;
        attackTag = 'SSH Brute Force';
    }

    const score = parseFloat(Math.min(1.0, (packets / 250) + Math.random() * 0.2).toFixed(2));
    let status = score >= sensitivityThreshold ? (score > 0.8 ? 'HIGH' : 'SUSPICIOUS') : 'NORMAL';

    return {
        id: 'FL-' + Math.floor(Math.random() * 90000 + 10000),
        time: new Date().toLocaleTimeString(),
        srcIp, dstIp, proto, dstPort, packets, bytes,
        score, status, attackTag
    };
}

function processFlow(flow) {
    totalFlows++;
    if (flow.status === 'NORMAL') normalFlows++;
    else if (flow.status === 'SUSPICIOUS') suspiciousFlows++;
    else criticalFlows++;

    document.getElementById('kpi-total-flows').innerText = totalFlows.toLocaleString();
    document.getElementById('kpi-normal-flows').innerText = normalFlows.toLocaleString();
    document.getElementById('kpi-suspicious-flows').innerText = suspiciousFlows.toLocaleString();
    document.getElementById('kpi-critical-flows').innerText = criticalFlows.toLocaleString();

    flowHistory.unshift(flow);
    if (flowHistory.length > 30) flowHistory.pop();

    renderTelemetryTable();
    if (flow.status === 'HIGH') addAlertFeedItem(flow);
}

function renderTelemetryTable() {
    const tbody = document.getElementById('telemetry-table-body');
    if (!tbody) return;

    tbody.innerHTML = flowHistory.slice(0, 7).map(f => `
        <tr class="hover:bg-slate-50">
            <td class="p-3 text-slate-500">${f.time}</td>
            <td class="p-3 font-semibold text-slate-800">${f.srcIp}</td>
            <td class="p-3 text-slate-500">${f.dstIp}</td>
            <td class="p-3 text-slate-600">${f.proto}</td>
            <td class="p-3 text-slate-600">${f.dstPort}</td>
            <td class="p-3 text-slate-600">${f.packets}</td>
            <td class="p-3 text-slate-600">${f.bytes}</td>
            <td class="p-3 font-bold ${f.score > 0.65 ? 'text-rose-600' : 'text-emerald-600'}">${f.score}</td>
            <td class="p-3"><span class="px-2 py-0.5 rounded text-[11px] font-semibold ${f.status === 'HIGH' ? 'bg-rose-100 text-rose-700' : (f.status === 'SUSPICIOUS' ? 'bg-amber-100 text-amber-700' : 'bg-emerald-100 text-emerald-700')}">${f.status}</span></td>
            <td class="p-3 text-right">
                <button onclick='inspectFlow(${JSON.stringify(f)})' class="px-2 py-1 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded text-[11px] border border-slate-300">Inspect</button>
            </td>
        </tr>
    `).join('');
}

function addAlertFeedItem(f) {
    const feed = document.getElementById('alert-feed');
    if (!feed) return;

    const item = document.createElement('div');
    item.className = 'p-2.5 rounded bg-rose-50 border border-rose-200 space-y-1';
    item.innerHTML = `
        <div class="flex justify-between font-bold text-rose-700">
            <span>🚨 ${f.attackTag}</span>
            <span class="text-[10px] text-slate-500">${f.time}</span>
        </div>
        <p class="text-slate-700 text-[11px]">SRC: ${f.srcIp} -> Port: ${f.dstPort}</p>
        <button onclick="quarantineIP('${f.srcIp}', '${f.attackTag}')" class="mt-1 px-2 py-0.5 bg-rose-600 hover:bg-rose-700 text-white font-semibold rounded text-[10px] shadow-sm">Quarantine IP</button>
    `;
    feed.prepend(item);
    if (feed.children.length > 4) feed.removeChild(feed.lastChild);
}

function injectAttack(type) {
    processFlow(generateRandomFlow(type));
}

function updateSensitivityThreshold(val) {
    sensitivityThreshold = parseFloat(val);
    document.getElementById('threshold-val-label').innerText = val;
}

function quarantineIP(ip, reason) {
    if (quarantinedIPs.some(q => q.ip === ip)) return;
    quarantinedIPs.push({
        ip, reason,
        iptables: `sudo iptables -A INPUT -s ${ip} -j DROP`,
        ufw: `sudo ufw deny from ${ip}`
    });
    renderQuarantineTable();
    alert(`IP ${ip} Quarantined!`);
}

function renderQuarantineTable() {
    const tbody = document.getElementById('quarantine-table-body');
    if (!tbody) return;
    tbody.innerHTML = quarantinedIPs.map(q => `
        <tr class="hover:bg-slate-50">
            <td class="p-3 text-rose-600 font-bold">${q.ip}</td>
            <td class="p-3 text-slate-700">${q.reason}</td>
            <td class="p-3 text-slate-600 font-mono bg-slate-50 rounded">${q.iptables}</td>
            <td class="p-3 text-slate-600 font-mono bg-slate-50 rounded">${q.ufw}</td>
            <td class="p-3 text-right"><span class="px-2 py-0.5 bg-rose-100 text-rose-700 rounded font-semibold text-[10px]">ENFORCED</span></td>
        </tr>
    `).join('');
}

function renderRulesTable() {
    const tbody = document.getElementById('rules-table-body');
    if (!tbody) return;
    tbody.innerHTML = activeRules.map(r => `
        <tr class="hover:bg-slate-50">
            <td class="p-2.5 font-bold text-slate-700">${r.id}</td>
            <td class="p-2.5 text-slate-800">${r.name}</td>
            <td class="p-2.5 text-slate-600">${r.proto}</td>
            <td class="p-2.5 text-emerald-700 font-mono">${r.condition}</td>
            <td class="p-2.5"><span class="px-2 py-0.5 bg-emerald-100 text-emerald-700 rounded font-semibold text-[10px]">ACTIVE</span></td>
        </tr>
    `).join('');
}

function initPlots() {
    Plotly.newPlot('chart-flow-rate', [{
        y: [12, 18, 15, 24, 30, 85, 40, 22, 19, 25],
        type: 'scatter', mode: 'lines+markers',
        line: { color: '#0284c7', width: 2 },
        marker: { color: '#0369a1', size: 6 }
    }], {
        margin: { t: 10, r: 10, l: 30, b: 30 },
        paper_bgcolor: 'transparent', plot_bgcolor: 'transparent',
        xaxis: { color: '#64748b', gridcolor: '#f1f5f9' },
        yaxis: { color: '#64748b', gridcolor: '#f1f5f9' }
    }, { responsive: true });

    Plotly.newPlot('chart-threat-pie', [{
        values: [75, 12, 8, 5],
        labels: ['Normal', 'SYN Floods', 'Port Scans', 'Brute Force'],
        type: 'pie',
        marker: { colors: ['#10b981', '#ef4444', '#f59e0b', '#8b5cf6'] }
    }], {
        margin: { t: 10, r: 10, l: 10, b: 10 },
        paper_bgcolor: 'transparent',
        legend: { font: { color: '#475569' } }
    }, { responsive: true });

    Plotly.newPlot('chart-scatter-space', [{
        x: [10, 25, 15, 30, 220, 180],
        y: [500, 1200, 800, 1500, 15000, 12000],
        mode: 'markers', type: 'scatter',
        marker: { size: 10, color: ['#10b981', '#10b981', '#10b981', '#10b981', '#ef4444', '#ef4444'] }
    }], {
        margin: { t: 10, r: 10, l: 40, b: 30 },
        paper_bgcolor: 'transparent', plot_bgcolor: 'transparent',
        xaxis: { title: 'Packet Count', color: '#64748b', gridcolor: '#f1f5f9' },
        yaxis: { title: 'Total Bytes', color: '#64748b', gridcolor: '#f1f5f9' }
    }, { responsive: true });
}

function initTopologyCanvas() {
    const canvas = document.getElementById('topology-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    canvas.width = canvas.parentElement.clientWidth;
    canvas.height = canvas.parentElement.clientHeight;

    ctx.fillStyle = '#0284c7';
    ctx.beginPath();
    ctx.arc(canvas.width / 2, canvas.height / 2, 12, 0, Math.PI * 2);
    ctx.fill();
}

function openModal(id) { document.getElementById(id).classList.remove('hidden'); }
function closeModal(id) { document.getElementById(id).classList.add('hidden'); }

function inspectFlow(f) {
    document.getElementById('modal-flow-content').innerHTML = `
        <p>Flow ID: ${f.id} | Score: ${f.score}</p>
        <p>SRC: ${f.srcIp} -> DST: ${f.dstIp}:${f.dstPort}</p>
        <pre class="bg-slate-100 p-2 text-slate-800 font-mono mt-2 border border-slate-200 rounded">
0000  45 00 00 3c 1c 46 40 00  40 06 b1 e6 c0 a8 01 69
0010  c0 a8 01 01 00 16 00 50  00 00 00 00 00 00 00 00
        </pre>
    `;
    openModal('modal-flow-inspect');
}
