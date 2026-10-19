/* SentinelAI — Core SOC & AI Engine Logic */

// Global State
let streamActive = true;
let sensitivityThreshold = 0.65;
let flowHistory = [];
let quarantinedIPs = [];
let totalFlows = 1248;
let normalFlows = 1180;
let suspiciousFlows = 42;
let criticalFlows = 26;

// Snort-style Rule Base
let activeRules = [
    { id: 'RULE-01', name: 'SYN Flood Volumetric Pattern', proto: 'TCP', condition: 'Packets > 150 & Flags == SYN', status: 'ACTIVE' },
    { id: 'RULE-02', name: 'SSH Brute Force Attempt', proto: 'TCP', condition: 'Port == 22 & Packets > 40', status: 'ACTIVE' },
    { id: 'RULE-03', name: 'DNS Tunneling Exfiltration', proto: 'UDP', condition: 'Port == 53 & Bytes > 1500', status: 'ACTIVE' }
];

// Initialize on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
    lucide.createIcons();
    initPlots();
    initTopologyCanvas();
    startTelemetryStream();
});

// Navigation Tab Switcher
function switchTab(tabId) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.add('hidden'));
    document.querySelectorAll('.nav-tab').forEach(el => el.classList.remove('active-tab', 'text-slate-100'));
    
    document.getElementById(`view-${tabId}`).classList.remove('hidden');
    const activeBtn = document.getElementById(`tab-${tabId}`);
    activeBtn.classList.add('active-tab');
}

// Telemetry Generator
function startTelemetryStream() {
    setInterval(() => {
        if (!streamActive) return;
        
        const flow = generateRandomFlow();
        processFlow(flow);
    }, 1200);
}

function toggleStream() {
    streamActive = !streamActive;
    const statusText = document.getElementById('stream-status');
    const btnText = document.getElementById('stream-btn-text');
    const icon = document.getElementById('stream-icon');
    
    if (streamActive) {
        statusText.innerText = 'ACTIVE';
        statusText.className = 'text-emerald-400';
        btnText.innerText = 'Pause Stream';
        icon.setAttribute('data-lucide', 'pause');
    } else {
        statusText.innerText = 'PAUSED';
        statusText.className = 'text-amber-400';
        btnText.innerText = 'Resume Stream';
        icon.setAttribute('data-lucide', 'play');
    }
    lucide.createIcons();
}

function generateRandomFlow(forcedAttackType = null) {
    const ips = ['192.168.1.105', '192.168.1.112', '10.0.4.22', '172.16.0.8'];
    const externalIps = ['185.220.101.5', '45.33.32.156', '198.51.100.42', '203.0.113.195'];
    const protos = ['TCP', 'UDP'];
    
    let proto = protos[Math.floor(Math.random() * protos.length)];
    let srcIp = externalIps[Math.floor(Math.random() * externalIps.length)];
    let dstIp = ips[Math.floor(Math.random() * ips.length)];
    let dstPort = [80, 443, 22, 53, 8080][Math.floor(Math.random() * 5)];
    let packets = Math.floor(Math.random() * 30) + 2;
    let bytes = packets * (Math.floor(Math.random() * 200) + 64);
    let attackTag = 'NORMAL';

    if (forcedAttackType === 'syn_flood' || (!forcedAttackType && Math.random() < 0.15)) {
        proto = 'TCP';
        packets = Math.floor(Math.random() * 300) + 150;
        bytes = packets * 60;
        attackTag = 'SYN Flood Attack';
    } else if (forcedAttackType === 'port_scan') {
        dstPort = Math.floor(Math.random() * 1000) + 20;
        packets = 2;
        bytes = 120;
        attackTag = 'Port Scan';
    } else if (forcedAttackType === 'ssh_brute') {
        dstPort = 22;
        packets = Math.floor(Math.random() * 80) + 40;
        attackTag = 'SSH Brute Force';
    } else if (forcedAttackType === 'c2_beacon') {
        dstPort = 443;
        packets = 12;
        bytes = 4500;
        attackTag = 'C2 Beaconing';
    }

    // AI Anomaly Math Scoring
    const zRate = Math.min(1.0, packets / 250);
    const zBytes = Math.min(1.0, bytes / 10000);
    const anomalyScore = parseFloat((zRate * 0.5 + zBytes * 0.3 + Math.random() * 0.2).toFixed(2));

    let status = 'NORMAL';
    if (anomalyScore >= sensitivityThreshold + 0.15 || attackTag !== 'NORMAL') {
        status = 'HIGH';
    } else if (anomalyScore >= sensitivityThreshold) {
        status = 'SUSPICIOUS';
    }

    return {
        id: 'FL-' + Math.floor(Math.random() * 90000 + 10000),
        time: new Date().toLocaleTimeString(),
        srcIp, dstIp, proto, dstPort, packets, bytes,
        score: anomalyScore, status, attackTag
    };
}

function processFlow(flow) {
    totalFlows++;
    if (flow.status === 'NORMAL') normalFlows++;
    else if (flow.status === 'SUSPICIOUS') suspiciousFlows++;
    else criticalFlows++;

    // Update KPIs
    document.getElementById('kpi-total-flows').innerText = totalFlows.toLocaleString();
    document.getElementById('kpi-normal-flows').innerText = normalFlows.toLocaleString();
    document.getElementById('kpi-suspicious-flows').innerText = suspiciousFlows.toLocaleString();
    document.getElementById('kpi-critical-flows').innerText = criticalFlows.toLocaleString();

    // Store in history
    flowHistory.unshift(flow);
    if (flowHistory.length > 50) flowHistory.pop();

    renderTelemetryTable();
    if (flow.status === 'HIGH') addAlertFeedItem(flow);
}

function renderTelemetryTable() {
    const tbody = document.getElementById('telemetry-table-body');
    if (!tbody) return;

    tbody.innerHTML = flowHistory.slice(0, 8).map(f => {
        let statusBadge = `<span class="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">NORMAL</span>`;
        if (f.status === 'SUSPICIOUS') statusBadge = `<span class="px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/20">SUSPICIOUS</span>`;
        if (f.status === 'HIGH') statusBadge = `<span class="px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/20">CRITICAL</span>`;

        return `
            <tr class="hover:bg-slate-900/50 transition">
                <td class="p-3 text-slate-400">${f.time}</td>
                <td class="p-3 font-semibold text-slate-200">${f.srcIp}</td>
                <td class="p-3 text-slate-400">${f.dstIp}</td>
                <td class="p-3 text-slate-300">${f.proto}</td>
                <td class="p-3 text-slate-300">${f.dstPort}</td>
                <td class="p-3 text-slate-300">${f.packets}</td>
                <td class="p-3 text-slate-300">${f.bytes.toLocaleString()}</td>
                <td class="p-3 font-bold ${f.score > 0.65 ? 'text-rose-400' : 'text-emerald-400'}">${f.score}</td>
                <td class="p-3">${statusBadge}</td>
                <td class="p-3 text-right">
                    <button onclick='inspectFlow(${JSON.stringify(f)})' class="px-2 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-[11px] border border-slate-700">
                        Inspect
                    </button>
                </td>
            </tr>
        `;
    }).join('');
}

function addAlertFeedItem(f) {
    const feed = document.getElementById('alert-feed');
    if (!feed) return;

    const item = document.createElement('div');
    item.className = 'p-2.5 rounded bg-rose-950/30 border border-rose-800/40 space-y-1';
    item.innerHTML = `
        <div class="flex justify-between font-bold text-rose-400">
            <span>🚨 ${f.attackTag}</span>
            <span class="text-[10px] text-slate-400">${f.time}</span>
        </div>
        <p class="text-slate-300">SRC: <strong class="text-slate-100">${f.srcIp}</strong> -> DST Port: ${f.dstPort}</p>
        <div class="flex justify-between items-center pt-1">
            <span class="text-[10px] text-rose-300">Score: ${f.score}</span>
            <button onclick="quarantineIP('${f.srcIp}', '${f.attackTag}')" class="px-2 py-0.5 bg-rose-600 hover:bg-rose-500 text-slate-950 font-bold rounded text-[10px]">
                Quarantine IP
            </button>
        </div>
    `;
    feed.prepend(item);
    if (feed.children.length > 5) feed.removeChild(feed.lastChild);
}

function injectAttack(type) {
    const attackFlow = generateRandomFlow(type);
    processFlow(attackFlow);
}

function updateSensitivityThreshold(val) {
    sensitivityThreshold = parseFloat(val);
    document.getElementById('threshold-val-label').innerText = val;
}

function quarantineIP(ip, reason) {
    if (quarantinedIPs.some(q => q.ip === ip)) return;

    const record = {
        ip,
        reason,
        iptables: `sudo iptables -A INPUT -s ${ip} -j DROP`,
        ufw: `sudo ufw deny from ${ip}`
    };
    quarantinedIPs.push(record);
    renderQuarantineTable();
    alert(`IP ${ip} quarantined! Firewall rules generated in Incident Response tab.`);
}

function renderQuarantineTable() {
    const tbody = document.getElementById('quarantine-table-body');
    if (!tbody) return;

    tbody.innerHTML = quarantinedIPs.map(q => `
        <tr class="hover:bg-slate-900/50">
            <td class="p-3 text-rose-400 font-bold">${q.ip}</td>
            <td class="p-3 text-slate-300">${q.reason}</td>
            <td class="p-3 text-slate-400 text-[11px] font-mono bg-slate-950 rounded">${q.iptables}</td>
            <td class="p-3 text-slate-400 text-[11px] font-mono bg-slate-950 rounded">${q.ufw}</td>
            <td class="p-3 text-right">
                <span class="px-2 py-0.5 bg-rose-500/10 text-rose-400 border border-rose-500/20 rounded">ENFORCED</span>
            </td>
        </tr>
    `).join('');
}

// Plotly Initialization
function initPlots() {
    Plotly.newPlot('chart-flow-rate', [{
        y: [12, 18, 15, 24, 30, 85, 40, 22, 19, 25],
        type: 'scatter',
        mode: 'lines+markers',
        line: { color: '#10b981', width: 2 },
        marker: { color: '#34d399', size: 6 }
    }], {
        margin: { t: 10, r: 10, l: 30, b: 30 },
        paper_bgcolor: 'transparent',
        plot_bgcolor: 'transparent',
        xaxis: { color: '#64748b', gridcolor: '#1e293b' },
        yaxis: { color: '#64748b', gridcolor: '#1e293b' }
    }, { responsive: true });

    Plotly.newPlot('chart-threat-pie', [{
        values: [75, 12, 8, 5],
        labels: ['Normal Traffic', 'SYN Floods', 'Port Scans', 'Brute Force'],
        type: 'pie',
        marker: { colors: ['#10b981', '#f43f5e', '#f59e0b', '#a855f7'] }
    }], {
        margin: { t: 10, r: 10, l: 10, b: 10 },
        paper_bgcolor: 'transparent',
        legend: { font: { color: '#94a3b8' } }
    }, { responsive: true });

    Plotly.newPlot('chart-scatter-space', [{
        x: [10, 25, 15, 30, 220, 180, 15, 28],
        y: [500, 1200, 800, 1500, 15000, 12000, 700, 950],
        mode: 'markers',
        type: 'scatter',
        marker: {
            size: 10,
            color: ['#10b981', '#10b981', '#10b981', '#10b981', '#f43f5e', '#f43f5e', '#10b981', '#10b981']
        }
    }], {
        margin: { t: 10, r: 10, l: 40, b: 30 },
        paper_bgcolor: 'transparent',
        plot_bgcolor: 'transparent',
        xaxis: { title: 'Packet Count', color: '#64748b', gridcolor: '#1e293b' },
        yaxis: { title: 'Total Bytes', color: '#64748b', gridcolor: '#1e293b' }
    }, { responsive: true });
}

// Topology Canvas Animation
function initTopologyCanvas() {
    const canvas = document.getElementById('topology-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');

    function resize() {
        canvas.width = canvas.parentElement.clientWidth;
        canvas.height = canvas.parentElement.clientHeight;
    }
    resize();
    window.addEventListener('resize', resize);

    const nodes = [
        { x: 0.2, y: 0.5, label: 'Gateway Router', type: 'gw' },
        { x: 0.5, y: 0.3, label: 'Web Server (192.168.1.10)', type: 'int' },
        { x: 0.5, y: 0.7, label: 'DB Server (192.168.1.20)', type: 'int' },
        { x: 0.85, y: 0.4, label: 'Threat Node (185.220.101.5)', type: 'ext' }
    ];

    function draw() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        // Draw Links
        ctx.strokeStyle = '#334155';
        ctx.lineWidth = 1.5;
        nodes.forEach((n1, i) => {
            nodes.forEach((n2, j) => {
                if (i < j) {
                    ctx.beginPath();
                    ctx.moveTo(n1.x * canvas.width, n1.y * canvas.height);
                    ctx.lineTo(n2.x * canvas.width, n2.y * canvas.height);
                    ctx.stroke();
                }
            });
        });

        // Draw Nodes
        nodes.forEach(n => {
            const cx = n.x * canvas.width;
            const cy = n.y * canvas.height;

            ctx.beginPath();
            ctx.arc(cx, cy, 10, 0, Math.PI * 2);
            ctx.fillStyle = n.type === 'ext' ? '#f43f5e' : (n.type === 'gw' ? '#3b82f6' : '#10b981');
            ctx.fill();
            ctx.strokeStyle = '#0f172a';
            ctx.lineWidth = 2;
            ctx.stroke();

            ctx.fillStyle = '#94a3b8';
            ctx.font = '10px monospace';
            ctx.fillText(n.label, cx - 40, cy + 22);
        });

        requestAnimationFrame(draw);
    }
    draw();
}

// Modal Helpers
function openModal(id) {
    document.getElementById(id).classList.remove('hidden');
}

function closeModal(id) {
    document.getElementById(id).classList.add('hidden');
}

function inspectFlow(f) {
    const modalContent = document.getElementById('modal-flow-content');
    modalContent.innerHTML = `
        <div class="bg-slate-950 p-3 rounded border border-slate-800 space-y-1">
            <p><strong class="text-slate-300">Flow ID:</strong> ${f.id} | <strong class="text-slate-300">Time:</strong> ${f.time}</p>
            <p><strong class="text-slate-300">Connection:</strong> ${f.srcIp} -> ${f.dstIp}:${f.dstPort} (${f.proto})</p>
            <p><strong class="text-slate-300">Volume:</strong> ${f.packets} packets (${f.bytes} bytes)</p>
            <p><strong class="text-slate-300">Anomaly Score:</strong> <span class="text-rose-400 font-bold">${f.score}</span></p>
        </div>
        <div>
            <h4 class="text-xs font-semibold text-slate-300 mb-1">Simulated Packet Hex Dump</h4>
            <pre class="bg-slate-950 p-2.5 rounded text-[11px] text-emerald-400 font-mono border border-slate-800">
0000  45 00 00 3c 1c 46 40 00  40 06 b1 e6 c0 a8 01 69  E..<.@.@......i
0010  c0 a8 01 01 00 16 00 50  00 00 00 00 00 00 00 00  .......P........
0020  a0 02 72 10 91 1e 00 00  02 04 05 b4 04 02 08 0a  ..r.............
            </pre>
        </div>
    `;
    openModal('modal-flow-inspect');
}

function addCustomRule(e) {
    e.preventDefault();
    const name = document.getElementById('rule-name').value;
    const proto = document.getElementById('rule-proto').value;
    const port = document.getElementById('rule-port').value || 'ANY';
    const pkts = document.getElementById('rule-packets').value || '0';

    activeRules.push({
        id: 'RULE-0' + (activeRules.length + 1),
        name,
        proto,
        condition: `Port == ${port} & Packets > ${pkts}`,
        status: 'ACTIVE'
    });

    renderRulesTable();
    e.target.reset();
    alert('Rule added successfully!');
}

function renderRulesTable() {
    const tbody = document.getElementById('rules-table-body');
    if (!tbody) return;

    tbody.innerHTML = activeRules.map(r => `
        <tr class="hover:bg-slate-900/50">
            <td class="p-2.5 font-bold text-slate-300">${r.id}</td>
            <td class="p-2.5 text-slate-200">${r.name}</td>
            <td class="p-2.5 text-slate-400">${r.proto}</td>
            <td class="p-2.5 text-emerald-400 font-mono">${r.condition}</td>
            <td class="p-2.5"><span class="px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 text-[10px]">ACTIVE</span></td>
        </tr>
    `).join('');
}

function downloadReport() {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(quarantinedIPs, null, 2));
    const dlAnchorElem = document.createElement('a');
    dlAnchorElem.setAttribute("href", dataStr);
    dlAnchorElem.setAttribute("download", "sentinel_ai_incident_report.json");
    dlAnchorElem.click();
}