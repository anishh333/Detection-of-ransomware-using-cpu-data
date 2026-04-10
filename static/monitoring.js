/* ============================================
   Live Monitoring Page JavaScript
   ============================================ */

let isMonitoring = false;
let monitorTimer = null;
let detectionCount = 0;
let alertCount = 0;

// Chart instances
let cpuChart = null;
let diskChart = null;
let timelineChart = null;

// Data buffers
const MAX_POINTS = 60;
const cpuData = [];
const diskReadData = [];
const diskWriteData = [];
const probData = [];
const labels = [];

document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    checkStatus();
    setInterval(pollStaticLogs, 2000);
});

async function checkStatus() {
    try {
        const res = await fetch('/api/system-status');
        const data = await res.json();
        const dot = document.getElementById('systemStatusDot');
        const text = document.getElementById('systemStatusText');
        if (data.success) {
            dot.className = 'status-dot connected';
            text.textContent = 'System Online';
        }
    } catch (e) { }
}

function initCharts() {
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 300 },
        plugins: {
            legend: {
                labels: { color: '#94a3b8', font: { size: 11, family: 'Inter' } }
            }
        },
        scales: {
            x: {
                grid: { color: 'rgba(255,255,255,0.03)' },
                ticks: { color: '#64748b', font: { size: 10 }, maxTicksLimit: 10 }
            },
            y: {
                grid: { color: 'rgba(255,255,255,0.05)' },
                ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 11 } }
            }
        }
    };

    // CPU Chart
    cpuChart = new Chart(document.getElementById('liveCpuChart'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'CPU %',
                data: [],
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                borderWidth: 2,
            }]
        },
        options: { ...chartOptions, scales: { ...chartOptions.scales, y: { ...chartOptions.scales.y, min: 0, max: 100 } } }
    });

    // Disk I/O Chart
    diskChart = new Chart(document.getElementById('liveDiskChart'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                {
                    label: 'Read Ops',
                    data: [],
                    borderColor: '#10b981',
                    backgroundColor: 'rgba(16, 185, 129, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    borderWidth: 2,
                },
                {
                    label: 'Write Ops',
                    data: [],
                    borderColor: '#f59e0b',
                    backgroundColor: 'rgba(245, 158, 11, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    borderWidth: 2,
                }
            ]
        },
        options: chartOptions
    });

    // Detection Timeline Chart
    timelineChart = new Chart(document.getElementById('detectionTimeline'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Ransomware Probability',
                data: [],
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                fill: true,
                tension: 0.3,
                pointRadius: 2,
                pointBackgroundColor: '#ef4444',
                borderWidth: 2,
            }]
        },
        options: {
            ...chartOptions,
            scales: {
                ...chartOptions.scales,
                y: {
                    ...chartOptions.scales.y, min: 0, max: 1,
                    ticks: { ...chartOptions.scales.y.ticks, callback: v => (v * 100).toFixed(0) + '%' }
                }
            },
            plugins: {
                ...chartOptions.plugins,
                annotation: {
                    annotations: {
                        threshold: {
                            type: 'line',
                            yMin: 0.5,
                            yMax: 0.5,
                            borderColor: 'rgba(239, 68, 68, 0.5)',
                            borderWidth: 1,
                            borderDash: [5, 5],
                        }
                    }
                }
            }
        }
    });
}

function toggleMonitoring() {
    const btn = document.getElementById('btnStartMonitor');
    const icon = document.getElementById('monitorIcon');
    const text = document.getElementById('monitorBtnText');

    if (isMonitoring) {
        isMonitoring = false;
        clearInterval(monitorTimer);
        icon.className = 'fas fa-play';
        text.textContent = 'Start Monitoring';
        btn.classList.add('btn-glow');
    } else {
        isMonitoring = true;
        icon.className = 'fas fa-stop';
        text.textContent = 'Stop Monitoring';
        btn.classList.remove('btn-glow');
        monitorTimer = setInterval(runMonitorCycle, 200);
        runMonitorCycle(); // Run immediately
    }
}

async function runMonitorCycle() {
    // Get system status
    const statusRes = await fetch('/api/system-status');
    const statusData = await statusRes.json();

    // Run detection
    const detectRes = await fetch('/api/detect');
    const detectData = await detectRes.json();

    if (!statusData.success || !detectData.success) return;

    const status = statusData.data;
    const detection = detectData.data;
    detectionCount++;
    document.getElementById('detCountValue').textContent = detectionCount;

    const now = new Date().toLocaleTimeString();

    // Update live metrics
    document.getElementById('liveCpuAvg').textContent = status.cpu.average.toFixed(1) + '%';
    document.getElementById('liveMemUsed').textContent = formatBytes(status.memory.used);
    document.getElementById('liveDiskRead').textContent = formatBytes(status.disk_io.read_bytes);
    document.getElementById('liveDiskWrite').textContent = formatBytes(status.disk_io.write_bytes);

    const prob = detection.probability || 0;
    const isRansomware = detection.is_ransomware;

    const detEl = document.getElementById('liveDetection');
    const confEl = document.getElementById('liveConfidence');

    if (isRansomware === null) {
        detEl.textContent = 'N/A';
        detEl.style.color = '#f59e0b';
        confEl.textContent = 'Model not loaded';
    } else if (isRansomware) {
        detEl.textContent = '⚠️ THREAT';
        detEl.style.color = '#ef4444';
        confEl.textContent = (prob * 100).toFixed(1) + '%';
        confEl.style.color = '#ef4444';
        addAlert(now, prob, detection.threat_info);
    } else {
        detEl.textContent = '✅ SAFE';
        detEl.style.color = '#10b981';
        confEl.textContent = (prob * 100).toFixed(1) + '%';
        confEl.style.color = '#10b981';
    }

    // Update charts
    labels.push(now);
    cpuData.push(status.cpu.average);
    diskReadData.push(status.disk_io.read_count);
    diskWriteData.push(status.disk_io.write_count);
    probData.push(prob);

    if (labels.length > MAX_POINTS) {
        labels.shift();
        cpuData.shift();
        diskReadData.shift();
        diskWriteData.shift();
        probData.shift();
    }

    // CPU Chart
    cpuChart.data.labels = [...labels];
    cpuChart.data.datasets[0].data = [...cpuData];
    cpuChart.update('none');

    // Disk Chart
    diskChart.data.labels = [...labels];
    diskChart.data.datasets[0].data = [...diskReadData];
    diskChart.data.datasets[1].data = [...diskWriteData];
    diskChart.update('none');

    // Timeline Chart
    timelineChart.data.labels = [...labels];
    timelineChart.data.datasets[0].data = [...probData];
    timelineChart.update('none');
}
let lastAlertTimestamp = 0;
let lastAlertPid = -1;

function addAlert(time, probability, threatInfo) {
    const currentTime = Date.now();
    const currentPid = threatInfo ? threatInfo.pid : -1;
    
    // Throttle duplicate alerts for the same PID to once every 10 seconds
    if (currentPid === lastAlertPid && (currentTime - lastAlertTimestamp) < 10000) {
        return; // Skip flooding the UI with identical alerts
    }
    
    lastAlertTimestamp = currentTime;
    lastAlertPid = currentPid;

    alertCount++;
    const alertBadge = document.getElementById('alertBadge');
    alertBadge.style.display = 'flex';
    document.getElementById('alertText').textContent = `${alertCount} Alert(s)`;

    const log = document.getElementById('alertLog');
    const empty = log.querySelector('.log-empty');
    if (empty) empty.remove();

    const entry = document.createElement('div');

    // Determine Alert Color based on Signature & I/O
    let alertClass = 'danger'; // default Red
    let alertIcon = 'fa-skull-crossbones';

    if (threatInfo) {
        if (threatInfo.is_signed) {
            alertClass = 'warning'; // Yellow for signed
            alertIcon = 'fa-shield-virus';
        }
    }

    entry.className = `log-entry ${alertClass}`;
    entry.style.flexDirection = 'column';
    entry.style.alignItems = 'stretch';
    entry.style.gap = '8px';

    let threatDetailsHtml = '';
    if (threatInfo && threatInfo.pid !== -1) {
        
        let killedHtml = '';
        if (threatInfo.killed_by_ai) {
            killedHtml = `<div style="color: #ef4444; font-weight: bold; margin-top: 5px;"><i class="fas fa-biohazard"></i> TERMINATED BY AUTO-KILL ENGINE</div>`;
        }
        
        threatDetailsHtml = `
            <div class="threat-details" style="font-size: 0.9em; margin-top: 5px; padding: 8px; background: rgba(0,0,0,0.2); border-radius: 4px;">
                <div><strong>Process:</strong> ${threatInfo.name} (PID: ${threatInfo.pid})</div>
                <div><strong>Path:</strong> <span style="font-family: monospace; font-size: 0.85em;">${threatInfo.path}</span></div>
                <div><strong>Category:</strong> ${threatInfo.category}</div>
                <div><strong>Signed:</strong> ${threatInfo.is_signed ? '<span style="color:#f59e0b">Yes (May be system update)</span>' : '<span style="color:#ef4444">No (Suspicious)</span>'}</div>
                ${killedHtml}
                <div style="display: flex; gap: 8px; margin-top: 8px;">
                    <button onclick="confirmKillProcess(${threatInfo.pid}, '${threatInfo.name}')" class="btn btn-sm" style="background: #ef4444; color: white; border: none; cursor: pointer; padding: 4px 8px; border-radius: 4px;">
                        <i class="fas fa-times-circle"></i> Kill
                    </button>
                    <button onclick="ignoreProcess(${threatInfo.pid})" class="btn btn-sm" style="background: #64748b; color: white; border: none; cursor: pointer; padding: 4px 8px; border-radius: 4px;">
                        <i class="fas fa-eye-slash"></i> Ignore
                    </button>
                </div>
            </div>
        `;
    }

    entry.innerHTML = `
        <div style="display: flex; justify-content: space-between; width: 100%;">
            <span>
                <span class="log-time">${time}</span>
                <span class="log-message"><i class="fas ${alertIcon}"></i> Potential ransomware activity detected</span>
            </span>
            <span class="log-prob" style="color: ${alertClass === 'warning' ? '#f59e0b' : '#ef4444'}">${(probability * 100).toFixed(1)}%</span>
        </div>
        ${threatDetailsHtml}
    `;
    log.insertBefore(entry, log.firstChild);

    while (log.children.length > 50) log.removeChild(log.lastChild);
}

async function confirmKillProcess(pid, name) {
    if (confirm(`CRITICAL WARNING:\n\nAre you sure you want to terminate the process '${name}' (PID: ${pid})?\n\nIf this is a critical system process, your computer may crash (Blue Screen).`)) {
        try {
            const res = await fetch('/api/kill-process', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ pid: pid })
            });
            const data = await res.json();

            if (data.success) {
                alert(`Success: ${data.message}`);
            } else {
                alert(`Failed to terminate process:\n\n${data.error}`);
            }
        } catch (e) {
            alert(`Network error occurred while trying to kill the process.`);
        }
    }
}

function clearAlerts() {
    alertCount = 0;
    document.getElementById('alertBadge').style.display = 'none';
    const log = document.getElementById('alertLog');
    log.innerHTML = `
        <div class="log-empty">
            <i class="fas fa-check-circle"></i>
            <p>No alerts. System is being monitored.</p>
        </div>
    `;
}

function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

async function toggleAutoKill() {
    const isChecked = document.getElementById('autoKillToggle').checked;
    
    if (isChecked) {
        if (!confirm("⚠️ WARNING: Autonomous Kill Mode is DANGEROUS.\n\nThe ML engine will instantly terminate any process it flags with > 95% confidence without your permission. Do you want to enable this?")) {
            document.getElementById('autoKillToggle').checked = false;
            return;
        }
    }
    
    try {
        const res = await fetch('/api/toggle-autokill', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled: isChecked })
        });
        const data = await res.json();
        console.log(data.message);
    } catch (e) {
        console.error("Failed to toggle auto-kill", e);
    }
}

async function ignoreProcess(pid) {
    try {
        const res = await fetch('/api/ignore-pid', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ pid: pid })
        });
        const data = await res.json();
        if (data.success) {
            clearAlerts(); // Reset UI 
            alert(`Process ${pid} is now muted and ignored by the ML engine.`);
        }
    } catch (e) {
        alert('Failed to ignore process.');
    }
}

// === EMBER Static Logs ===
let lastStaticLogTime = 0;

async function pollStaticLogs() {
    try {
        const result = await fetch('/api/static-logs').then(r => r.json());
        if (result.success && result.logs && result.logs.length > 0) {
            const logContainer = document.getElementById('emberLog');
            
            result.logs.forEach(log => {
                if (log.timestamp > lastStaticLogTime) {
                    lastStaticLogTime = log.timestamp;
                    
                    const isEmpty = logContainer.querySelector('.log-empty');
                    if (isEmpty) isEmpty.remove();
                    
                    const timeStr = new Date(log.timestamp * 1000).toLocaleTimeString();
                    
                    let className = 'safe';
                    if (log.event.includes('QUARANTINED') || log.event.includes('MALICIOUS')) {
                        className = 'danger';
                    } else if (log.event.includes('Analyzing')) {
                        className = 'warning';
                    }

                    const entry = document.createElement('div');
                    entry.className = `log-entry ${className}`;
                    entry.innerHTML = `
                        <div style="display: flex; gap: 12px; width: 100%; align-items: flex-start;">
                            <span class="log-time" style="white-space: nowrap;">${timeStr}</span>
                            <span class="log-message" style="flex: 1; word-break: break-all;">${log.event}</span>
                        </div>
                    `;
                    
                    logContainer.insertBefore(entry, logContainer.firstChild);
                    
                    while (logContainer.children.length > 20) {
                        logContainer.removeChild(logContainer.lastChild);
                    }
                }
            });
        }
    } catch (e) {
        console.error("Error fetching static logs: ", e);
    }
}
