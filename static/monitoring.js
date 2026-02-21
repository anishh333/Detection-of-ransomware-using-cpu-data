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
        monitorTimer = setInterval(runMonitorCycle, 1000);
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
        addAlert(now, prob);
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

function addAlert(time, probability) {
    alertCount++;
    const alertBadge = document.getElementById('alertBadge');
    alertBadge.style.display = 'flex';
    document.getElementById('alertText').textContent = `${alertCount} Alert(s)`;

    const log = document.getElementById('alertLog');
    const empty = log.querySelector('.log-empty');
    if (empty) empty.remove();

    const entry = document.createElement('div');
    entry.className = 'log-entry danger';
    entry.innerHTML = `
        <span class="log-time">${time}</span>
        <span class="log-message">⚠️ Potential ransomware activity detected</span>
        <span class="log-prob" style="color:#ef4444">${(probability * 100).toFixed(1)}%</span>
    `;
    log.insertBefore(entry, log.firstChild);

    while (log.children.length > 50) log.removeChild(log.lastChild);
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
