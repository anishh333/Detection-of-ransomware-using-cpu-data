/* ============================================
   Dashboard JavaScript - Main page logic
   ============================================ */

// === System Status Polling ===
let statusInterval = null;
let detectionInterval = null;
let isDetecting = false;

// Mini chart data buffers
const chartBuffers = {
    cpu: [], memory: [], diskRead: [], diskWrite: []
};
const BUFFER_SIZE = 20;

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    checkSystemStatus();
    loadModelInfo();
    statusInterval = setInterval(checkSystemStatus, 3000);
});

// === API Helpers ===
async function fetchAPI(endpoint) {
    try {
        const response = await fetch(endpoint);
        return await response.json();
    } catch (error) {
        console.error(`API Error (${endpoint}):`, error);
        return { success: false, error: error.message };
    }
}

// === System Status ===
async function checkSystemStatus() {
    const result = await fetchAPI('/api/system-status');
    const dot = document.getElementById('systemStatusDot');
    const text = document.getElementById('systemStatusText');

    if (result.success) {
        dot.className = 'status-dot connected';
        text.textContent = 'System Online';
        updateStats(result.data);
    } else {
        dot.className = 'status-dot error';
        text.textContent = 'Connection Error';
    }
}

// === Update Stats Cards ===
function updateStats(data) {
    // CPU
    const cpuAvg = data.cpu.average.toFixed(1);
    document.getElementById('cpuValue').textContent = cpuAvg + '%';
    chartBuffers.cpu.push(parseFloat(cpuAvg));
    if (chartBuffers.cpu.length > BUFFER_SIZE) chartBuffers.cpu.shift();
    drawMiniChart('cpuMiniChart', chartBuffers.cpu, '#3b82f6');

    // Memory
    const memPercent = data.memory.percent.toFixed(1);
    document.getElementById('memValue').textContent = memPercent + '%';
    chartBuffers.memory.push(parseFloat(memPercent));
    if (chartBuffers.memory.length > BUFFER_SIZE) chartBuffers.memory.shift();
    drawMiniChart('memMiniChart', chartBuffers.memory, '#8b5cf6');

    // Disk Read
    const readMB = (data.disk_io.read_bytes / (1024 * 1024)).toFixed(0);
    document.getElementById('diskReadValue').textContent = readMB + ' MB';
    chartBuffers.diskRead.push(parseInt(readMB));
    if (chartBuffers.diskRead.length > BUFFER_SIZE) chartBuffers.diskRead.shift();
    drawMiniChart('diskReadMiniChart', chartBuffers.diskRead, '#10b981');

    // Disk Write
    const writeMB = (data.disk_io.write_bytes / (1024 * 1024)).toFixed(0);
    document.getElementById('diskWriteValue').textContent = writeMB + ' MB';
    chartBuffers.diskWrite.push(parseInt(writeMB));
    if (chartBuffers.diskWrite.length > BUFFER_SIZE) chartBuffers.diskWrite.shift();
    drawMiniChart('diskWriteMiniChart', chartBuffers.diskWrite, '#f59e0b');
}

// === Mini Sparkline Charts ===
function drawMiniChart(canvasId, data, color) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const w = canvas.width;
    const h = canvas.height;
    
    ctx.clearRect(0, 0, w, h);
    
    if (data.length < 2) return;
    
    const min = Math.min(...data);
    const max = Math.max(...data) || 1;
    const range = max - min || 1;
    
    // Draw line
    ctx.beginPath();
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.lineJoin = 'round';
    
    data.forEach((val, i) => {
        const x = (i / (data.length - 1)) * w;
        const y = h - ((val - min) / range) * (h - 4) - 2;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
    });
    ctx.stroke();
    
    // Fill area
    const gradient = ctx.createLinearGradient(0, 0, 0, h);
    gradient.addColorStop(0, color + '40');
    gradient.addColorStop(1, color + '00');
    
    ctx.lineTo(w, h);
    ctx.lineTo(0, h);
    ctx.closePath();
    ctx.fillStyle = gradient;
    ctx.fill();
}

// === Model Info ===
async function loadModelInfo() {
    const result = await fetchAPI('/api/model-info');
    
    if (result.success) {
        const info = result.data;
        const metrics = info.metrics;
        
        document.getElementById('modelBadge').textContent = info.classifier + ' (Trained)';
        document.getElementById('modelBadge').className = 'card-badge trained';
        
        // Update metric rings
        updateMetricRing('accuracy', metrics.balanced_accuracy);
        updateMetricRing('f1', metrics.f1_score);
        updateMetricRing('precision', metrics.precision);
        updateMetricRing('recall', metrics.recall);
        
        // Update details
        document.getElementById('modelDetails').innerHTML = `
            <div style="display:flex;gap:16px;flex-wrap:wrap;">
                <div class="info-badge"><i class="fas fa-clock"></i> Trained: ${new Date(info.trained_at).toLocaleString()}</div>
                <div class="info-badge"><i class="fas fa-layer-group"></i> Type: ${info.model_type}</div>
                <div class="info-badge"><i class="fas fa-chart-column"></i> Features: ${info.feature_columns.length}</div>
                <div class="info-badge"><i class="fas fa-triangle-exclamation"></i> FPR: ${metrics.fpr}</div>
                <div class="info-badge"><i class="fas fa-circle-xmark"></i> FNR: ${metrics.fnr}</div>
            </div>
        `;
    }
}

function updateMetricRing(metric, value) {
    const circumference = 201; // 2 * PI * 32
    const offset = circumference * (1 - value);
    
    const ring = document.getElementById(metric + 'Ring');
    const valueEl = document.getElementById(metric + 'Value');
    
    if (ring) ring.style.strokeDashoffset = offset;
    if (valueEl) valueEl.textContent = (value * 100).toFixed(0) + '%';
}

// === Quick Detection ===
async function startQuickDetection() {
    const btn = document.getElementById('btnStartDetection');
    
    if (isDetecting) {
        isDetecting = false;
        clearInterval(detectionInterval);
        btn.innerHTML = '<i class="fas fa-play"></i> Start Detection';
        btn.classList.add('btn-glow');
        updateThreatMeter(0, 'System Idle', false);
        return;
    }
    
    isDetecting = true;
    btn.innerHTML = '<i class="fas fa-stop"></i> Stop Detection';
    btn.classList.remove('btn-glow');
    
    detectionInterval = setInterval(async () => {
        const result = await fetchAPI('/api/detect');
        if (result.success) {
            const data = result.data;
            const prob = data.probability || 0;
            const isRansomware = data.is_ransomware;
            
            updateThreatMeter(prob, 
                isRansomware === null ? 'Model Not Loaded' :
                isRansomware ? 'THREAT DETECTED!' : 'System Safe',
                isRansomware
            );
            
            addLogEntry(data);
        }
    }, 1000);
}

function updateThreatMeter(probability, statusText, isDanger) {
    const circumference = 534; // 2 * PI * 85
    const offset = circumference * (1 - probability);
    
    const fill = document.getElementById('meterFill');
    const value = document.getElementById('meterValue');
    const status = document.getElementById('meterStatus');
    
    if (fill) {
        fill.style.strokeDashoffset = offset;
        fill.style.stroke = isDanger ? '#ef4444' : probability > 0.3 ? '#f59e0b' : '#10b981';
    }
    
    if (value) {
        value.textContent = (probability * 100).toFixed(0) + '%';
        value.style.color = isDanger ? '#ef4444' : probability > 0.3 ? '#f59e0b' : '#10b981';
    }
    
    if (status) {
        status.className = 'meter-status' + (isDanger ? ' danger' : '');
        status.innerHTML = `<i class="fas fa-${isDanger ? 'exclamation-triangle' : 'circle-check'}"></i> ${statusText}`;
    }
}

function addLogEntry(data) {
    const log = document.getElementById('detectionLog');
    const isEmpty = log.querySelector('.log-empty');
    if (isEmpty) isEmpty.remove();
    
    const time = new Date(data.timestamp * 1000).toLocaleTimeString();
    const prob = data.probability || 0;
    const isRansomware = data.is_ransomware;
    
    let className = 'safe';
    let message = 'Normal activity detected';
    
    if (isRansomware === null) {
        className = 'warning';
        message = 'Model not loaded - cannot classify';
    } else if (isRansomware) {
        className = 'danger';
        message = '⚠️ Potential ransomware activity detected!';
    }
    
    const entry = document.createElement('div');
    entry.className = `log-entry ${className}`;
    entry.style.flexDirection = 'column';
    entry.style.alignItems = 'stretch';
    entry.style.gap = '4px';

    let pathHtml = '';
    if (isRansomware && data.threat_info && data.threat_info.path) {
        pathHtml = `<div style="font-family: monospace; font-size: 0.85em; opacity: 0.8; margin-left: 55px; word-break: break-all;"><i class="fas fa-folder-open"></i> ${data.threat_info.path}</div>`;
    }

    entry.innerHTML = `
        <div style="display: flex; align-items: center; gap: 12px; width: 100%;">
            <span class="log-time">${time}</span>
            <span class="log-message" style="flex: 1;">${message}</span>
            <span class="log-prob" style="color:${isRansomware ? '#ef4444' : '#10b981'}">${(prob * 100).toFixed(1)}%</span>
        </div>
        ${pathHtml}
    `;
    
    log.insertBefore(entry, log.firstChild);
    
    // Keep only last 50 entries
    while (log.children.length > 50) {
        log.removeChild(log.lastChild);
    }
}

function clearLog() {
    const log = document.getElementById('detectionLog');
    log.innerHTML = `
        <div class="log-empty">
            <i class="fas fa-shield-halved"></i>
            <p>No detection events yet. Start monitoring to see activity.</p>
        </div>
    `;
}
