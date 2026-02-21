/* ============================================
   Training Page JavaScript
   ============================================ */

let allResults = null;

document.addEventListener('DOMContentLoaded', () => {
    loadExistingResults();
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

async function loadExistingResults() {
    try {
        const res = await fetch('/api/model-results');
        const data = await res.json();
        if (data.success) {
            allResults = data.data;
            displayResults('integrated');
            showCharts();
        }
    } catch (e) { }
}

async function startTraining() {
    const btn = document.getElementById('btnTrain');
    const progress = document.getElementById('trainingProgress');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');

    btn.disabled = true;
    btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Training in Progress...';
    progress.style.display = 'block';

    // Simulate progress
    let pct = 0;
    const stages = [
        { text: 'Generating simulated data...', pct: 20 },
        { text: 'Training HPC models...', pct: 40 },
        { text: 'Training I/O models...', pct: 60 },
        { text: 'Training Integrated models...', pct: 80 },
        { text: 'Evaluating classifiers...', pct: 90 },
    ];

    let stageIdx = 0;
    const progressTimer = setInterval(() => {
        if (stageIdx < stages.length) {
            progressFill.style.width = stages[stageIdx].pct + '%';
            progressText.textContent = stages[stageIdx].text;
            stageIdx++;
        }
    }, 3000);

    try {
        const res = await fetch('/api/train', { method: 'POST' });
        const data = await res.json();

        clearInterval(progressTimer);

        if (data.success) {
            progressFill.style.width = '100%';
            progressText.textContent = 'Training complete! ✅';

            // Load results
            await loadExistingResults();
        } else {
            progressText.textContent = 'Error: ' + (data.error || 'Unknown error');
            progressFill.style.background = 'linear-gradient(135deg, #ef4444, #ec4899)';
        }
    } catch (error) {
        clearInterval(progressTimer);
        progressText.textContent = 'Error: ' + error.message;
    }

    btn.disabled = false;
    btn.innerHTML = '<i class="fas fa-rocket"></i> Re-train Models';
}

function switchModelTab(modelType, tabEl) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tabEl.classList.add('active');
    displayResults(modelType);
}

function displayResults(modelType) {
    if (!allResults || !allResults[modelType]) {
        return;
    }

    const tbody = document.getElementById('resultsTableBody');
    const data = allResults[modelType];

    // Find best accuracy
    let bestAcc = 0;
    let bestClf = '';
    Object.entries(data).forEach(([clf, metrics]) => {
        if (metrics.balanced_accuracy > bestAcc) {
            bestAcc = metrics.balanced_accuracy;
            bestClf = clf;
        }
    });

    tbody.innerHTML = '';

    Object.entries(data).forEach(([clf, metrics]) => {
        const isBest = clf === bestClf;
        const row = document.createElement('tr');
        if (isBest) row.className = 'best-row';

        row.innerHTML = `
            <td style="font-family: var(--font-sans); font-weight: 500;">${clf}</td>
            <td style="color: ${getMetricColor(metrics.balanced_accuracy)}">${metrics.balanced_accuracy.toFixed(4)}</td>
            <td style="color: ${getMetricColor(metrics.f1_score)}">${metrics.f1_score.toFixed(4)}</td>
            <td style="color: ${getMetricColor(metrics.precision)}">${metrics.precision.toFixed(4)}</td>
            <td style="color: ${getMetricColor(metrics.recall)}">${metrics.recall.toFixed(4)}</td>
            <td style="color: ${metrics.fpr < 0.05 ? '#10b981' : metrics.fpr < 0.1 ? '#f59e0b' : '#ef4444'}">${metrics.fpr.toFixed(4)}</td>
            <td style="color: ${metrics.fnr < 0.1 ? '#10b981' : metrics.fnr < 0.2 ? '#f59e0b' : '#ef4444'}">${metrics.fnr.toFixed(4)}</td>
        `;
        tbody.appendChild(row);
    });
}

function getMetricColor(value) {
    if (value >= 0.9) return '#10b981';
    if (value >= 0.8) return '#06b6d4';
    if (value >= 0.7) return '#f59e0b';
    return '#ef4444';
}

function showCharts() {
    if (!allResults) return;

    const chartsSection = document.getElementById('chartsSection');
    chartsSection.style.display = 'block';

    // Accuracy Chart
    const intData = allResults['integrated'] || {};
    const classifiers = Object.keys(intData);
    const accuracies = classifiers.map(c => intData[c].balanced_accuracy);

    const colors = [
        'rgba(59, 130, 246, 0.8)',
        'rgba(139, 92, 246, 0.8)',
        'rgba(16, 185, 129, 0.8)',
        'rgba(6, 182, 212, 0.8)',
        'rgba(245, 158, 11, 0.8)',
    ];

    const borderColors = [
        'rgba(59, 130, 246, 1)',
        'rgba(139, 92, 246, 1)',
        'rgba(16, 185, 129, 1)',
        'rgba(6, 182, 212, 1)',
        'rgba(245, 158, 11, 1)',
    ];

    new Chart(document.getElementById('accuracyChart'), {
        type: 'bar',
        data: {
            labels: classifiers,
            datasets: [{
                label: 'Balanced Accuracy',
                data: accuracies,
                backgroundColor: colors,
                borderColor: borderColors,
                borderWidth: 1,
                borderRadius: 6,
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
            },
            scales: {
                y: {
                    beginAtZero: false,
                    min: 0.5,
                    max: 1.0,
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono' } }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#94a3b8', font: { size: 11 } }
                }
            }
        }
    });

    // FPR vs FNR Chart
    const fprs = classifiers.map(c => intData[c].fpr);
    const fnrs = classifiers.map(c => intData[c].fnr);

    new Chart(document.getElementById('errorChart'), {
        type: 'bar',
        data: {
            labels: classifiers,
            datasets: [
                {
                    label: 'FPR',
                    data: fprs,
                    backgroundColor: 'rgba(239, 68, 68, 0.7)',
                    borderColor: 'rgba(239, 68, 68, 1)',
                    borderWidth: 1,
                    borderRadius: 6,
                },
                {
                    label: 'FNR',
                    data: fnrs,
                    backgroundColor: 'rgba(245, 158, 11, 0.7)',
                    borderColor: 'rgba(245, 158, 11, 1)',
                    borderWidth: 1,
                    borderRadius: 6,
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: { color: '#94a3b8', font: { size: 12 } }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono' } }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#94a3b8', font: { size: 11 } }
                }
            }
        }
    });
}
