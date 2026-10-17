/**
 * CyberNinjas - Real-time Network Telemetry Charts
 * New High-Contrast Electric Cyan & Vivid Amber Color Combination
 */

let bandwidthChart = null;
let packetsChart = null;
let protocolChart = null;
let statusChart = null;

function initCharts() {
    const commonChartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 250 },
        interaction: { mode: 'index', intersect: false },
        plugins: {
            legend: {
                labels: { color: '#e2e8f0', font: { family: 'Plus Jakarta Sans', size: 11, weight: '600' } }
            },
            tooltip: {
                backgroundColor: 'rgba(15, 19, 28, 0.96)',
                titleColor: '#ffffff',
                bodyColor: '#e2e8f0',
                borderColor: '#28334a',
                borderWidth: 1,
                padding: 8,
                boxPadding: 4,
                titleFont: { family: 'Plus Jakarta Sans', weight: 'bold', size: 11 },
                bodyFont: { family: 'JetBrains Mono', size: 10 }
            }
        },
        scales: {
            x: {
                grid: { color: 'rgba(255, 255, 255, 0.04)' },
                ticks: { color: '#8896ab', maxTicksLimit: 7, font: { family: 'JetBrains Mono', size: 10, weight: '500' } }
            },
            y: {
                grid: { color: 'rgba(255, 255, 255, 0.04)' },
                ticks: { color: '#8896ab', font: { family: 'JetBrains Mono', size: 10, weight: '500' } },
                beginAtZero: true
            }
        }
    };

    // 1. Bandwidth Throughput Chart (KB/s) - Electric Cyan (RX) vs Vivid Amber (TX)
    const ctxBw = document.getElementById('bandwidthChart')?.getContext('2d');
    if (ctxBw) {
        const gradDownload = ctxBw.createLinearGradient(0, 0, 0, 220);
        gradDownload.addColorStop(0, 'rgba(0, 229, 255, 0.32)');
        gradDownload.addColorStop(1, 'rgba(0, 229, 255, 0.00)');

        const gradUpload = ctxBw.createLinearGradient(0, 0, 0, 220);
        gradUpload.addColorStop(0, 'rgba(245, 158, 11, 0.30)');
        gradUpload.addColorStop(1, 'rgba(245, 158, 11, 0.00)');

        bandwidthChart = new Chart(ctxBw, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Download (RX KB/s)',
                        data: [],
                        borderColor: '#00e5ff',
                        backgroundColor: gradDownload,
                        fill: true,
                        tension: 0.3,
                        borderWidth: 2,
                        pointRadius: 0,
                        pointHitRadius: 10
                    },
                    {
                        label: 'Upload (TX KB/s)',
                        data: [],
                        borderColor: '#f59e0b',
                        backgroundColor: gradUpload,
                        fill: true,
                        tension: 0.3,
                        borderWidth: 2,
                        pointRadius: 0,
                        pointHitRadius: 10
                    }
                ]
            },
            options: {
                ...commonChartOptions,
                scales: {
                    ...commonChartOptions.scales,
                    y: {
                        ...commonChartOptions.scales.y,
                        title: { display: true, text: 'KB/s', color: '#94a3b8', font: { size: 10, weight: '600' } }
                    }
                }
            }
        });
    }

    // 2. Packets Per Second Chart - Emerald vs Orange
    const ctxPackets = document.getElementById('packetsChart')?.getContext('2d');
    if (ctxPackets) {
        packetsChart = new Chart(ctxPackets, {
            type: 'line',
            data: {
                labels: [],
                datasets: [
                    {
                        label: 'Packets In / s',
                        data: [],
                        borderColor: '#10b981',
                        backgroundColor: 'rgba(16, 185, 129, 0.08)',
                        tension: 0.2,
                        borderWidth: 1.8,
                        pointRadius: 0
                    },
                    {
                        label: 'Packets Out / s',
                        data: [],
                        borderColor: '#fb923c',
                        backgroundColor: 'rgba(251, 146, 60, 0.08)',
                        tension: 0.2,
                        borderWidth: 1.8,
                        pointRadius: 0
                    }
                ]
            },
            options: {
                ...commonChartOptions,
                scales: {
                    ...commonChartOptions.scales,
                    y: {
                        ...commonChartOptions.scales.y,
                        title: { display: true, text: 'Pkts / s', color: '#94a3b8', font: { size: 10, weight: '600' } }
                    }
                }
            }
        });
    }

    // 3. Protocol Distribution Doughnut
    const ctxProto = document.getElementById('protocolChart')?.getContext('2d');
    if (ctxProto) {
        protocolChart = new Chart(ctxProto, {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP', 'ICMP', 'DNS', 'Other'],
                datasets: [{
                    data: [1, 1, 0, 0, 0],
                    backgroundColor: ['#00e5ff', '#f59e0b', '#10b981', '#818cf8', '#64748b'],
                    borderWidth: 2,
                    borderColor: '#131722'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '68%',
                plugins: {
                    legend: { position: 'bottom', labels: { color: '#cbd5e1', boxWidth: 10, font: { size: 10, weight: '500' } } }
                }
            }
        });
    }

    // 4. Socket State Breakdown Bar Chart
    const ctxStatus = document.getElementById('statusChart')?.getContext('2d');
    if (ctxStatus) {
        statusChart = new Chart(ctxStatus, {
            type: 'bar',
            data: {
                labels: ['ESTABLISHED', 'LISTEN', 'TIME_WAIT', 'CLOSE_WAIT', 'SYN_SENT'],
                datasets: [{
                    label: 'Socket Count',
                    data: [0, 0, 0, 0, 0],
                    backgroundColor: ['#10b981', '#00e5ff', '#f59e0b', '#f43f5e', '#818cf8'],
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { ticks: { color: '#cbd5e1', font: { size: 9, weight: '500' } }, grid: { display: false } },
                    y: { ticks: { color: '#8896ab', precision: 0, font: { size: 9 } }, grid: { color: 'rgba(255,255,255,0.04)' }, beginAtZero: true }
                }
            }
        });
    }
}

function updateChartsWithHistory(history) {
    if (!bandwidthChart || !history || history.length === 0) return;

    const labels = history.map(item => item.timestamp);
    const rxData = history.map(item => item.rx_kbps);
    const txData = history.map(item => item.tx_kbps);
    const pktInData = history.map(item => item.packets_in);
    const pktOutData = history.map(item => item.packets_out);

    bandwidthChart.data.labels = labels;
    bandwidthChart.data.datasets[0].data = rxData;
    bandwidthChart.data.datasets[1].data = txData;
    bandwidthChart.update('none');

    if (packetsChart) {
        packetsChart.data.labels = labels;
        packetsChart.data.datasets[0].data = pktInData;
        packetsChart.data.datasets[1].data = pktOutData;
        packetsChart.update('none');
    }
}

function pushChartPoint(point) {
    if (!bandwidthChart || !point) return;

    const maxPoints = 60;
    const labels = bandwidthChart.data.labels;
    const rx = bandwidthChart.data.datasets[0].data;
    const tx = bandwidthChart.data.datasets[1].data;

    labels.push(point.timestamp);
    rx.push(point.rx_kbps);
    tx.push(point.tx_kbps);

    if (labels.length > maxPoints) {
        labels.shift();
        rx.shift();
        tx.shift();
    }
    bandwidthChart.update('none');

    if (packetsChart) {
        const pLabels = packetsChart.data.labels;
        const pIn = packetsChart.data.datasets[0].data;
        const pOut = packetsChart.data.datasets[1].data;

        pLabels.push(point.timestamp);
        pIn.push(point.packets_in);
        pOut.push(point.packets_out);

        if (pLabels.length > maxPoints) {
            pLabels.shift();
            pIn.shift();
            pOut.shift();
        }
        packetsChart.update('none');
    }
}

function updateDistributionCharts(statusDist, protoDist) {
    if (statusChart && statusDist) {
        const labels = ['ESTABLISHED', 'LISTEN', 'TIME_WAIT', 'CLOSE_WAIT', 'SYN_SENT'];
        const values = labels.map(l => statusDist[l] || 0);
        statusChart.data.datasets[0].data = values;
        statusChart.update('none');
    }

    if (protocolChart && protoDist) {
        const labels = ['TCP', 'UDP', 'ICMP', 'DNS', 'Other'];
        const values = [
            protoDist['TCP'] || 0,
            protoDist['UDP'] || 0,
            protoDist['ICMP'] || 0,
            protoDist['DNS'] || 0,
            protoDist['Other'] || 0
        ];
        protocolChart.data.datasets[0].data = values;
        protocolChart.update('none');
    }
}
