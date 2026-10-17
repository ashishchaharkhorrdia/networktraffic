/**
 * CyberNinjas - Main Application Controller & WebSocket Engine
 */

let socket = null;
let isStreamingPaused = false;
let reconnectAttempts = 0;
let lastTelemetry = null;

document.addEventListener('DOMContentLoaded', () => {
    initCharts();
    initWebSocket();
    initTabs();
    initInterfaceSelector();
    initScanner();
    loadConnections();
    initSniffer();
    initFirewall();
    if (typeof initIds === 'function') initIds();

    // Periodic quick refresh for non-WebSocket data (e.g. connections table)
    setInterval(() => {
        if (!isStreamingPaused && document.getElementById('tab-connections')?.classList.contains('active-tab-content')) {
            loadConnections();
        }
    }, 4000);
});

// WebSocket Connection
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/live`;

    updateConnectionStatus('connecting');

    try {
        socket = new WebSocket(wsUrl);

        socket.onopen = () => {
            console.log('WebSocket connected to CyberNinjas');
            reconnectAttempts = 0;
            updateConnectionStatus('connected');
        };

        socket.onmessage = (event) => {
            if (isStreamingPaused) return;

            try {
                const data = JSON.parse(event.data);
                handleTelemetry(data);
            } catch (err) {
                console.error('Error handling WS message', err);
            }
        };

        socket.onclose = () => {
            updateConnectionStatus('disconnected');
            // Auto reconnect with backoff
            const delay = Math.min(1000 * Math.pow(1.5, reconnectAttempts), 10000);
            reconnectAttempts++;
            setTimeout(initWebSocket, delay);
        };

        socket.onerror = (err) => {
            console.error('WebSocket encountered error', err);
        };
    } catch (e) {
        console.error('Failed to initialize WebSocket', e);
        setTimeout(initWebSocket, 3000);
    }
}

function updateConnectionStatus(status) {
    const pill = document.getElementById('wsStatusPill');
    const dot = document.getElementById('wsStatusDot');
    const text = document.getElementById('wsStatusText');

    if (!pill || !dot || !text) return;

    if (status === 'connected') {
        pill.className = 'flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-emerald-950/90 border border-emerald-700 text-xs text-emerald-200 font-medium';
        dot.className = 'w-2 h-2 rounded-full bg-emerald-400 animate-live-pulse';
        text.innerText = 'LIVE TELEMETRY';
    } else if (status === 'connecting') {
        pill.className = 'flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-amber-950/90 border border-amber-700 text-xs text-amber-200 font-medium';
        dot.className = 'w-2 h-2 rounded-full bg-amber-400 animate-ping';
        text.innerText = 'CONNECTING...';
    } else {
        pill.className = 'flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-rose-950/90 border border-rose-700 text-xs text-rose-200 font-medium';
        dot.className = 'w-2 h-2 rounded-full bg-rose-400';
        text.innerText = 'RECONNECTING';
    }
}

function handleTelemetry(data) {
    lastTelemetry = data;

    if (data.type === 'initial') {
        if (data.bandwidth && data.bandwidth.history) {
            updateChartsWithHistory(data.bandwidth.history);
        }
        if (data.default_gateway) {
            document.getElementById('topGatewayIp').innerText = data.default_gateway;
        }
        populateInterfaceDropdown(data.interfaces, data.default_interface);
    }

    if (data.bandwidth) {
        const cur = data.bandwidth.current;
        pushChartPoint(cur);

        // Update KPI Cards
        const rxEl = document.getElementById('cardRxSpeed');
        const txEl = document.getElementById('cardTxSpeed');
        const rxMbpsEl = document.getElementById('cardRxMbps');
        const txMbpsEl = document.getElementById('cardTxMbps');

        if (rxEl) rxEl.innerText = `${cur.rx_kbps.toLocaleString()}`;
        if (txEl) txEl.innerText = `${cur.tx_kbps.toLocaleString()}`;
        if (rxMbpsEl) rxMbpsEl.innerText = `${cur.rx_mbps} Mbps`;
        if (txMbpsEl) txMbpsEl.innerText = `${cur.tx_mbps} Mbps`;

        // Update Session Totals in Top Bar
        if (data.bandwidth.session) {
            const sess = data.bandwidth.session;
            const sessionRx = document.getElementById('topSessionRx');
            const sessionTx = document.getElementById('topSessionTx');
            if (sessionRx) sessionRx.innerText = `${sess.rx_mb} MB`;
            if (sessionTx) sessionTx.innerText = `${sess.tx_mb} MB`;
        }

        // Errors & Drops
        const dropEl = document.getElementById('cardDropRate');
        if (dropEl) dropEl.innerText = cur.drops > 0 ? `${cur.drops}/s` : '0';
    }

    if (data.connections_summary) {
        const cs = data.connections_summary;
        const totalSockets = document.getElementById('cardActiveSockets');
        const estabSockets = document.getElementById('cardEstablishedSockets');
        if (totalSockets) totalSockets.innerText = cs.total;
        if (estabSockets) estabSockets.innerText = `${cs.established} established`;

        updateDistributionCharts(cs.status_distribution, cs.protocol_distribution);

        if (cs.top_remote_ips) {
            renderTopTalkers(cs.top_remote_ips);
        }
    }

    if (data.scanner) {
        const lanCount = document.getElementById('cardLanHosts');
        if (lanCount && data.scanner.host_count !== undefined) {
            lanCount.innerText = data.scanner.host_count;
        }
    }

    if (data.firewall && typeof renderFirewallStats === 'function') {
        renderFirewallStats(data.firewall);
    }

    if (data.ids && typeof renderIdsStats === 'function') {
        renderIdsStats(data.ids);
    }

    if (data.top_talkers) {
        renderProcessTopTalkers(data.top_talkers);
    }
}

function renderProcessTopTalkers(talkers) {
    const list = document.getElementById('processTopTalkersList');
    if (!list || !talkers) return;

    if (talkers.length === 0) {
        list.innerHTML = `<div class="text-xs text-slate-400 py-3 text-center font-mono">No active process network traffic.</div>`;
        return;
    }

    list.innerHTML = talkers.map(p => `
        <div class="flex items-center justify-between p-2.5 rounded-lg bg-[#181d2c] border border-[#222a3d] hover:border-cyan-800/80 transition text-xs">
            <div class="flex items-center space-x-2.5 overflow-hidden">
                <div class="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-800 text-[#00e5ff] flex items-center justify-center shrink-0">
                    <i class="fa-solid fa-microchip text-xs"></i>
                </div>
                <div class="overflow-hidden">
                    <div class="font-bold text-white truncate text-xs flex items-center space-x-1.5">
                        <span>${p.name}</span>
                        <span class="text-[10px] font-mono text-slate-400 font-normal">PID ${p.pid}</span>
                    </div>
                    <div class="text-[11px] text-slate-400 truncate">${p.category} • ${p.connections} sockets</div>
                </div>
            </div>
            <div class="flex flex-col items-end pl-2">
                <span class="font-mono font-bold text-[#00e5ff] text-xs">${p.rx_rate_str}</span>
                <span class="font-mono text-[10px] text-slate-400">up: ${p.tx_rate_str}</span>
            </div>
        </div>
    `).join('');
}

// Interface selector logic
async function initInterfaceSelector() {
    try {
        const resp = await fetch('/api/interfaces');
        const interfaces = await resp.json();
        populateInterfaceDropdown(interfaces);
    } catch (e) {
        console.error('Failed to load interfaces', e);
    }

    const select = document.getElementById('interfaceSelect');
    if (select) {
        select.addEventListener('change', async (e) => {
            const iface = e.target.value;
            await fetch('/api/interfaces/select', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ interface: iface })
            });

            if (socket && socket.readyState === WebSocket.OPEN) {
                socket.send(JSON.stringify({ action: 'set_interface', interface: iface }));
            }
        });
    }
}

function populateInterfaceDropdown(interfaces, defaultIface) {
    const select = document.getElementById('interfaceSelect');
    if (!select || !interfaces) return;

    const currentVal = select.value;
    select.innerHTML = `<option value="all">All Interfaces</option>`;

    interfaces.forEach(i => {
        const opt = document.createElement('option');
        opt.value = i.name;
        opt.textContent = `${i.name} (${i.ipv4 || 'No IP'})`;
        if (i.is_default && !currentVal) {
            opt.selected = true;
        }
        select.appendChild(opt);
    });

    if (currentVal) {
        select.value = currentVal;
    }
}

// Navigation Tabs
function initTabs() {
    document.querySelectorAll('.nav-tab').forEach(tab => {
        tab.addEventListener('click', () => {
            const target = tab.dataset.tab;
            switchTab(target);
        });
    });
}

function switchTab(tabId) {
    document.querySelectorAll('.nav-tab').forEach(t => {
        if (t.dataset.tab === tabId) {
            t.classList.add('active');
        } else {
            t.classList.remove('active');
        }
    });

    document.querySelectorAll('.tab-content').forEach(c => {
        if (c.id === `tab-${tabId}`) {
            c.classList.remove('hidden');
            c.classList.add('active-tab-content');
        } else {
            c.classList.add('hidden');
            c.classList.remove('active-tab-content');
        }
    });

    // Special tab initialization
    if (tabId === 'diagnostics') {
        initDiagnostics();
    } else if (tabId === 'connections') {
        loadConnections();
    } else if (tabId === 'sniffer') {
        fetchPackets();
    } else if (tabId === 'firewall') {
        initFirewall();
    } else if (tabId === 'ids') {
        initIds();
    }
}

// Toggle Live Stream Pause
function toggleLiveStream() {
    isStreamingPaused = !isStreamingPaused;
    const btn = document.getElementById('btnPauseStream');
    if (btn) {
        if (isStreamingPaused) {
            btn.innerHTML = `<i class="fa-solid fa-play mr-1.5 text-emerald-300"></i> Resume Stream`;
            btn.classList.add('bg-amber-950', 'text-amber-200', 'border-amber-700');
        } else {
            btn.innerHTML = `<i class="fa-solid fa-pause mr-1.5 text-slate-300"></i> Pause Stream`;
            btn.classList.remove('bg-amber-950', 'text-amber-200', 'border-amber-700');
        }
    }
}

// Export Full Telemetry Snapshot
function exportReport() {
    if (!lastTelemetry) {
        alert('No telemetry data available to export yet.');
        return;
    }

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(lastTelemetry, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `cyberninjas_report_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
}

// Meet Developers Modal Controllers
function openMeetDevelopersModal() {
    const modal = document.getElementById('meetDevelopersModal');
    if (modal) modal.classList.remove('hidden');
}

function closeMeetDevelopersModal() {
    const modal = document.getElementById('meetDevelopersModal');
    if (modal) modal.classList.add('hidden');
}
