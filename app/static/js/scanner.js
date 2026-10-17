/**
 * CyberNinjas - Subnet Host Discovery & Port Scanner Client Module
 */

let isScanRunning = false;
let scanPollInterval = null;
let currentDiscoveredHosts = [];

async function initScanner() {
    try {
        const resp = await fetch('/api/overview');
        const data = await resp.json();
        if (data.subnet && data.subnet.subnet) {
            const cidrInput = document.getElementById('subnetCidrInput');
            if (cidrInput) {
                cidrInput.value = data.subnet.subnet;
            }
            const localIpBadge = document.getElementById('scannerLocalIp');
            if (localIpBadge) {
                localIpBadge.innerText = `${data.subnet.local_ip} (Gateway: ${data.subnet.gateway})`;
            }
        }
    } catch (e) {
        console.error('Failed to init subnet info', e);
    }

    // Check if a scan is already running or fetch last results
    fetchScanStatus();
}

async function startSubnetScan() {
    if (isScanRunning) return;

    const cidrInput = document.getElementById('subnetCidrInput');
    const cidr = cidrInput ? cidrInput.value.trim() : null;

    setScanUiState(true);

    try {
        const resp = await fetch('/api/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ cidr: cidr || null })
        });
        const res = await resp.json();
        
        // Start polling
        if (scanPollInterval) clearInterval(scanPollInterval);
        scanPollInterval = setInterval(fetchScanStatus, 800);
    } catch (e) {
        alert('Failed to start subnet scan: ' + e);
        setScanUiState(false);
    }
}

async function fetchScanStatus() {
    try {
        const resp = await fetch('/api/scan/status');
        const data = await resp.json();
        
        const progressBar = document.getElementById('scanProgressBar');
        const progressText = document.getElementById('scanProgressText');

        if (progressBar && progressText) {
            progressBar.style.width = `${data.progress}%`;
            progressText.innerText = `${data.progress}%`;
        }

        if (data.results && data.results.length > 0) {
            currentDiscoveredHosts = data.results;
            renderDiscoveredHosts(data.results);
            const countEl = document.getElementById('discoveredHostsCount');
            if (countEl) countEl.innerText = data.results.length;
            const overviewCount = document.getElementById('cardLanHosts');
            if (overviewCount) overviewCount.innerText = data.results.length;
        }

        if (!data.is_scanning) {
            setScanUiState(false);
            if (scanPollInterval) {
                clearInterval(scanPollInterval);
                scanPollInterval = null;
            }
        }
    } catch (e) {
        console.error('Error fetching scan status', e);
    }
}

function setScanUiState(scanning) {
    isScanRunning = scanning;
    const btn = document.getElementById('btnStartScan');
    const radar = document.getElementById('scanRadarIcon');
    const progressContainer = document.getElementById('scanProgressContainer');

    if (btn) {
        if (scanning) {
            btn.disabled = true;
            btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1.5"></i> Scanning...`;
            btn.classList.add('opacity-75');
        } else {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-magnifying-glass mr-1.5"></i> Scan Subnet`;
            btn.classList.remove('opacity-75');
        }
    }

    if (radar) {
        if (scanning) {
            radar.classList.add('radar-sweep-animation', 'text-[#00e5ff]');
        } else {
            radar.classList.remove('radar-sweep-animation', 'text-[#00e5ff]');
        }
    }

    if (progressContainer) {
        if (scanning) {
            progressContainer.classList.remove('hidden');
        } else {
            setTimeout(() => {
                progressContainer.classList.add('hidden');
            }, 1500);
        }
    }
}

function renderDiscoveredHosts(hosts) {
    const grid = document.getElementById('hostsGrid');
    const tbody = document.getElementById('hostsTableBody');
    if (!grid || !tbody) return;

    // Filter by search query if any
    const searchInput = document.getElementById('hostSearchInput');
    const query = searchInput ? searchInput.value.toLowerCase().trim() : '';
    const filtered = query
        ? hosts.filter(h => 
            h.ip.toLowerCase().includes(query) ||
            h.hostname.toLowerCase().includes(query) ||
            h.mac.toLowerCase().includes(query) ||
            h.vendor.toLowerCase().includes(query)
          )
        : hosts;

    // Render Cards
    grid.innerHTML = filtered.map(h => {
        let roleBadge = '<span class="text-xs px-2 py-0.5 rounded bg-[#181d2c] text-slate-200 border border-[#222a3d]">Host</span>';
        let cardBorder = 'border-[#222a3d]';

        if (h.is_self) {
            roleBadge = '<span class="text-xs px-2 py-0.5 rounded bg-cyan-950 text-[#00e5ff] border border-cyan-700 font-semibold">Local Machine</span>';
            cardBorder = 'border-cyan-500/70';
        } else if (h.is_gateway) {
            roleBadge = '<span class="text-xs px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-700 font-semibold">Default Gateway</span>';
            cardBorder = 'border-emerald-500/70';
        }

        let latencyColor = 'text-emerald-300 bg-emerald-950 border-emerald-700';
        if (h.latency_ms > 100) latencyColor = 'text-[#f43f5e] bg-rose-950 border-rose-700';
        else if (h.latency_ms > 30) latencyColor = 'text-[#f59e0b] bg-amber-950 border-amber-700';

        return `
        <div class="glass-panel-interactive rounded-xl p-4 border ${cardBorder} flex flex-col justify-between">
            <div>
                <div class="flex items-start justify-between mb-2.5">
                    <div class="flex items-center space-x-2">
                        <div class="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-live-pulse"></div>
                        <span class="font-mono font-bold text-base text-white">${h.ip}</span>
                    </div>
                    ${roleBadge}
                </div>
                
                <div class="space-y-1.5 text-xs text-slate-300 mb-3">
                    <div class="flex justify-between">
                        <span class="text-slate-400">Hostname:</span>
                        <span class="text-slate-100 font-medium truncate max-w-[150px]" title="${h.hostname}">${h.hostname || '-'}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-slate-400">MAC:</span>
                        <span class="font-mono text-[#00e5ff] font-semibold">${h.mac}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-slate-400">Vendor:</span>
                        <span class="text-slate-200 truncate max-w-[150px]" title="${h.vendor}">${h.vendor}</span>
                    </div>
                    <div class="flex justify-between items-center pt-1 border-t border-[#222a3d]">
                        <span class="text-slate-400">Latency:</span>
                        <span class="font-mono text-xs px-2 py-0.5 rounded border ${latencyColor} font-bold">${h.latency_ms} ms</span>
                    </div>
                </div>
            </div>

            <div class="pt-2.5 border-t border-[#222a3d] flex items-center justify-between">
                <button onclick="openPortScanner('${h.ip}')" class="text-xs px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 text-[#00e5ff] border border-cyan-700 transition flex items-center font-medium">
                    <i class="fa-solid fa-shield-halved mr-1.5"></i> Scan Ports
                </button>
                <button onclick="navigator.clipboard.writeText('${h.ip}')" class="text-xs text-slate-300 hover:text-white transition" title="Copy IP">
                    <i class="fa-regular fa-copy"></i>
                </button>
            </div>
        </div>
        `;
    }).join('');

    // Render Table Rows
    tbody.innerHTML = filtered.map(h => {
        let roleText = 'Host';
        if (h.is_self) roleText = 'Local Machine';
        if (h.is_gateway) roleText = 'Gateway Router';

        return `
        <tr class="border-b border-[#222a3d] hover:bg-[#181d2c] text-xs transition">
            <td class="py-2.5 px-4 font-mono font-bold text-white flex items-center space-x-2">
                <span class="w-2 h-2 rounded-full bg-emerald-400"></span>
                <span>${h.ip}</span>
            </td>
            <td class="py-2.5 px-4 text-slate-200">${h.hostname || '-'}</td>
            <td class="py-2.5 px-4 font-mono text-[#00e5ff] font-semibold">${h.mac}</td>
            <td class="py-2.5 px-4 text-slate-200">${h.vendor}</td>
            <td class="py-2.5 px-4 font-mono text-slate-100">${h.latency_ms} ms</td>
            <td class="py-2.5 px-4 text-slate-300">${roleText}</td>
            <td class="py-2.5 px-4 text-right">
                <button onclick="openPortScanner('${h.ip}')" class="text-xs px-2.5 py-1 rounded bg-[#181d2c] hover:bg-cyan-950 text-[#00e5ff] border border-[#222a3d] hover:border-cyan-700 transition font-medium">
                    Scan Ports
                </button>
            </td>
        </tr>
        `;
    }).join('');
}

function filterHosts() {
    renderDiscoveredHosts(currentDiscoveredHosts);
}

// Port Scanner Modal Logic
async function openPortScanner(ip) {
    const modal = document.getElementById('portScanModal');
    const targetLabel = document.getElementById('portScanTargetIp');
    const resultsContainer = document.getElementById('portScanResults');
    const spinner = document.getElementById('portScanSpinner');

    if (!modal) return;
    targetLabel.innerText = ip;
    resultsContainer.innerHTML = '';
    spinner.classList.remove('hidden');
    modal.classList.remove('hidden');

    try {
        const resp = await fetch('/api/scan/ports', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        });
        const data = await resp.json();
        spinner.classList.add('hidden');

        if (!data.ports || data.ports.length === 0) {
            resultsContainer.innerHTML = `
                <div class="text-center py-5 text-slate-300">
                    <i class="fa-solid fa-shield text-2xl text-slate-500 mb-1.5"></i>
                    <p class="font-medium">No open service ports detected on <span class="font-mono text-white">${ip}</span>.</p>
                    <p class="text-xs text-slate-400 mt-0.5">Target host may have an active firewall rejecting probes.</p>
                </div>
            `;
            return;
        }

        resultsContainer.innerHTML = `
            <div class="mb-2.5 text-xs text-slate-200 font-semibold">
                Detected <span class="font-bold text-emerald-300">${data.ports.length}</span> accessible ports:
            </div>
            <div class="grid grid-cols-1 md:grid-cols-2 gap-2">
                ${data.ports.map(p => `
                    <div class="flex items-center justify-between p-2.5 rounded-lg bg-[#181d2c] border border-[#222a3d]">
                        <div class="flex items-center space-x-2">
                            <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                            <span class="font-mono font-bold text-[#00e5ff]">${p.port}</span>
                            <span class="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-200 border border-slate-700 font-medium">${p.service}</span>
                        </div>
                        <span class="text-xs font-mono text-slate-300 font-semibold">${p.latency_ms} ms</span>
                    </div>
                `).join('')}
            </div>
        `;
    } catch (e) {
        spinner.classList.add('hidden');
        resultsContainer.innerHTML = `<div class="p-3 text-rose-300">Port scan operation failed: ${e}</div>`;
    }
}

function closePortScanner() {
    const modal = document.getElementById('portScanModal');
    if (modal) modal.classList.add('hidden');
}
