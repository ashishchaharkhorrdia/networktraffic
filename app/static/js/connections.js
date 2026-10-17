/**
 * CyberNinjas - Active Sockets and Process Attribution Client Module
 */

let allConnections = [];
let currentFilter = 'ALL';
let connectionSearchQuery = '';

async function loadConnections() {
    try {
        const resp = await fetch('/api/connections?limit=200');
        const data = await resp.json();
        allConnections = data.connections || [];
        renderConnectionsTable();
        renderTopTalkers(data.top_remote_ips || []);
        renderCountryDistribution(data.country_distribution || {});
    } catch (e) {
        console.error('Failed to fetch connections', e);
    }
}

function renderCountryDistribution(dist) {
    const container = document.getElementById('countryDistributionList');
    if (!container) return;

    const entries = Object.entries(dist || {}).sort((a, b) => b[1] - a[1]);
    if (entries.length === 0) {
        container.innerHTML = `<div class="text-xs text-slate-400 py-2">No active foreign country routes.</div>`;
        return;
    }

    container.innerHTML = entries.slice(0, 6).map(([country, count]) => `
        <div class="flex items-center justify-between p-2 rounded-lg bg-[#181d2c] border border-[#222a3d] text-xs">
            <div class="flex items-center space-x-2">
                <i class="fa-solid fa-earth-americas text-xs text-[#00e5ff]"></i>
                <span class="font-medium text-white truncate max-w-[130px]">${country}</span>
            </div>
            <span class="px-2 py-0.5 rounded text-xs bg-cyan-950 text-[#00e5ff] font-mono border border-cyan-800 font-bold">${count} ${count === 1 ? 'conn' : 'conns'}</span>
        </div>
    `).join('');
}

function setConnectionFilter(filter) {
    currentFilter = filter;
    
    // Update button styles
    document.querySelectorAll('.filter-btn').forEach(btn => {
        if (btn.dataset.filter === filter) {
            btn.className = 'filter-btn px-2.5 py-1 rounded bg-cyan-600 text-white border border-cyan-500 font-semibold transition';
        } else {
            btn.className = 'filter-btn px-2.5 py-1 rounded bg-[#181d2c] text-slate-300 hover:text-white border border-[#222a3d] transition';
        }
    });

    renderConnectionsTable();
}

function handleConnectionSearch(query) {
    connectionSearchQuery = query.toLowerCase().trim();
    renderConnectionsTable();
}

function renderConnectionsTable() {
    const tbody = document.getElementById('connectionsTableBody');
    const totalBadge = document.getElementById('connFilteredCount');
    if (!tbody) return;

    let filtered = allConnections;

    // Apply status filter
    if (currentFilter !== 'ALL') {
        if (currentFilter === 'UDP') {
            filtered = filtered.filter(c => c.proto === 'UDP');
        } else {
            filtered = filtered.filter(c => c.status === currentFilter);
        }
    }

    // Apply search filter
    if (connectionSearchQuery) {
        filtered = filtered.filter(c =>
            (c.local_ip && c.local_ip.includes(connectionSearchQuery)) ||
            (c.remote_ip && c.remote_ip.includes(connectionSearchQuery)) ||
            (c.remote_host && c.remote_host.toLowerCase().includes(connectionSearchQuery)) ||
            (c.process && c.process.toLowerCase().includes(connectionSearchQuery)) ||
            (c.service && c.service.toLowerCase().includes(connectionSearchQuery)) ||
            (c.local_port && c.local_port.toString().includes(connectionSearchQuery)) ||
            (c.remote_port && c.remote_port.toString().includes(connectionSearchQuery))
        );
    }

    if (totalBadge) {
        totalBadge.innerText = `${filtered.length} connections`;
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="py-8 text-center text-slate-400">
                    <i class="fa-solid fa-network-wired text-2xl mb-2 text-slate-500"></i>
                    <p class="font-medium">No matching network connections found.</p>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = filtered.map(c => {
        // Status styling with high contrast
        let statusBadge = '<span class="px-2 py-0.5 rounded text-xs bg-[#181d2c] text-slate-300 border border-[#222a3d] font-mono">NONE</span>';
        if (c.status === 'ESTABLISHED') {
            statusBadge = '<span class="px-2 py-0.5 rounded text-xs bg-emerald-950 text-emerald-300 border border-emerald-700 font-mono font-semibold">ESTABLISHED</span>';
        } else if (c.status === 'LISTEN') {
            statusBadge = '<span class="px-2 py-0.5 rounded text-xs bg-cyan-950 text-[#00e5ff] border border-cyan-800 font-mono font-semibold">LISTEN</span>';
        } else if (c.status === 'TIME_WAIT') {
            statusBadge = '<span class="px-2 py-0.5 rounded text-xs bg-amber-950 text-[#f59e0b] border border-amber-800 font-mono font-semibold">TIME_WAIT</span>';
        } else if (c.status === 'CLOSE_WAIT') {
            statusBadge = '<span class="px-2 py-0.5 rounded text-xs bg-rose-950 text-[#f43f5e] border border-rose-800 font-mono font-semibold">CLOSE_WAIT</span>';
        }

        const protoBadge = c.proto === 'TCP'
            ? '<span class="px-2 py-0.5 rounded text-xs bg-cyan-950 text-[#00e5ff] border border-cyan-800 font-mono font-bold">TCP</span>'
            : '<span class="px-2 py-0.5 rounded text-xs bg-amber-950 text-[#f59e0b] border border-amber-800 font-mono font-bold">UDP</span>';

        // Process Icon
        let procIcon = 'fa-gear';
        if (c.process.includes('chrome') || c.process.includes('firefox') || c.process.includes('browser')) procIcon = 'fa-globe';
        else if (c.process.includes('python')) procIcon = 'fa-brands fa-python';
        else if (c.process.includes('node')) procIcon = 'fa-brands fa-node-js';
        else if (c.process.includes('code')) procIcon = 'fa-code';
        else if (c.process.includes('sql')) procIcon = 'fa-database';

        const remoteDisplay = c.remote_ip ? `${c.remote_ip}:${c.remote_port}` : '<span class="text-slate-500 font-bold">*</span>';
        const hostnameDisplay = c.remote_host && c.remote_host !== c.remote_ip
            ? `<div class="text-xs text-[#00e5ff] truncate max-w-[200px]" title="${c.remote_host}">${c.remote_host}</div>`
            : '';

        return `
        <tr class="border-b border-[#222a3d] hover:bg-[#181d2c] text-xs transition">
            <td class="py-2 px-4">${protoBadge}</td>
            <td class="py-2 px-4 font-mono text-slate-200">${c.local_ip}:${c.local_port}</td>
            <td class="py-2 px-4 font-mono text-white">
                <div>${remoteDisplay}</div>
                ${hostnameDisplay}
            </td>
            <td class="py-2 px-4">
                ${c.remote_ip && c.geoip ? `
                <div class="flex items-center space-x-1.5">
                    <span class="px-1.5 py-0.5 rounded text-[10px] bg-[#181d2c] border border-[#222a3d] font-mono text-[#00e5ff] font-bold">${c.geoip.country_code}</span>
                    <span class="text-xs text-slate-300 truncate max-w-[130px]" title="${c.geoip.country} • ${c.geoip.org}">${c.geoip.country}</span>
                </div>
                ` : '<span class="text-slate-500 font-mono text-xs">Localhost</span>'}
            </td>
            <td class="py-2 px-4">${statusBadge}</td>
            <td class="py-2 px-4">
                <div class="flex items-center space-x-2">
                    <i class="fa-solid ${procIcon} text-[#00e5ff] text-xs"></i>
                    <span class="font-medium text-slate-100">${c.process}</span>
                    ${c.pid ? `<span class="text-slate-400 font-mono text-xs">(${c.pid})</span>` : ''}
                </div>
            </td>
            <td class="py-2 px-4">
                <span class="px-2 py-0.5 rounded text-xs bg-[#181d2c] text-[#00e5ff] border border-[#222a3d] font-mono font-medium">${c.service}</span>
            </td>
            <td class="py-2 px-4 text-right">
                ${c.remote_ip ? `
                <button onclick="openPortScanner('${c.remote_ip}')" class="text-xs px-2 py-1 rounded bg-[#181d2c] hover:bg-cyan-950 text-[#00e5ff] border border-[#222a3d] hover:border-cyan-700 transition" title="Inspect Remote Host">
                    <i class="fa-solid fa-magnifying-glass"></i>
                </button>
                ` : ''}
            </td>
        </tr>
        `;
    }).join('');
}

function renderTopTalkers(topIps) {
    const list = document.getElementById('topTalkersList');
    if (!list) return;

    if (!topIps || topIps.length === 0) {
        list.innerHTML = `<div class="text-xs text-slate-400 py-2">No active remote endpoints.</div>`;
        return;
    }

    list.innerHTML = topIps.map(item => `
        <div class="flex items-center justify-between p-2 rounded-lg bg-[#181d2c] border border-[#222a3d] hover:border-[#00e5ff]/50 transition text-xs">
            <div class="flex items-center space-x-2 overflow-hidden">
                <div class="w-1.5 h-1.5 rounded-full bg-[#00e5ff]"></div>
                <div class="overflow-hidden">
                    <div class="font-mono font-semibold text-white truncate text-xs">${item.ip}</div>
                    <div class="text-[11px] text-slate-400 truncate">${item.host !== item.ip ? item.host : 'Remote Host'}</div>
                </div>
            </div>
            <div class="flex items-center space-x-1.5 pl-2">
                <span class="px-2 py-0.5 rounded text-xs bg-cyan-950 text-[#00e5ff] font-mono border border-cyan-800 font-semibold">
                    ${item.count} conn
                </span>
                <button onclick="openPortScanner('${item.ip}')" class="text-slate-400 hover:text-[#00e5ff] transition" title="Scan Host">
                    <i class="fa-solid fa-crosshairs text-xs"></i>
                </button>
            </div>
        </div>
    `).join('');
}
