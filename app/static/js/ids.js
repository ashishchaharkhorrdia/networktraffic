/**
 * CyberNinjas - Intrusion Detection System (IDS) & Threat Intelligence Module
 */

let allIdsAlerts = [];
let idsActiveFilter = 'ALL';
let idsSearchQuery = '';

async function initIds() {
    await fetchIdsAlerts();
}

async function fetchIdsAlerts() {
    try {
        const resp = await fetch('/api/ids/alerts');
        const data = await resp.json();
        allIdsAlerts = data.alerts || [];
        renderIdsStats(data.stats);
        renderIdsAlerts();
    } catch (e) {
        console.error('Failed to load IDS alerts', e);
    }
}

function renderIdsStats(stats) {
    if (!stats) return;

    const totalEl = document.getElementById('idsTotalAlerts');
    const critEl = document.getElementById('idsCriticalAlerts');
    const highEl = document.getElementById('idsHighAlerts');
    const medEl = document.getElementById('idsMediumAlerts');
    const mitEl = document.getElementById('idsMitigatedAlerts');
    const postureEl = document.getElementById('idsPostureStatus');

    if (totalEl) totalEl.innerText = stats.total_alerts || 0;
    if (critEl) critEl.innerText = stats.critical || 0;
    if (highEl) highEl.innerText = stats.high || 0;
    if (medEl) medEl.innerText = stats.medium || 0;
    if (mitEl) mitEl.innerText = stats.mitigated || 0;

    if (postureEl) {
        const level = stats.threat_level || 'NORMAL';
        if (level === 'ELEVATED') {
            postureEl.className = 'font-bold text-[#f43f5e] font-mono tracking-wide';
            postureEl.innerText = 'ELEVATED';
        } else if (level === 'GUARDED') {
            postureEl.className = 'font-bold text-[#f59e0b] font-mono tracking-wide';
            postureEl.innerText = 'GUARDED';
        } else {
            postureEl.className = 'font-bold text-[#10b981] font-mono tracking-wide';
            postureEl.innerText = 'NORMAL';
        }
    }

    // Update navbar badge
    const navBadge = document.getElementById('navAlertBadge');
    const tabBadge = document.getElementById('tabAlertPill');
    const unmitigated = stats.unmitigated || 0;

    if (navBadge) {
        navBadge.innerText = unmitigated;
        navBadge.style.display = unmitigated > 0 ? 'inline-block' : 'none';
    }
    if (tabBadge) {
        tabBadge.innerText = unmitigated;
    }
}

function filterIdsBySeverity(severity) {
    idsActiveFilter = severity;
    // Update active filter pill style
    document.querySelectorAll('.ids-filter-btn').forEach(btn => {
        if (btn.getAttribute('data-severity') === severity) {
            btn.className = 'ids-filter-btn px-3 py-1 rounded-lg text-xs font-semibold bg-cyan-600 text-white transition';
        } else {
            btn.className = 'ids-filter-btn px-3 py-1 rounded-lg text-xs font-medium bg-[#181d2c] text-slate-300 hover:text-white border border-[#222a3d] transition';
        }
    });
    renderIdsAlerts();
}

function filterIdsSearch(query) {
    idsSearchQuery = query.toLowerCase().trim();
    renderIdsAlerts();
}

function renderIdsAlerts() {
    const tbody = document.getElementById('idsTableBody');
    if (!tbody) return;

    let filtered = allIdsAlerts;

    if (idsActiveFilter !== 'ALL') {
        filtered = filtered.filter(a => a.severity.toUpperCase() === idsActiveFilter);
    }

    if (idsSearchQuery) {
        filtered = filtered.filter(a =>
            a.title.toLowerCase().includes(idsSearchQuery) ||
            a.source_ip.toLowerCase().includes(idsSearchQuery) ||
            a.category.toLowerCase().includes(idsSearchQuery) ||
            a.description.toLowerCase().includes(idsSearchQuery)
        );
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="py-8 text-center text-slate-400">
                    <i class="fa-solid fa-shield-check text-2xl mb-2 text-[#10b981]"></i>
                    <p class="font-medium text-slate-200">No matching threat alerts found.</p>
                    <p class="text-xs text-slate-400 mt-0.5">Network telemetry indicates clean operating conditions.</p>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = filtered.map(alert => {
        // Severity badge
        let sevBadge = '';
        if (alert.severity === 'CRITICAL') {
            sevBadge = `<span class="px-2 py-0.5 rounded text-[11px] bg-rose-950 text-[#f43f5e] border border-rose-800 font-mono font-bold">CRITICAL</span>`;
        } else if (alert.severity === 'HIGH') {
            sevBadge = `<span class="px-2 py-0.5 rounded text-[11px] bg-amber-950 text-[#f59e0b] border border-amber-800 font-mono font-bold">HIGH</span>`;
        } else if (alert.severity === 'MEDIUM') {
            sevBadge = `<span class="px-2 py-0.5 rounded text-[11px] bg-cyan-950 text-[#00e5ff] border border-cyan-800 font-mono font-bold">MEDIUM</span>`;
        } else {
            sevBadge = `<span class="px-2 py-0.5 rounded text-[11px] bg-slate-800 text-slate-300 border border-slate-700 font-mono font-bold">INFO</span>`;
        }

        // Mitigation status
        const mitBadge = alert.mitigated
            ? `<span class="px-2 py-0.5 rounded text-xs bg-emerald-950 text-emerald-300 border border-emerald-700 font-semibold flex items-center space-x-1.5 w-max">
                 <span class="w-1.5 h-1.5 rounded-full bg-emerald-400"></span>
                 <span>BLOCKED</span>
               </span>`
            : `<span class="px-2 py-0.5 rounded text-xs bg-rose-950/80 text-rose-300 border border-rose-800 font-semibold flex items-center space-x-1.5 w-max">
                 <span class="w-1.5 h-1.5 rounded-full bg-rose-400 animate-live-pulse"></span>
                 <span>ACTIVE THREAT</span>
               </span>`;

        // Action button
        const actionBtn = alert.mitigated
            ? `<span class="text-xs text-emerald-400 font-mono font-medium"><i class="fa-solid fa-check mr-1"></i>Mitigated</span>`
            : `<button onclick="mitigateThreatAlert('${alert.id}')" class="px-2.5 py-1 rounded bg-rose-950/80 hover:bg-rose-900 border border-rose-800 text-[#f43f5e] hover:text-white text-xs font-semibold transition flex items-center space-x-1" title="Block source IP in Firewall">
                 <i class="fa-solid fa-shield-slash"></i>
                 <span>Block IP</span>
               </button>`;

        return `
        <tr class="border-b border-[#222a3d] hover:bg-[#181d2c] text-xs transition">
            <td class="py-2.5 px-4 font-mono text-slate-400 whitespace-nowrap">${alert.timestamp || '-'}</td>
            <td class="py-2.5 px-4">${sevBadge}</td>
            <td class="py-2.5 px-4 font-mono font-bold text-white">
                <span class="text-[#00e5ff] mr-1.5"><i class="fa-solid fa-crosshairs text-xs"></i></span>
                <span>${alert.source_ip || '-'}</span>
            </td>
            <td class="py-2.5 px-4 font-mono text-slate-300">${alert.target_port || '-'}</td>
            <td class="py-2.5 px-4 text-slate-200">
                <div class="font-bold text-white">${alert.title}</div>
                <div class="text-slate-400 text-[11px] truncate max-w-sm mt-0.5" title="${alert.description}">${alert.description}</div>
            </td>
            <td class="py-2.5 px-4">${mitBadge}</td>
            <td class="py-2.5 px-4 text-right">${actionBtn}</td>
        </tr>
        `;
    }).join('');
}

async function mitigateThreatAlert(alertId) {
    try {
        const resp = await fetch('/api/ids/mitigate', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ alert_id: alertId })
        });
        const res = await resp.json();
        if (res.success) {
            await fetchIdsAlerts();
            if (typeof fetchFirewallRules === 'function') {
                await fetchFirewallRules();
            }
        }
    } catch (e) {
        alert('Failed to mitigate threat: ' + e);
    }
}

async function clearAllIdsAlerts() {
    if (!confirm('Clear all recorded IDS security alerts?')) return;
    try {
        const resp = await fetch('/api/ids/clear', { method: 'POST' });
        const res = await resp.json();
        if (res.success) {
            await fetchIdsAlerts();
        }
    } catch (e) {
        alert('Failed to clear alerts: ' + e);
    }
}
