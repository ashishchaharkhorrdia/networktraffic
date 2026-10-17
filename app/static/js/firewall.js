/**
 * CyberNinjas - Firewall & IP / Domain Blocker Module
 */

let allFirewallRules = [];
let firewallSearchQuery = '';

async function initFirewall() {
    await fetchFirewallRules();
}

async function fetchFirewallRules() {
    try {
        const resp = await fetch('/api/firewall/rules');
        const data = await resp.json();
        allFirewallRules = data.rules || [];
        renderFirewallStats(data.stats);
        renderFirewallRules();
    } catch (e) {
        console.error('Failed to load firewall rules', e);
    }
}

function renderFirewallStats(stats) {
    if (!stats) return;
    const totalEl = document.getElementById('fwTotalRules');
    const ipsEl = document.getElementById('fwBlockedIps');
    const domainsEl = document.getElementById('fwBlockedDomains');
    const hitsEl = document.getElementById('fwTotalHits');

    if (totalEl) totalEl.innerText = stats.total_rules || 0;
    if (ipsEl) ipsEl.innerText = stats.blocked_ips || 0;
    if (domainsEl) domainsEl.innerText = stats.blocked_domains || 0;
    if (hitsEl) hitsEl.innerText = (stats.total_intercepted || 0).toLocaleString();
}

function filterFirewallRules(query) {
    firewallSearchQuery = query.toLowerCase().trim();
    renderFirewallRules();
}

function renderFirewallRules() {
    const tbody = document.getElementById('firewallTableBody');
    if (!tbody) return;

    let filtered = allFirewallRules;
    if (firewallSearchQuery) {
        filtered = filtered.filter(r =>
            r.target.toLowerCase().includes(firewallSearchQuery) ||
            r.reason.toLowerCase().includes(firewallSearchQuery) ||
            r.target_type.toLowerCase().includes(firewallSearchQuery)
        );
    }

    if (filtered.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="py-8 text-center text-slate-400">
                    <i class="fa-solid fa-shield-virus text-2xl mb-2 text-slate-500"></i>
                    <p class="font-medium">No matching firewall block rules active.</p>
                    <p class="text-xs text-slate-500 mt-0.5">Add an IP or Domain using the input above to begin blocking traffic.</p>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = filtered.map(rule => {
        const isIp = rule.target_type === 'ip';
        const typeBadge = isIp
            ? `<span class="px-2 py-0.5 rounded text-xs bg-amber-950 text-[#f59e0b] border border-amber-800 font-mono font-bold">IP ADDR</span>`
            : `<span class="px-2 py-0.5 rounded text-xs bg-cyan-950 text-[#00e5ff] border border-cyan-800 font-mono font-bold">WEBSITE</span>`;

        const icon = isIp ? 'fa-network-wired text-[#f59e0b]' : 'fa-globe text-[#00e5ff]';

        const statusBadge = rule.is_active
            ? `<span class="px-2 py-0.5 rounded text-xs bg-emerald-950 text-emerald-300 border border-emerald-700 font-semibold flex items-center space-x-1.5 w-max">
                 <span class="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-live-pulse"></span>
                 <span>ACTIVE BLOCK</span>
               </span>`
            : `<span class="px-2 py-0.5 rounded text-xs bg-slate-800 text-slate-400 border border-slate-700 font-semibold flex items-center space-x-1.5 w-max">
                 <span class="w-1.5 h-1.5 rounded-full bg-slate-500"></span>
                 <span>PAUSED</span>
               </span>`;

        const toggleBtnText = rule.is_active
            ? `<i class="fa-solid fa-pause text-amber-400"></i>`
            : `<i class="fa-solid fa-play text-emerald-400"></i>`;
        const toggleBtnTitle = rule.is_active ? "Pause Rule" : "Activate Rule";

        return `
        <tr class="border-b border-[#222a3d] hover:bg-[#181d2c] text-xs transition">
            <td class="py-2.5 px-4 font-mono font-bold text-white flex items-center space-x-2">
                <i class="fa-solid ${icon} text-xs"></i>
                <span class="truncate max-w-[240px]" title="${rule.target}">${rule.target}</span>
            </td>
            <td class="py-2.5 px-4">${typeBadge}</td>
            <td class="py-2.5 px-4 text-slate-200">
                <div class="truncate max-w-[280px]" title="${rule.reason}">${rule.reason || '-'}</div>
            </td>
            <td class="py-2.5 px-4 font-mono text-slate-400">${rule.created_at || '-'}</td>
            <td class="py-2.5 px-4">
                <span class="px-2 py-0.5 rounded bg-rose-950/80 text-[#f43f5e] font-mono font-bold border border-rose-800">
                    ${(rule.hits || 0).toLocaleString()} drops
                </span>
            </td>
            <td class="py-2.5 px-4">${statusBadge}</td>
            <td class="py-2.5 px-4 text-right">
                <div class="flex items-center justify-end space-x-2">
                    <button onclick="toggleFirewallRule('${rule.id}')" class="text-xs p-1.5 rounded bg-[#181d2c] hover:bg-[#20273b] border border-[#222a3d] text-slate-300 hover:text-white transition" title="${toggleBtnTitle}">
                        ${toggleBtnText}
                    </button>
                    <button onclick="deleteFirewallRule('${rule.id}')" class="text-xs p-1.5 rounded bg-rose-950/60 hover:bg-rose-900 text-rose-300 border border-rose-800 transition" title="Unblock / Remove Rule">
                        <i class="fa-solid fa-trash-can"></i>
                    </button>
                </div>
            </td>
        </tr>
        `;
    }).join('');
}

async function handleAddBlockRule(event) {
    if (event) event.preventDefault();

    const targetInput = document.getElementById('fwTargetInput');
    const typeSelect = document.getElementById('fwTypeSelect');
    const reasonInput = document.getElementById('fwReasonInput');

    const target = targetInput ? targetInput.value.trim() : '';
    const type = typeSelect ? typeSelect.value : null;
    const reason = reasonInput ? reasonInput.value.trim() : '';

    if (!target) {
        alert('Please specify an IP address or Website/Domain to block.');
        return;
    }

    try {
        const resp = await fetch('/api/firewall/block', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                target: target,
                target_type: type === 'auto' ? null : type,
                reason: reason || `Manual block rule for ${target}`
            })
        });

        const res = await resp.json();
        if (res.success) {
            if (targetInput) targetInput.value = '';
            if (reasonInput) reasonInput.value = '';
            await fetchFirewallRules();
        } else {
            alert('Failed to add rule: ' + (res.detail || res.error));
        }
    } catch (e) {
        alert('Error adding block rule: ' + e);
    }
}

async function deleteFirewallRule(ruleId) {
    if (!confirm('Are you sure you want to unblock this target?')) return;

    try {
        const resp = await fetch('/api/firewall/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule_id: ruleId })
        });
        const res = await resp.json();
        if (res.success) {
            await fetchFirewallRules();
        }
    } catch (e) {
        alert('Error deleting rule: ' + e);
    }
}

async function toggleFirewallRule(ruleId) {
    try {
        const resp = await fetch('/api/firewall/toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ rule_id: ruleId })
        });
        const res = await resp.json();
        if (res.success) {
            await fetchFirewallRules();
        }
    } catch (e) {
        console.error('Error toggling rule: ' + e);
    }
}

function quickPresetBlock(target, type, reason) {
    const targetInput = document.getElementById('fwTargetInput');
    const typeSelect = document.getElementById('fwTypeSelect');
    const reasonInput = document.getElementById('fwReasonInput');

    if (targetInput) targetInput.value = target;
    if (typeSelect) typeSelect.value = type;
    if (reasonInput) reasonInput.value = reason;

    handleAddBlockRule();
}
