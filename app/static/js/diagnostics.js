/**
 * CyberNinjas - Network Diagnostics, Latency Monitor & DNS Benchmark
 */

let diagnosticsInterval = null;

async function initDiagnostics() {
    await updateDiagnostics();
    await loadInterfaceCards();
    await runDnsBenchmark();
}

async function updateDiagnostics() {
    try {
        const resp = await fetch('/api/diagnostics/latency');
        const data = await resp.json();
        renderLatencyTargets(data.targets || []);
    } catch (e) {
        console.error('Failed to update latency diagnostics', e);
    }
}

function renderLatencyTargets(targets) {
    const container = document.getElementById('latencyTargetsGrid');
    if (!container) return;

    container.innerHTML = targets.map(t => {
        let statusBadge = '<span class="px-2 py-0.5 rounded text-xs bg-emerald-950 text-emerald-300 border border-emerald-700 font-semibold">ONLINE</span>';
        let latencyColor = 'text-emerald-300';
        
        if (t.status !== 'Online' || t.loss_pct > 0) {
            statusBadge = '<span class="px-2 py-0.5 rounded text-xs bg-rose-950 text-[#f43f5e] border border-rose-700 font-semibold">LOSS / TIMEOUT</span>';
            latencyColor = 'text-[#f43f5e]';
        } else if (t.latency_ms > 80) {
            latencyColor = 'text-[#f59e0b]';
        }

        return `
        <div class="glass-panel p-3.5 rounded-xl border border-[#222a3d]">
            <div class="flex items-center justify-between mb-1.5">
                <div class="font-bold text-white text-sm">${t.name}</div>
                ${statusBadge}
            </div>
            <div class="font-mono text-xs text-slate-300 font-semibold mb-2.5">${t.ip}</div>
            
            <div class="grid grid-cols-2 gap-2 text-xs pt-2 border-t border-[#222a3d]">
                <div>
                    <span class="text-slate-400 block font-medium">Latency (RTT)</span>
                    <span class="font-mono text-base font-bold ${latencyColor}">${t.latency_ms} <span class="text-xs font-normal text-slate-300">ms</span></span>
                </div>
                <div>
                    <span class="text-slate-400 block font-medium">Jitter</span>
                    <span class="font-mono text-base font-bold text-slate-100">±${t.jitter_ms} <span class="text-xs font-normal text-slate-300">ms</span></span>
                </div>
            </div>
        </div>
        `;
    }).join('');
}

async function runDnsBenchmark() {
    const list = document.getElementById('dnsBenchmarkList');
    if (!list) return;

    list.innerHTML = `
        <div class="p-4 text-center text-slate-300">
            <i class="fa-solid fa-spinner fa-spin text-lg text-[#00e5ff] mb-1.5"></i>
            <p class="text-xs font-medium">Benchmarking DNS lookup latency across target resolvers...</p>
        </div>
    `;

    try {
        const resp = await fetch('/api/diagnostics/dns');
        const data = await resp.json();
        
        list.innerHTML = (data.results || []).map(r => {
            let speedClass = 'text-emerald-300 bg-emerald-950 border-emerald-700';
            if (r.lookup_time_ms > 80) speedClass = 'text-[#f59e0b] bg-amber-950 border-amber-700';
            if (r.status !== 'Resolved') speedClass = 'text-[#f43f5e] bg-rose-950 border-rose-700';

            return `
            <div class="flex items-center justify-between p-2.5 rounded-lg bg-[#181d2c] border border-[#222a3d] text-xs">
                <div>
                    <div class="font-semibold text-white flex items-center space-x-1.5">
                        <i class="fa-solid fa-server text-[#00e5ff] text-xs"></i>
                        <span>${r.domain}</span>
                    </div>
                    <div class="text-[11px] text-slate-400 font-mono mt-0.5">
                        ${r.ips.length > 0 ? r.ips.join(', ') : (r.error || 'Resolution Failed')}
                    </div>
                </div>
                <div class="font-mono px-2 py-0.5 rounded border ${speedClass} font-bold text-xs">
                    ${r.lookup_time_ms} ms
                </div>
            </div>
            `;
        }).join('');
    } catch (e) {
        list.innerHTML = `<div class="p-3 text-rose-300 text-xs">DNS test error: ${e}</div>`;
    }
}

async function loadInterfaceCards() {
    const container = document.getElementById('interfacesGrid');
    if (!container) return;

    try {
        const resp = await fetch('/api/interfaces');
        const interfaces = await resp.json();

        container.innerHTML = interfaces.map(iface => {
            const rxMb = (iface.bytes_recv / (1024 * 1024)).toFixed(1);
            const txMb = (iface.bytes_sent / (1024 * 1024)).toFixed(1);
            const statusBadge = iface.is_up
                ? '<span class="px-2 py-0.5 rounded text-xs bg-emerald-950 text-emerald-300 border border-emerald-700 font-semibold">UP</span>'
                : '<span class="px-2 py-0.5 rounded text-xs bg-slate-800 text-slate-400 border border-slate-700 font-semibold">DOWN</span>';

            const defaultTag = iface.is_default ? '<span class="text-xs px-2 py-0.5 rounded bg-cyan-950 text-[#00e5ff] border border-cyan-800 font-bold">PRIMARY</span>' : '';

            return `
            <div class="glass-panel p-3.5 rounded-xl border border-[#222a3d]">
                <div class="flex items-center justify-between mb-2.5">
                    <div class="flex items-center space-x-2">
                        <i class="fa-solid fa-ethernet text-[#00e5ff]"></i>
                        <span class="font-bold text-white font-mono text-sm">${iface.name}</span>
                        ${defaultTag}
                    </div>
                    ${statusBadge}
                </div>

                <div class="space-y-1 text-xs text-slate-300 mb-3">
                    <div class="flex justify-between">
                        <span class="text-slate-400">IPv4 Address:</span>
                        <span class="font-mono text-white font-semibold">${iface.ipv4 || 'Unassigned'}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-slate-400">Subnet Mask:</span>
                        <span class="font-mono text-slate-300">${iface.netmask || '-'}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-slate-400">MAC Address:</span>
                        <span class="font-mono text-[#00e5ff] font-semibold">${iface.mac || '-'}</span>
                    </div>
                    <div class="flex justify-between">
                        <span class="text-slate-400">MTU:</span>
                        <span class="font-mono text-slate-300 font-semibold">${iface.mtu}</span>
                    </div>
                </div>

                <div class="grid grid-cols-2 gap-2 pt-2.5 border-t border-[#222a3d] text-xs">
                    <div>
                        <span class="text-slate-400 block font-medium">Inbound Total</span>
                        <span class="font-mono font-bold text-[#00e5ff] text-sm">${rxMb} MB</span>
                        <span class="text-slate-400 block font-mono text-[11px]">${iface.packets_recv.toLocaleString()} pkts</span>
                    </div>
                    <div>
                        <span class="text-slate-400 block font-medium">Outbound Total</span>
                        <span class="font-mono font-bold text-[#f59e0b] text-sm">${txMb} MB</span>
                        <span class="text-slate-400 block font-mono text-[11px]">${iface.packets_sent.toLocaleString()} pkts</span>
                    </div>
                </div>

                ${(iface.errin > 0 || iface.dropin > 0) ? `
                <div class="mt-2 text-xs text-rose-300 flex justify-between font-mono font-semibold pt-2 border-t border-[#222a3d]">
                    <span>Errors: ${iface.errin + iface.errout}</span>
                    <span>Drops: ${iface.dropin + iface.dropout}</span>
                </div>
                ` : ''}
            </div>
            `;
        }).join('');
    } catch (e) {
        console.error('Failed to load interfaces', e);
    }
}
