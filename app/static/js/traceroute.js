/**
 * CyberNinjas - Visual Hop-by-Hop Traceroute Module
 */

let isTracingRoute = false;

async function runVisualTraceroute() {
    if (isTracingRoute) return;

    const input = document.getElementById('tracerouteTargetInput');
    const hopsSelect = document.getElementById('tracerouteHopsSelect');
    const target = input ? input.value.trim() : '';
    const maxHops = hopsSelect ? parseInt(hopsSelect.value, 10) : 15;

    if (!target) {
        alert('Please specify a valid hostname or destination IP address.');
        return;
    }

    const btn = document.getElementById('btnStartTraceroute');
    const spinner = document.getElementById('tracerouteSpinner');
    const resultsContainer = document.getElementById('tracerouteResultsContainer');
    const hopsList = document.getElementById('tracerouteHopsList');

    isTracingRoute = true;
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-1.5"></i> Probing Route...`;
    }
    if (spinner) spinner.classList.remove('hidden');
    if (resultsContainer) resultsContainer.classList.add('hidden');

    try {
        const resp = await fetch('/api/diagnostics/traceroute', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ target: target, max_hops: maxHops })
        });

        const data = await resp.json();

        if (!resp.ok) {
            throw new Error(data.detail || 'Traceroute failed');
        }

        renderTracerouteResults(data);
    } catch (e) {
        alert('Traceroute error: ' + e.message);
    } finally {
        isTracingRoute = false;
        if (btn) {
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-route mr-1.5"></i> Trace Path`;
        }
        if (spinner) spinner.classList.add('hidden');
    }
}

function renderTracerouteResults(data) {
    const resultsContainer = document.getElementById('tracerouteResultsContainer');
    const hopsList = document.getElementById('tracerouteHopsList');
    if (!resultsContainer || !hopsList) return;

    // Header metrics
    const targetEl = document.getElementById('traceResultTarget');
    const destGeoEl = document.getElementById('traceResultDestGeo');
    const hopsCountEl = document.getElementById('traceResultTotalHops');
    const avgLatencyEl = document.getElementById('traceResultAvgLatency');
    const statusEl = document.getElementById('traceResultStatus');

    if (targetEl) targetEl.innerText = `${data.target} (${data.target_ip})`;
    if (destGeoEl && data.target_geoip) {
        destGeoEl.innerText = `${data.target_geoip.country} • ${data.target_geoip.org}`;
    }
    if (hopsCountEl) hopsCountEl.innerText = `${data.total_hops} hops`;
    if (avgLatencyEl) avgLatencyEl.innerText = `${data.avg_latency_ms} ms avg`;
    if (statusEl) {
        if (data.reached_destination) {
            statusEl.className = 'px-2 py-0.5 rounded text-xs bg-emerald-950 text-emerald-300 border border-emerald-800 font-semibold';
            statusEl.innerText = 'REACHED DESTINATION';
        } else {
            statusEl.className = 'px-2 py-0.5 rounded text-xs bg-amber-950 text-amber-300 border border-amber-800 font-semibold';
            statusEl.innerText = 'PARTIAL / FILTERED';
        }
    }

    // Render Hops Node Graph
    const hops = data.hops || [];
    hopsList.innerHTML = hops.map((h, idx) => {
        const isTimeout = h.status === 'TIMEOUT';
        const isLast = idx === hops.length - 1;

        // Latency color
        let latencyBadge = '';
        if (isTimeout) {
            latencyBadge = `<span class="px-2 py-0.5 rounded text-xs font-mono bg-slate-800 text-slate-400 border border-slate-700">* Request Timed Out</span>`;
        } else if (h.rtt_ms < 30) {
            latencyBadge = `<span class="px-2 py-0.5 rounded text-xs font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">${h.rtt_ms} ms</span>`;
        } else if (h.rtt_ms < 90) {
            latencyBadge = `<span class="px-2 py-0.5 rounded text-xs font-mono font-bold bg-amber-950 text-[#f59e0b] border border-amber-800">${h.rtt_ms} ms</span>`;
        } else {
            latencyBadge = `<span class="px-2 py-0.5 rounded text-xs font-mono font-bold bg-rose-950 text-[#f43f5e] border border-rose-800">${h.rtt_ms} ms</span>`;
        }

        const geo = h.geoip || {};
        const countryText = geo.country || 'Unknown';
        const orgText = geo.org || 'Unknown Autonomous System';
        const isLocal = geo.is_local;

        const icon = isTimeout
            ? 'fa-ban text-slate-500'
            : (isLast ? 'fa-bullseye text-[#00e5ff]' : (isLocal ? 'fa-house-signal text-cyan-400' : 'fa-server text-slate-300'));

        return `
        <div class="relative flex items-start space-x-3 group">
            <!-- Hop Connector Line -->
            ${!isLast ? `<div class="absolute left-4 top-8 bottom-0 w-0.5 bg-[#222a3d] group-hover:bg-cyan-700/50 transition"></div>` : ''}

            <!-- Node Circle -->
            <div class="relative z-10 w-8 h-8 rounded-full bg-[#131722] border-2 ${isLast ? 'border-[#00e5ff] shadow-md shadow-cyan-900/50' : 'border-[#222a3d]'} flex items-center justify-center shrink-0">
                <i class="fa-solid ${icon} text-xs"></i>
            </div>

            <!-- Hop Card Content -->
            <div class="flex-1 bg-[#131722] hover:bg-[#181d2c] border border-[#222a3d] hover:border-cyan-800/70 rounded-xl p-3 mb-2.5 transition">
                <div class="flex flex-col sm:flex-row sm:items-center justify-between gap-1.5 mb-1.5">
                    <div class="flex items-center space-x-2">
                        <span class="px-2 py-0.5 rounded text-[10px] bg-[#181d2c] text-[#00e5ff] border border-[#222a3d] font-mono font-bold">HOP #${h.hop}</span>
                        <span class="font-mono font-bold text-white text-xs">${h.ip}</span>
                        ${h.hostname && h.hostname !== h.ip && !isTimeout ? `<span class="text-xs text-slate-400 truncate max-w-xs font-mono">(${h.hostname})</span>` : ''}
                    </div>
                    <div>${latencyBadge}</div>
                </div>

                <div class="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400">
                    <div class="flex items-center space-x-1.5">
                        <i class="fa-solid fa-earth-americas text-xs text-slate-500"></i>
                        <span class="text-slate-300 font-medium">${countryText}</span>
                    </div>
                    <div class="flex items-center space-x-1.5">
                        <i class="fa-solid fa-network-wired text-xs text-slate-500"></i>
                        <span class="text-slate-400 truncate max-w-sm">${orgText}</span>
                    </div>
                </div>
            </div>
        </div>
        `;
    }).join('');

    resultsContainer.classList.remove('hidden');
}
