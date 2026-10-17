/**
 * CyberNinjas - Packet Capture & PCAP Protocol Analysis Module
 */

let capturedPackets = [];
let selectedPacketId = null;
let snifferPollInterval = null;
let currentProtoFilter = 'ALL';

async function initSniffer() {
    await fetchPackets();
}

async function fetchPackets() {
    try {
        const resp = await fetch(`/api/sniffer/packets?limit=150&proto=${currentProtoFilter}`);
        const data = await resp.json();
        
        capturedPackets = data.packets || [];
        renderPacketTable(capturedPackets);
        updateSnifferStats(data);
        
        // Handle permission banner
        const permBanner = document.getElementById('snifferPermBanner');
        if (permBanner) {
            if (!data.has_permission) {
                permBanner.classList.remove('hidden');
            } else {
                permBanner.classList.add('hidden');
            }
        }

        // Sniffing status button update
        updateSniffButtonState(data.is_sniffing);
    } catch (e) {
        console.error('Failed to fetch packets', e);
    }
}

function updateSnifferStats(data) {
    const totalEl = document.getElementById('sniffTotalCount');
    const bytesEl = document.getElementById('sniffTotalBytes');
    if (totalEl) totalEl.innerText = data.total_captured || 0;
    if (bytesEl) {
        const kb = ((data.total_bytes || 0) / 1024).toFixed(1);
        bytesEl.innerText = `${kb} KB`;
    }
}

function updateSniffButtonState(isSniffing) {
    const btn = document.getElementById('btnToggleSniff');
    if (!btn) return;

    if (isSniffing) {
        btn.innerHTML = `<i class="fa-solid fa-stop mr-1.5 text-rose-300"></i> Stop Capture`;
        btn.className = 'px-3.5 py-1.5 rounded-lg bg-rose-950 text-rose-200 border border-rose-700 text-xs font-semibold transition flex items-center shadow-sm';
    } else {
        btn.innerHTML = `<i class="fa-solid fa-play mr-1.5 text-emerald-300"></i> Start Live Capture`;
        btn.className = 'px-3.5 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-semibold transition flex items-center shadow-sm';
    }
}

async function toggleLiveSniff() {
    const filterInput = document.getElementById('bpfFilterInput');
    const filter = filterInput ? filterInput.value.trim() : '';

    const btn = document.getElementById('btnToggleSniff');
    const isStopping = btn && btn.innerText.includes('Stop');

    if (isStopping) {
        await fetch('/api/sniffer/stop', { method: 'POST' });
        if (snifferPollInterval) {
            clearInterval(snifferPollInterval);
            snifferPollInterval = null;
        }
        await fetchPackets();
    } else {
        const resp = await fetch('/api/sniffer/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ filter: filter })
        });
        const res = await resp.json();
        if (!res.success) {
            alert(res.error || 'Failed to initialize packet capture');
            return;
        }
        // Poll every 1s while sniffing
        if (!snifferPollInterval) {
            snifferPollInterval = setInterval(fetchPackets, 1000);
        }
        await fetchPackets();
    }
}

async function clearPacketBuffer() {
    await fetch('/api/sniffer/clear', { method: 'POST' });
    capturedPackets = [];
    renderPacketTable([]);
    document.getElementById('packetInspectorDrawer')?.classList.add('hidden');
    await fetchPackets();
}

async function generateDemoTraffic() {
    try {
        await fetch('/api/sniffer/demo?count=30', { method: 'POST' });
        await fetchPackets();
    } catch (e) {
        alert('Failed to synthesize test packets: ' + e);
    }
}

async function uploadPcapFile(event) {
    const file = event.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    const statusEl = document.getElementById('uploadPcapStatus');
    if (statusEl) statusEl.innerText = 'Parsing PCAP file...';

    try {
        const resp = await fetch('/api/sniffer/upload', {
            method: 'POST',
            body: formData
        });
        const res = await resp.json();
        if (res.success) {
            if (statusEl) statusEl.innerText = res.message;
            await fetchPackets();
        } else {
            alert('Upload failed: ' + (res.error || res.detail));
        }
    } catch (e) {
        alert('Error uploading PCAP: ' + e);
    }
}

function exportPcapFile() {
    window.location.href = '/api/sniffer/export';
}

function filterPacketsByProto(proto) {
    currentProtoFilter = proto;
    document.querySelectorAll('.sniff-filter-btn').forEach(btn => {
        if (btn.dataset.proto === proto) {
            btn.className = 'sniff-filter-btn px-2.5 py-0.5 rounded bg-cyan-600 text-white font-bold';
        } else {
            btn.className = 'sniff-filter-btn px-2.5 py-0.5 rounded bg-[#181d2c] text-slate-300 hover:text-white border border-[#222a3d]';
        }
    });
    fetchPackets();
}

function renderPacketTable(packets) {
    const tbody = document.getElementById('packetsTableBody');
    if (!tbody) return;

    if (packets.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" class="py-10 text-center text-slate-400">
                    <i class="fa-solid fa-satellite-dish text-2xl mb-2 text-slate-500"></i>
                    <p class="font-medium">No packets in capture buffer</p>
                    <p class="text-xs text-slate-400 mt-0.5">Start live capture, inject test traffic, or drop a PCAP file.</p>
                </td>
            </tr>
        `;
        return;
    }

    tbody.innerHTML = packets.map(p => {
        // High contrast protocol badges with Cyan & Amber accents
        let protoClass = 'bg-[#181d2c] text-slate-200 border-[#222a3d]';
        if (p.proto === 'TCP') protoClass = 'bg-cyan-950 text-[#00e5ff] border-cyan-800';
        else if (p.proto === 'UDP') protoClass = 'bg-amber-950 text-[#f59e0b] border-amber-800';
        else if (p.proto === 'ICMP') protoClass = 'bg-emerald-950 text-emerald-300 border-emerald-800';
        else if (p.proto === 'DNS') protoClass = 'bg-indigo-950 text-[#818cf8] border-indigo-800';
        else if (p.proto.includes('HTTP') || p.proto.includes('TLS')) protoClass = 'bg-sky-950 text-sky-300 border-sky-800';
        else if (p.proto === 'ARP') protoClass = 'bg-rose-950 text-[#f43f5e] border-rose-800';

        const isSelected = selectedPacketId === p.id;
        const rowClass = isSelected ? 'bg-cyan-950/70 border-l-4 border-l-[#00e5ff]' : 'hover:bg-[#181d2c]';

        return `
        <tr onclick="inspectPacket(${p.id})" class="border-b border-[#222a3d] cursor-pointer text-xs font-mono transition ${rowClass}">
            <td class="py-2 px-3 text-slate-400 font-semibold">${p.id}</td>
            <td class="py-2 px-3 text-slate-300">${p.timestamp}</td>
            <td class="py-2 px-3">
                <span class="px-2 py-0.5 rounded text-xs font-bold border ${protoClass}">${p.proto}</span>
            </td>
            <td class="py-2 px-3 text-slate-100">${p.src_ip}${p.src_port ? ':' + p.src_port : ''}</td>
            <td class="py-2 px-3 text-slate-100">${p.dst_ip}${p.dst_port ? ':' + p.dst_port : ''}</td>
            <td class="py-2 px-3 text-slate-300 font-semibold">${p.length} B</td>
            <td class="py-2 px-3 text-slate-200 truncate max-w-[260px]" title="${p.info}">${p.info}</td>
        </tr>
        `;
    }).join('');
}

function inspectPacket(packetId) {
    selectedPacketId = packetId;
    const pkt = capturedPackets.find(p => p.id === packetId);
    if (!pkt) return;

    renderPacketTable(capturedPackets);

    const drawer = document.getElementById('packetInspectorDrawer');
    if (!drawer) return;

    drawer.classList.remove('hidden');

    document.getElementById('inspectPktId').innerText = `#${pkt.id}`;
    document.getElementById('inspectPktProto').innerText = pkt.proto;
    document.getElementById('inspectPktTime').innerText = pkt.timestamp;
    document.getElementById('inspectPktLen').innerText = `${pkt.length} bytes`;

    // Layer breakdown with high contrast
    const treeEl = document.getElementById('inspectLayerTree');
    if (treeEl) {
        treeEl.innerHTML = `
            <div class="space-y-1.5 text-xs">
                <!-- Frame / Ether -->
                <div class="p-2 rounded-lg bg-[#181d2c] border border-[#222a3d]">
                    <div class="font-bold text-slate-100 flex items-center space-x-2">
                        <i class="fa-solid fa-ethernet text-[#00e5ff]"></i>
                        <span>Layer 2: Ethernet Frame</span>
                    </div>
                    <div class="mt-0.5 pl-5 text-slate-300 font-mono space-y-0.5">
                        <div>Source MAC: <span class="text-[#00e5ff] font-semibold">${pkt.src_mac}</span></div>
                        <div>Destination MAC: <span class="text-[#00e5ff] font-semibold">${pkt.dst_mac}</span></div>
                    </div>
                </div>

                <!-- IP Layer -->
                <div class="p-2 rounded-lg bg-[#181d2c] border border-[#222a3d]">
                    <div class="font-bold text-slate-100 flex items-center space-x-2">
                        <i class="fa-solid fa-globe text-blue-400"></i>
                        <span>Layer 3: Internet Protocol (IP)</span>
                    </div>
                    <div class="mt-0.5 pl-5 text-slate-300 font-mono space-y-0.5">
                        <div>Source IP: <span class="text-white font-semibold">${pkt.src_ip}</span></div>
                        <div>Destination IP: <span class="text-white font-semibold">${pkt.dst_ip}</span></div>
                        <div>TTL: <span class="text-slate-200">${pkt.ttl}</span></div>
                    </div>
                </div>

                <!-- Transport Layer -->
                <div class="p-2 rounded-lg bg-[#181d2c] border border-[#222a3d]">
                    <div class="font-bold text-slate-100 flex items-center space-x-2">
                        <i class="fa-solid fa-arrows-split-up-and-left text-[#f59e0b]"></i>
                        <span>Layer 4: ${pkt.proto} Transport</span>
                    </div>
                    <div class="mt-0.5 pl-5 text-slate-300 font-mono space-y-0.5">
                        <div>Source Port: <span class="text-white font-semibold">${pkt.src_port || '-'}</span></div>
                        <div>Destination Port: <span class="text-white font-semibold">${pkt.dst_port || '-'}</span></div>
                        ${pkt.flags ? `<div>Flags: <span class="text-[#f59e0b] font-semibold">[${pkt.flags}]</span></div>` : ''}
                        <div>Identified Service: <span class="text-[#00e5ff] font-semibold">${pkt.service}</span></div>
                    </div>
                </div>
            </div>
        `;
    }

    // Hexdump viewer
    const hexdumpEl = document.getElementById('inspectHexdump');
    if (hexdumpEl) {
        hexdumpEl.innerText = pkt.hexdump || 'No payload data available.';
    }
}

function closePacketInspector() {
    selectedPacketId = null;
    document.getElementById('packetInspectorDrawer')?.classList.add('hidden');
    renderPacketTable(capturedPackets);
}
