"""CyberNinjas - Centralized Network Traffic & Security Analysis Server."""

import os
import time
import json
import asyncio
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Query, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.config import HOST, PORT
from app.collector import (
    BandwidthCollector,
    ConnectionCollector,
    NetworkScanner,
    PacketSniffer,
    DiagnosticsCollector,
    FirewallManager,
    GeoIPResolver,
    IntrusionDetectionEngine,
    ProcessTrafficCollector,
    TracerouteCollector
)

# Initialize collectors
bandwidth_collector = BandwidthCollector()
connection_collector = ConnectionCollector()
network_scanner = NetworkScanner()
packet_sniffer = PacketSniffer()
diagnostics_collector = DiagnosticsCollector()
firewall_manager = FirewallManager()
geoip_resolver = connection_collector.geoip_resolver
ids_engine = IntrusionDetectionEngine(firewall_manager=firewall_manager)
process_collector = ProcessTrafficCollector()
traceroute_collector = TracerouteCollector(geoip_resolver=geoip_resolver)

# Background broadcast task
broadcast_task = None
connected_websockets: List[WebSocket] = []
active_interface = "all"

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Pre-populate demo packets if sniffing is unprivileged so UI starts populated
    if not packet_sniffer.has_permission:
        packet_sniffer.generate_demo_packets(30)
    
    # Start live streaming loop in background
    global broadcast_task
    broadcast_task = asyncio.create_task(websocket_broadcast_loop())
    yield
    # Shutdown
    if broadcast_task:
        broadcast_task.cancel()
    packet_sniffer.stop_sniffing()

app = FastAPI(title="CyberNinjas", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Background WebSocket broadcaster (1Hz live telemetry)
async def websocket_broadcast_loop():
    global active_interface
    while True:
        try:
            if connected_websockets:
                # Collect live stats
                bw_data = bandwidth_collector.collect(selected_interface=active_interface)
                conn_data = connection_collector.get_connections(limit=25)
                default_info = bandwidth_collector.get_default_interface()
                
                # Analyze connections with IDS engine
                for c in conn_data.get("connections", []):
                    ids_engine.analyze_connection(c)

                payload = {
                    "type": "telemetry",
                    "timestamp": time.time(),
                    "bandwidth": bw_data,
                    "connections_summary": {
                        "total": conn_data["total"],
                        "established": conn_data["established"],
                        "listening": conn_data["listening"],
                        "time_wait": conn_data["time_wait"],
                        "top_remote_ips": conn_data["top_remote_ips"],
                        "status_distribution": conn_data["status_distribution"],
                        "protocol_distribution": conn_data["protocol_distribution"],
                        "country_distribution": conn_data.get("country_distribution", {}),
                    },
                    "sniffer": {
                        "is_sniffing": packet_sniffer.is_sniffing,
                        "packet_count": len(packet_sniffer.packet_buffer),
                        "has_permission": packet_sniffer.has_permission,
                    },
                    "scanner": {
                        "is_scanning": network_scanner.is_scanning,
                        "progress": network_scanner.scan_progress,
                        "host_count": len(network_scanner.last_results)
                    },
                    "default_gateway": default_info["gateway"],
                    "default_interface": default_info["interface"],
                    "firewall": firewall_manager.get_stats(),
                    "ids": ids_engine.get_stats(),
                    "top_talkers": process_collector.get_top_talkers(limit=5),
                }
                
                # Broadcast to all connected clients
                disconnected = []
                msg_str = json.dumps(payload)
                for ws in connected_websockets:
                    try:
                        await ws.send_text(msg_str)
                    except Exception:
                        disconnected.append(ws)
                
                for ws in disconnected:
                    if ws in connected_websockets:
                        connected_websockets.remove(ws)

            await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(1.0)

# Request Models
class ScanRequest(BaseModel):
    cidr: Optional[str] = None

class PortScanRequest(BaseModel):
    ip: str
    ports: Optional[List[int]] = None

class SnifferStartRequest(BaseModel):
    interface: Optional[str] = None
    filter: Optional[str] = ""

class InterfaceChangeRequest(BaseModel):
    interface: str

class BlockRequest(BaseModel):
    target: str
    target_type: Optional[str] = None
    reason: Optional[str] = ""

class UnblockRequest(BaseModel):
    rule_id: str

class TracerouteRequest(BaseModel):
    target: str
    max_hops: Optional[int] = 15

class MitigateRequest(BaseModel):
    alert_id: str

# API Routes
@app.get("/api/overview")
async def get_overview():
    """Get complete dashboard overview in a single call."""
    bw = bandwidth_collector.collect(active_interface)
    conns = connection_collector.get_connections(limit=10)
    ifaces = bandwidth_collector.get_interfaces_info()
    default_info = bandwidth_collector.get_default_interface()
    subnet_info = network_scanner.detect_local_subnet()
    
    return {
        "bandwidth": bw,
        "connections": conns,
        "interfaces": ifaces,
        "default_interface": default_info["interface"],
        "gateway": default_info["gateway"],
        "subnet": subnet_info,
        "sniffer_status": {
            "is_sniffing": packet_sniffer.is_sniffing,
            "has_permission": packet_sniffer.has_permission,
            "total_packets": len(packet_sniffer.packet_buffer)
        }
    }

@app.get("/api/interfaces")
async def get_interfaces():
    return bandwidth_collector.get_interfaces_info()

@app.post("/api/interfaces/select")
async def select_interface(req: InterfaceChangeRequest):
    global active_interface
    active_interface = req.interface
    return {"success": True, "selected_interface": active_interface}

@app.get("/api/connections")
async def get_connections(limit: int = Query(150, ge=1, le=500)):
    return connection_collector.get_connections(limit=limit)

@app.post("/api/scan")
async def start_scan(req: ScanRequest = ScanRequest()):
    """Start asynchronous subnet IP discovery."""
    if network_scanner.is_scanning:
        return {"status": "in_progress", "progress": network_scanner.scan_progress}
    
    # Launch in background
    asyncio.create_task(network_scanner.scan_subnet(req.cidr))
    return {
        "status": "started",
        "message": f"Scanning subnet {req.cidr or 'auto-detected'}"
    }

@app.get("/api/scan/status")
async def get_scan_status():
    """Check scanner status and results."""
    return {
        "is_scanning": network_scanner.is_scanning,
        "progress": network_scanner.scan_progress,
        "count": len(network_scanner.last_results),
        "results": network_scanner.last_results,
        "last_scan_time": network_scanner.last_scan_time
    }

@app.post("/api/scan/ports")
async def scan_target_ports(req: PortScanRequest):
    """Scan ports on target IP."""
    if not req.ip:
        raise HTTPException(status_code=400, detail="Target IP is required")
    ports = await network_scanner.scan_ports(req.ip, req.ports)
    return {
        "ip": req.ip,
        "open_ports_count": len(ports),
        "ports": ports
    }

@app.post("/api/sniffer/start")
async def start_sniffer(req: SnifferStartRequest = SnifferStartRequest()):
    res = packet_sniffer.start_sniffing(interface=req.interface, bpf_filter=req.filter or "")
    return res

@app.post("/api/sniffer/stop")
async def stop_sniffer():
    return packet_sniffer.stop_sniffing()

@app.post("/api/sniffer/clear")
async def clear_sniffer():
    packet_sniffer.clear_buffer()
    return {"success": True}

@app.get("/api/sniffer/packets")
async def get_sniffer_packets(limit: int = 150, proto: Optional[str] = "ALL"):
    return packet_sniffer.get_packets(limit=limit, filter_proto=proto)

@app.post("/api/sniffer/demo")
async def generate_demo_packets(count: int = 25):
    packet_sniffer.generate_demo_packets(count=count)
    return {"success": True, "count": count}

@app.post("/api/sniffer/upload")
async def upload_pcap(file: UploadFile = File(...)):
    """Upload a .pcap file to inspect."""
    temp_path = f"/tmp/uploaded_{int(time.time())}_{file.filename}"
    try:
        content = await file.read()
        with open(temp_path, "wb") as f:
            f.write(content)
        res = packet_sniffer.load_pcap_file(temp_path)
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return res
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise HTTPException(status_code=400, detail=f"Failed to parse PCAP file: {e}")

@app.get("/api/sniffer/export")
async def export_pcap():
    """Download current capture as .pcap file."""
    if len(packet_sniffer.raw_packets) == 0:
        raise HTTPException(status_code=400, detail="No packets captured to export")
    export_path = f"/tmp/cyberninjas_export_{int(time.time())}.pcap"
    packet_sniffer.export_pcap(export_path)
    return FileResponse(
        export_path,
        media_type="application/vnd.tcpdump.pcap",
        filename="cyberninjas_capture.pcap"
    )

@app.get("/api/diagnostics/latency")
async def get_diagnostics_latency():
    default_info = bandwidth_collector.get_default_interface()
    latency_data = await diagnostics_collector.get_multi_latency(gateway_ip=default_info["gateway"])
    return {"targets": latency_data}

@app.get("/api/diagnostics/dns")
async def benchmark_dns():
    res = await diagnostics_collector.benchmark_dns()
    return {"results": res}

# Firewall & Blocklist Endpoints
@app.get("/api/firewall/rules")
async def get_firewall_rules():
    """Retrieve all active and paused firewall rules and metrics."""
    return {
        "rules": firewall_manager.get_rules(),
        "stats": firewall_manager.get_stats()
    }

@app.post("/api/firewall/block")
async def block_target(req: BlockRequest):
    """Add a new target IP or domain to the blocklist."""
    try:
        rule = firewall_manager.add_rule(req.target, req.target_type, req.reason or "")
        return {"success": True, "rule": rule, "stats": firewall_manager.get_stats()}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/firewall/unblock")
async def unblock_target(req: UnblockRequest):
    """Remove a rule from the blocklist."""
    success = firewall_manager.remove_rule(req.rule_id)
    return {"success": success, "stats": firewall_manager.get_stats()}

@app.post("/api/firewall/toggle")
async def toggle_rule(req: UnblockRequest):
    """Toggle a rule between Active and Paused."""
    rule = firewall_manager.toggle_rule(req.rule_id)
    if rule:
        return {"success": True, "rule": rule, "stats": firewall_manager.get_stats()}
    raise HTTPException(status_code=404, detail="Rule not found")

# GeoIP Intelligence Endpoints
@app.get("/api/geoip/lookup")
async def lookup_geoip(ip: str = Query(..., description="Target IP to resolve")):
    """Lookup geographic location and ASN organization for an IP."""
    return geoip_resolver.resolve(ip)

# IDS Security Threat Endpoints
@app.get("/api/ids/alerts")
async def get_ids_alerts(limit: int = 50, severity: Optional[str] = None):
    """Retrieve security threat detection alerts."""
    return {
        "alerts": ids_engine.get_alerts(limit=limit, severity=severity),
        "stats": ids_engine.get_stats()
    }

@app.get("/api/ids/stats")
async def get_ids_stats():
    """Retrieve security posture and detection metrics."""
    return ids_engine.get_stats()

@app.post("/api/ids/mitigate")
async def mitigate_alert(req: MitigateRequest):
    """Mitigate a threat alert by automatically adding a firewall block rule."""
    alert = ids_engine.mitigate_alert(req.alert_id)
    if alert:
        return {
            "success": True,
            "alert": alert,
            "stats": ids_engine.get_stats(),
            "firewall_stats": firewall_manager.get_stats()
        }
    raise HTTPException(status_code=404, detail="Alert not found")

@app.post("/api/ids/clear")
async def clear_ids_alerts():
    """Clear threat alert feed."""
    ids_engine.clear_alerts()
    return {"success": True, "stats": ids_engine.get_stats()}

# Process Top Talkers Bandwidth Endpoint
@app.get("/api/processes/top-talkers")
async def get_process_top_talkers(limit: int = 10):
    """Retrieve top bandwidth-consuming processes and socket allocations."""
    return {
        "top_talkers": process_collector.get_top_talkers(limit=limit),
        "timestamp": time.time()
    }

# Traceroute Path Analysis Endpoint
@app.post("/api/diagnostics/traceroute")
async def run_traceroute(req: TracerouteRequest):
    """Execute hop-by-hop traceroute with RTT latency and GeoIP resolution."""
    try:
        res = await traceroute_collector.trace_path(req.target, req.max_hops or 15)
        return res
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Traceroute failed: {e}")

# WebSocket Endpoint
@app.websocket("/ws/live")
async def websocket_live_endpoint(websocket: WebSocket):
    global active_interface
    await websocket.accept()
    connected_websockets.append(websocket)
    try:
        # Send initial batch immediately on connect
        bw_data = bandwidth_collector.collect(selected_interface=active_interface)
        conn_data = connection_collector.get_connections(limit=25)
        default_info = bandwidth_collector.get_default_interface()
        init_payload = {
            "type": "initial",
            "bandwidth": bw_data,
            "interfaces": bandwidth_collector.get_interfaces_info(),
            "default_interface": default_info["interface"],
            "default_gateway": default_info["gateway"],
            "connections_summary": {
                "total": conn_data["total"],
                "established": conn_data["established"],
                "listening": conn_data["listening"],
                "time_wait": conn_data["time_wait"],
                "top_remote_ips": conn_data["top_remote_ips"],
                "status_distribution": conn_data["status_distribution"],
                "protocol_distribution": conn_data["protocol_distribution"],
                "country_distribution": conn_data.get("country_distribution", {}),
            },
            "sniffer": {
                "is_sniffing": packet_sniffer.is_sniffing,
                "packet_count": len(packet_sniffer.packet_buffer),
                "has_permission": packet_sniffer.has_permission,
            },
            "firewall": firewall_manager.get_stats(),
            "ids": ids_engine.get_stats(),
            "top_talkers": process_collector.get_top_talkers(limit=5),
        }
        await websocket.send_text(json.dumps(init_payload))

        while True:
            # Handle client incoming messages (like ping, filter, interface change)
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("action") == "set_interface":
                    active_interface = msg.get("interface", "all")
                elif msg.get("action") == "ping":
                    await websocket.send_text(json.dumps({"type": "pong", "time": time.time()}))
            except Exception:
                pass
    except WebSocketDisconnect:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)
    except Exception:
        if websocket in connected_websockets:
            connected_websockets.remove(websocket)

# Mount static files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.api_route("/", methods=["GET", "HEAD"])
async def serve_root():
    return FileResponse("app/static/index.html")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=HOST, port=PORT, reload=False)
