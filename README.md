# CyberNinjas - Network Traffic & Security Analysis Suite

**CyberNinjas** is a real-time Network Traffic Analysis and Subnet Security platform featuring a centralized web operations console, live bandwidth load telemetry, subnet host discovery, socket process attribution, and deep packet inspection.

---

## Core Capabilities & Features

### 1. Centralized Security Operations Dashboard
- **High-Contrast Dark Theme:** Optimized for operational visibility with structured card layouts, high-contrast typography, and real-time status indicators.
- **WebSocket Telemetry Stream (1 Hz):** Zero polling overhead; continuously streams bandwidth throughput, active socket counts, latency, and packet rates.
- **Network Interface Selector:** Switch between all aggregated interfaces (`all`) or specific network adapters (`eth0`, `wlan0`, `lo`, etc.).
- **Session Accounting:** Tracks cumulative data transfer (MB received and sent) and packet drop counters.

### 2. Live Network Load & Telemetry Graphs
- **Real-Time Bandwidth Time-Series:** Rolling 60-second window tracking Inbound (RX) and Outbound (TX) throughput in KB/s and Mbps.
- **Packet Throughput Graph:** Monitors incoming and outgoing packet rates per second.
- **Protocol Distribution:** Live breakdown across TCP, UDP, ICMP, DNS, and ancillary protocols.
- **Socket State Breakdown:** Real-time state metrics for `ESTABLISHED`, `LISTEN`, `TIME_WAIT`, `CLOSE_WAIT`, and `SYN_SENT`.
- **Top Remote Endpoints:** Highlights highest-frequency remote IP endpoints with reverse DNS hostnames and direct port scan shortcuts.

### 3. Subnet Host Discovery & Scanner
- **Auto-Subnet Detection:** Automatically identifies your active subnet CIDR (e.g., `192.168.1.0/24`).
- **Parallel Sweep Engine:** Sweeps subnet address space using non-blocking network probes.
- **Hardware MAC & Vendor Attribution:** Matches MAC addresses against an integrated OUI vendor database.
- **Latency Telemetry:** Displays round-trip response times (ms) with high-contrast latency indicators.
- **Integrated Port Scanner:** Scans common network service ports (SSH, HTTP, HTTPS, MySQL, RDP, Redis, etc.) on target hosts to report port status and service attribution.

### 4. Active Sockets & Process Attribution
- **Process-Level Attribution:** Associates active TCP and UDP sockets with their host Process Name (e.g., `chrome`, `python3`, `node`, `systemd`) and PID.
- **Asynchronous Reverse DNS:** Resolves foreign IP addresses to domain hostnames in the background.
- **Filtering & Search:** Real-time filtering by state (`ALL`, `ESTABLISHED`, `LISTEN`, `TIME_WAIT`, `CLOSE_WAIT`, `UDP`) and text search across addresses, ports, and process names.

### 5. Packet Capture & PCAP Engine
- **Protocol Layer Decomposition:** Deconstructs packets across Layer 2 (Ethernet MACs), Layer 3 (IP Source/Destination, TTL), and Layer 4 (TCP/UDP Ports, Flags `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`).
- **Hex Dump & ASCII Viewer:** Formatted byte offset display for packet payload inspection.
- **PCAP File Analysis:** Upload any `.pcap` or `.pcapng` capture file for frame-by-frame protocol inspection.
- **PCAP Export:** Export captured packets as a standard `.pcap` capture file.
- **Synthetic Test Traffic:** Generates representative packet streams for offline testing.

### 6. Network Diagnostics & Health
- **Multi-Target Latency & Jitter Monitor:** Measures latency, jitter, and packet loss to your Local Gateway and public DNS resolvers.
- **DNS Resolution Benchmark:** Benchmarks resolution latency (ms) for major domains through your active resolver.
- **Hardware Interface Inventory:** Comprehensive metrics covering MTU, MAC, transfer counters, and packet drop stats.

---

## Quick Start Guide

### Prerequisites
- Linux OS
- Python 3.9+ with `pip`

### 1. Installation
Navigate to the project directory and install dependencies:
```bash
cd /home/ashish/Desktop/network
pip install -r requirements.txt
```

### 2. Launching CyberNinjas
Start the server using the launch script:
```bash
./start.sh
```
Or start directly with Python:
```bash
python3 main.py --host 0.0.0.0 --port 8000
```

Access the web console in your browser at:
**[http://localhost:8000](http://localhost:8000)**

---

## Operating Modes & Privileges

CyberNinjas operates in two modes:

1. **Standard User Mode (Default):**
   - Runs out of the box with standard unprivileged user permissions.
   - Live throughput graphs, active socket monitoring, process attribution, subnet discovery, and PCAP file analysis work fully without root.
2. **Raw Packet Capture Mode (Optional):**
   - For live promiscuous packet capture via kernel sockets, either run with `sudo` or grant the Python binary raw socket capabilities:
   ```bash
   sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
   ```

---

## Project Architecture

```
/home/ashish/Desktop/pro/
├── app/
│   ├── __init__.py
│   ├── main.py                  # FastAPI server, WebSocket engine & REST routes
│   ├── config.py                # Service mappings, OUI vendor database, settings
│   ├── collector/
│   │   ├── __init__.py
│   │   ├── bandwidth.py         # Network throughput and load metrics
│   │   ├── connections.py       # Active socket monitoring and process attribution
│   │   ├── scanner.py           # Subnet host discovery and port scanner
│   │   ├── sniffer.py           # Live packet capture, PCAP parser & hex viewer
│   │   └── diagnostics.py       # Latency, jitter, loss & DNS benchmark
│   └── static/
│       ├── index.html           # Centralized dashboard frontend
│       ├── css/
│       │   └── custom.css       # High-contrast styling and animations
│       └── js/
│           ├── app.js           # WebSocket client and UI controller
│           ├── charts.js        # High-contrast Chart.js telemetry charts
│           ├── scanner.js       # Subnet scanner and port scan modal
│           ├── connections.js   # Sockets table, search, and filtering
│           ├── sniffer.js       # Packet inspector, PCAP viewer & hex dump
│           └── diagnostics.js   # Latency health and DNS benchmarking
├── tests/
│   ├── test_collectors.py       # Unit tests for collectors
│   └── test_api.py              # Integration tests for REST API
├── requirements.txt             # Python dependencies
├── start.sh                     # Startup script
├── main.py                      # CLI entrypoint with ASCII banner
└── README.md                    # Project documentation
```

---

## Running Automated Tests

Run the unit and integration test suite:
```bash
python3 -m pytest tests/ -v
```

---

## API Reference Summary

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/` | Serves the Operations Console |
| `WS` | `/ws/live` | Real-time 1Hz WebSocket telemetry stream |
| `GET` | `/api/overview` | Complete network overview snapshot |
| `GET` | `/api/interfaces` | List of all network interfaces and metrics |
| `POST` | `/api/interfaces/select` | Select active interface for monitoring |
| `GET` | `/api/connections` | Active sockets with process attribution |
| `POST` | `/api/scan` | Initiate asynchronous subnet host discovery |
| `GET` | `/api/scan/status` | Get ongoing or last scan progress and results |
| `POST` | `/api/scan/ports` | Scan common service ports on target IP |
| `POST` | `/api/sniffer/start` | Start live packet capture (BPF filters supported) |
| `POST` | `/api/sniffer/stop` | Stop packet capture |
| `POST` | `/api/sniffer/upload` | Upload `.pcap` file for deep packet analysis |
| `GET` | `/api/sniffer/export` | Download captured packets as `.pcap` |
| `GET` | `/api/diagnostics/latency` | Ping latency, jitter, and packet loss |
| `GET` | `/api/diagnostics/dns` | Benchmark DNS lookup latency |
