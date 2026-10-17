# CyberNinjas: Project Overview & Operations Guide

---

## 1. System Overview

**CyberNinjas** is a real-time **Network Traffic Analysis, Bandwidth Telemetry, and Subnet Security Operations Platform** with a centralized web dashboard.

It provides security engineers, system administrators, and network analysts with comprehensive visibility into local network traffic, active socket connections, throughput metrics, subnet endpoints, and packet payloads.

```
                    ┌────────────────────────────────────────────────────────┐
                    │              CyberNinjas Operations Console            │
                    └───────────────────────────┬────────────────────────────┘
                                                │
       ┌────────────────────┬───────────────────┼───────────────────┬────────────────────┐
       ▼                    ▼                   ▼                   ▼                    ▼
┌──────────────┐     ┌──────────────┐    ┌──────────────┐    ┌──────────────┐     ┌──────────────┐
│  Throughput  │     │ Subnet Host  │    │   Sockets &  │    │Packet Capture│     │ Diagnostics  │
│  & Metrics   │     │  Discovery   │    │  Processes   │    │  & PCAP Lab  │     │   & Health   │
└──────────────┘     └──────────────┘    └──────────────┘    └──────────────┘     └──────────────┘
```

---

### Core Capabilities & Features

### 1. Operations Dashboard
- **High-Contrast Dark Theme:** Structured card layouts, sharp contrast borders, high-contrast typography, and real-time status pulses.
- **WebSocket Streaming (1 Hz):** Zero polling lag; real-time bandwidth throughput, socket counts, and latency are pushed directly to the browser every second.
- **Multi-NIC Selector:** Switch between monitoring all interfaces or a specific adapter (e.g. `wlan0`, `lo`, `eth0`).
- **Session Accounting:** Tracks total MBs received, total MBs sent, and packet error/drop rates during your session.
- **Export Snapshot:** Download of the complete real-time telemetry snapshot as a JSON report.

### 2. Live Network Load & High-Resolution Graphs
- **Real-Time Bandwidth Line Chart:** 60-second rolling time-series graph tracking Download (RX) and Upload (TX) throughput in KB/s and Mbps.
- **Packet Throughput Graph:** Monitors incoming vs. outgoing packets per second in real time.
- **Protocol Distribution Doughnut:** Visual breakdown of active protocols (TCP, UDP, ICMP, DNS, Other).
- **Socket Lifecycle State Bar Chart:** Shows live counts for `ESTABLISHED`, `LISTEN`, `TIME_WAIT`, `CLOSE_WAIT`, and `SYN_SENT`.
- **Top Remote Endpoints Widget:** Lists the highest-frequency remote IP endpoints with resolved hostnames and quick scan buttons.

### 3. Subnet Host Discovery & LAN Scanner
- **Automatic Subnet CIDR Detection:** Detects your local subnet automatically (e.g., `192.168.1.0/24`).
- **Concurrent Parallel Sweep:** Asynchronously sweeps up to 512 hosts using non-blocking TCP socket probes and parallel ICMP pings.
- **Hardware MAC & Manufacturer Detection:** Correlates ARP cache entries with an embedded OUI database (Apple, Intel, Samsung, TP-Link, Raspberry Pi, Espressif, etc.).
- **Live Latency Badges:** Displays round-trip response time (ms) with high-contrast color-coded indicators (<20ms green, <100ms amber, >100ms red).
- **Host Role Identification:** Labels your local host ("Local Machine") and default gateway ("Gateway Router").
- **Integrated Port Scanner:** Scan top common ports (SSH, HTTP, HTTPS, MySQL, Redis, RDP, etc.) with open states, service names, and response latency.

### 4. Active Sockets & Process Attribution
- **Process-Level Attribution:** Associates active TCP and UDP sockets with the parent **Process Name** (e.g., `chrome`, `python3`, `mysqld`, `code`) and PID.
- **Asynchronous Reverse DNS:** Resolves remote IP addresses to domain names in the background without blocking the UI.
- **Dynamic Filters:** Instant filtering by state (`ALL`, `ESTABLISHED`, `LISTEN`, `TIME_WAIT`, `CLOSE_WAIT`, `UDP`) and text search by IP, port, service, or process name.

### 5. Packet Capture & PCAP Engine
- **Layer Decomposition:** Breaks down packets across Layer 2 (Ethernet MACs), Layer 3 (IP Src/Dst, TTL), and Layer 4 (TCP/UDP Ports, Flags `SYN`, `ACK`, `FIN`, `RST`, `PSH`, `URG`).
- **Hex Dump & ASCII Viewer:** Formatted byte offset display (`0000 45 00 00 ... |E..|`) for inspecting packet payloads.
- **PCAP File Analysis:** Upload any `.pcap` or `.pcapng` file to analyze it packet-by-packet.
- **Export to PCAP:** Download captured packets as a standard `.pcap` file.
- **Live Packet Capture:** Supports live capture with BPF filters (e.g., `tcp and port 443`, `icmp`).

### 6. Network Diagnostics & Health Monitor
- **Multi-Target Latency & Jitter Monitor:** Concurrently monitors round-trip latency, jitter, and packet loss to:
  - Local Gateway
  - Google Public DNS (`8.8.8.8`)
  - Cloudflare Public DNS (`1.1.1.1`)
- **DNS Resolution Speed Benchmark:** Tests and compares lookup response times (ms) for major internet domains through your active DNS resolver.
- **Adapter Hardware Explorer:** Comprehensive details on physical and virtual interfaces (MTU, MAC, speed, error counts, packet drops).

---

## 2. How to Run CyberNinjas

### Prerequisites
- **Operating System:** Linux (Ubuntu, Debian, Fedora, Arch, Kali, etc.)
- **Python:** Python 3.9 or higher
- **Browser:** Any modern web browser (Chrome, Firefox, Edge, Safari, Brave)

---

### Step 1: Navigate to the Project Directory
```bash
cd /home/ashish/Desktop/pro
```

---

### Step 2: Install Python Dependencies
```bash
pip install -r requirements.txt
```

---

### Step 3: Start the Application

You can start the tool in any of the following ways:

#### Option A: Using the Startup Script (Recommended)
```bash
./start.sh
```

#### Option B: Using Python CLI
```bash
python3 main.py --host 0.0.0.0 --port 8000
```

#### Option C: Custom Port (e.g., Port 8080)
```bash
python3 main.py --port 8080
```

---

### Step 4: Open the Dashboard in Your Browser
Once started, open your web browser and go to:
**[http://localhost:8000](http://localhost:8000)**

---

## 3. How to Use Each Feature in the Dashboard

### 1. View Live Network Load & Bandwidth
1. Open the **"Throughput & Metrics"** tab.
2. Watch the real-time **Download** (cyan) and **Upload** (purple) throughput curves.
3. Use the interface dropdown in the top bar to switch between `All Interfaces`, `wlan0`, or `lo`.
4. Click **"Pause"** in the top bar if you want to freeze the live graph to inspect a sudden spike.

### 2. Discover Active Hosts on Your Local Network
1. Click the **"Subnet Host Discovery"** tab.
2. The subnet CIDR (e.g. `192.168.1.0/24`) is detected automatically.
3. Click the **"Scan Subnet"** button.
4. Watch the progress bar as the engine scans the subnet.
5. Review the discovered devices:
   - Identify your machine, your router/gateway, and other connected devices.
   - See MAC addresses, device vendors (Apple, Samsung, Intel, etc.), and response latency.
6. Click **"Scan Ports"** on any host to discover open services (e.g., Port 80 HTTP, Port 22 SSH, Port 3306 MySQL).

### 3. Check Which Programs Are Using Network Traffic
1. Click the **"Active Sockets & Processes"** tab.
2. You will see active connections with local IP:Port, remote IP:Port, remote domain name, status, and the **Process Name & PID** (e.g., `chrome`, `code`, `python3`).
3. Click filter pills (`ESTABLISHED`, `LISTEN`, `TIME_WAIT`, `UDP`) to narrow down connections.
4. Type in the search box to find connections for a specific program or remote IP.

### 4. Inspect Packet Payloads and Upload PCAP Files
1. Click the **"Packet Capture & PCAP"** tab.
2. To inspect an existing capture file, click **"Upload PCAP"** and select any `.pcap` or `.pcapng` file.
3. To view simulated traffic, click **"Sample Packets"**.
4. Click on any packet row in the table:
   - The right drawer displays the protocol layer breakdown (Ethernet -> IP -> Transport).
   - Scroll down to view the **Hex Dump and ASCII** byte-by-byte viewer.
5. Click **"Export PCAP"** to download the current buffer as a standard PCAP file.

### 5. Check Network Health & Benchmark DNS
1. Click the **"Network Diagnostics"** tab.
2. View real-time latency, jitter, and packet loss to your Gateway router, Google DNS, and Cloudflare DNS.
3. View the **DNS Resolution Speed Benchmark** to verify how fast your system resolves major domains like `google.com`, `cloudflare.com`, and `github.com`.
4. Review physical adapter specifications (MTU, speed, packet error counts).

---

## 4. Permissions: Standard Mode vs. Raw Capture Mode

CyberNinjas is designed for flexible operation:

1. **Standard User Mode (Active by default):**
   - **No root or sudo required.**
   - Live bandwidth graphs, socket monitoring, process attribution, subnet IP scanning, port scanning, and PCAP file analysis work fully out of the box.

2. **Raw Packet Promiscuous Sniffing Mode (Optional):**
   - If you want the live packet sniffer to capture raw promiscuous packets on your Wi-Fi/Ethernet interface, Linux requires raw socket capabilities.
   - You can grant this capability to Python with a single command (without running the whole app as root):
     ```bash
     sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
     ```
   - Alternatively, you can run: `sudo python3 main.py --port 8000`.

---

## 5. Running Automated Tests

To verify that all backend modules, collectors, and API endpoints are working properly, run the test suite:
```bash
python3 -m pytest tests/ -v
```

All 13 automated tests will run and verify:
- Bandwidth throughput and interface calculations
- Active socket and process attribution parsing
- Subnet detection and port scanning
- Packet parsing, layer inspection, and hexdumps
- REST API and WebSocket endpoints

---

## 6. How to Stop the Application

- If running in your terminal foreground: Press **`Ctrl + C`**.
- If running in the background:
  ```bash
  pkill -f "python3 main.py"
  ```

---

## 7. File Structure Reference

```
/home/ashish/Desktop/pro/
├── app/
│   ├── main.py                  # FastAPI server, WebSocket broadcaster & REST routes
│   ├── config.py                # Port mappings, OUI vendor prefixes, settings
│   ├── collector/
│   │   ├── bandwidth.py         # Real-time network throughput and load metrics
│   │   ├── connections.py       # Active socket monitoring and process resolution
│   │   ├── scanner.py           # Parallel subnet IP finder & port scanner
│   │   ├── sniffer.py           # Scapy live packet capture, PCAP parser & hex viewer
│   │   └── diagnostics.py       # Latency, jitter, loss & DNS benchmark
│   └── static/
│       ├── index.html           # Centralized operations console frontend
│       ├── css/custom.css       # High-contrast styling and animations
│       └── js/
│           ├── app.js           # WebSocket client and UI orchestration
│           ├── charts.js        # Real-time Chart.js time-series streaming
│           ├── scanner.js       # Subnet scanner and port scan modal
│           ├── connections.js   # Sockets table, search, and filtering
│           ├── sniffer.js       # Packet inspector, PCAP viewer & hex dump
│           └── diagnostics.js   # Ping health and DNS benchmarking
├── tests/
│   ├── test_collectors.py       # Unit tests for collectors
│   └── test_api.py              # Integration tests for REST API
├── requirements.txt             # Python dependencies
├── start.sh                     # Convenient startup script
├── main.py                      # CLI entrypoint with ASCII banner
├── README.md                    # Quick summary documentation
└── PROJECT_GUIDE.md             # Complete project guide and how-to-run (this file)
```
