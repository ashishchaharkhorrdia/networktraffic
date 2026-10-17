"""Process-level Network Traffic Attribution and Top Talkers Monitor."""

import time
import psutil
from typing import Dict, Any, List

class ProcessTrafficCollector:
    """Tracks and ranks bandwidth consumption and active socket allocations per system process."""

    def __init__(self):
        self.last_sample_time: float = time.time()
        self.last_io: Dict[int, Dict[str, int]] = {}

    def _format_bytes(self, num_bytes: float) -> str:
        """Format raw byte counts to human-readable strings."""
        for unit in ["B", "KB", "MB", "GB"]:
            if abs(num_bytes) < 1024.0:
                return f"{num_bytes:.1f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} TB"

    def _format_rate(self, rate_bps: float) -> str:
        """Format byte transfer rates to human-readable per-second strings."""
        for unit in ["B/s", "KB/s", "MB/s", "GB/s"]:
            if abs(rate_bps) < 1024.0:
                return f"{rate_bps:.1f} {unit}"
            rate_bps /= 1024.0
        return f"{rate_bps:.1f} TB/s"

    def _categorize_process(self, name: str) -> str:
        """Determine general operational role of process."""
        name_lower = name.lower()
        if any(b in name_lower for b in ["chrome", "firefox", "brave", "edge", "safari", "opera"]):
            return "Web Browser"
        elif any(d in name_lower for d in ["code", "node", "python", "py", "java", "rust", "go", "gcc"]):
            return "Development & Runtime"
        elif any(s in name_lower for s in ["systemd", "dbus", "pipewire", "pulseaudio", "cron", "polkit"]):
            return "System Service"
        elif any(n in name_lower for n in ["sshd", "ssh", "curl", "wget", "traceroute", "ping", "netpulse", "wireshark"]):
            return "Network Tool"
        elif any(db in name_lower for db in ["postgres", "mysqld", "mongo", "redis", "cockroach"]):
            return "Database Engine"
        return "Application"

    def get_top_talkers(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Compute real-time bandwidth consumption rates and socket counts per process."""
        now = time.time()
        dt = max(now - self.last_sample_time, 0.5)

        # Map active socket counts per PID
        socket_counts: Dict[int, int] = {}
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.pid:
                    socket_counts[conn.pid] = socket_counts.get(conn.pid, 0) + 1
        except Exception:
            pass

        current_io: Dict[int, Dict[str, int]] = {}
        talkers = []

        # Iterate only through processes that hold active sockets or high I/O
        for pid, conn_count in socket_counts.items():
            try:
                proc = psutil.Process(pid)
                pname = proc.name()
                
                read_bytes = 0
                write_bytes = 0
                try:
                    io = proc.io_counters()
                    if io:
                        read_bytes = io.read_bytes
                        write_bytes = io.write_bytes
                except (psutil.AccessDenied, AttributeError):
                    pass

                current_io[pid] = {"read": read_bytes, "write": write_bytes}

                # Compute rate from previous sample
                prev = self.last_io.get(pid, {"read": read_bytes, "write": write_bytes})
                rx_delta = max(read_bytes - prev["read"], 0)
                tx_delta = max(write_bytes - prev["write"], 0)

                rx_rate = rx_delta / dt
                tx_rate = tx_delta / dt

                talkers.append({
                    "pid": pid,
                    "name": pname,
                    "category": self._categorize_process(pname),
                    "connections": conn_count,
                    "rx_rate_bps": rx_rate,
                    "tx_rate_bps": tx_rate,
                    "rx_rate_str": self._format_rate(rx_rate),
                    "tx_rate_str": self._format_rate(tx_rate),
                    "total_read_str": self._format_bytes(read_bytes),
                    "total_write_str": self._format_bytes(write_bytes),
                    "score": rx_rate + tx_rate + (conn_count * 5000)
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        self.last_io = current_io
        self.last_sample_time = now

        # Sort by activity score (bandwidth rates + connection weighting)
        talkers.sort(key=lambda x: x["score"], reverse=True)
        return talkers[:limit]
