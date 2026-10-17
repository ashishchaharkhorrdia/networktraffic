"""Real-time Bandwidth and Network Load Monitor."""

import time
import socket
import psutil
from collections import deque
from typing import Dict, Any, List, Optional
import subprocess

class BandwidthCollector:
    def __init__(self, history_len: int = 60):
        self.history_len = history_len
        self.last_timestamp: float = time.time()
        self.last_global_io = psutil.net_io_counters()
        self.last_pernic_io = psutil.net_io_counters(pernic=True)
        
        # History deque for total network load
        self.history = deque(maxlen=history_len)
        
        # Cumulative session stats
        self.session_start = time.time()
        self.initial_io = self.last_global_io

    def get_default_interface(self) -> Dict[str, str]:
        """Detect default interface and gateway."""
        default_iface = "lo"
        gateway = "127.0.0.1"
        try:
            # Try reading /proc/net/route
            with open("/proc/net/route", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[1] == "00000000":  # Default route
                        default_iface = parts[0]
                        # Gateway in hex (little-endian)
                        gw_hex = parts[2]
                        gw_bytes = bytes.fromhex(gw_hex)
                        gateway = f"{gw_bytes[3]}.{gw_bytes[2]}.{gw_bytes[1]}.{gw_bytes[0]}"
                        break
        except Exception:
            pass

        # If not found, look for non-loopback interface with an IPv4 address
        if default_iface == "lo":
            addrs = psutil.net_if_addrs()
            for iface, if_addrs in addrs.items():
                if iface != "lo":
                    for addr in if_addrs:
                        if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                            default_iface = iface
                            break
                    if default_iface != "lo":
                        break

        return {"interface": default_iface, "gateway": gateway}

    def get_interfaces_info(self) -> List[Dict[str, Any]]:
        """Get comprehensive network interface list and details."""
        if_addrs = psutil.net_if_addrs()
        if_stats = psutil.net_if_stats()
        io_counters = psutil.net_io_counters(pernic=True)
        default_info = self.get_default_interface()
        
        interfaces = []
        for iface_name, addrs in if_addrs.items():
            ipv4 = ""
            netmask = ""
            mac = ""
            ipv6 = ""
            
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ipv4 = addr.address
                    netmask = addr.netmask or ""
                elif addr.family == socket.AF_INET6:
                    ipv6 = addr.address.split('%')[0]
                elif addr.family == psutil.AF_LINK or addr.family == 17:
                    mac = addr.address

            stats = if_stats.get(iface_name)
            is_up = stats.isup if stats else False
            speed_mbps = stats.speed if stats else 0
            mtu = stats.mtu if stats else 1500
            
            io = io_counters.get(iface_name)
            bytes_sent = io.bytes_sent if io else 0
            bytes_recv = io.bytes_recv if io else 0
            packets_sent = io.packets_sent if io else 0
            packets_recv = io.packets_recv if io else 0
            errin = io.errin if io else 0
            errout = io.errout if io else 0
            dropin = io.dropin if io else 0
            dropout = io.dropout if io else 0

            interfaces.append({
                "name": iface_name,
                "is_default": (iface_name == default_info["interface"]),
                "ipv4": ipv4,
                "netmask": netmask,
                "ipv6": ipv6,
                "mac": mac,
                "is_up": is_up,
                "speed_mbps": speed_mbps,
                "mtu": mtu,
                "bytes_sent": bytes_sent,
                "bytes_recv": bytes_recv,
                "packets_sent": packets_sent,
                "packets_recv": packets_recv,
                "errin": errin,
                "errout": errout,
                "dropin": dropin,
                "dropout": dropout
            })

        return sorted(interfaces, key=lambda x: (not x["is_default"], x["name"]))

    def collect(self, selected_interface: Optional[str] = None) -> Dict[str, Any]:
        """Collect current network rates and delta stats."""
        current_time = time.time()
        dt = current_time - self.last_timestamp
        if dt <= 0:
            dt = 1.0

        current_global_io = psutil.net_io_counters()
        current_pernic_io = psutil.net_io_counters(pernic=True)

        # Selected interface or global
        if selected_interface and selected_interface != "all" and selected_interface in current_pernic_io:
            cur_io = current_pernic_io[selected_interface]
            prev_io = self.last_pernic_io.get(selected_interface, cur_io)
        else:
            cur_io = current_global_io
            prev_io = self.last_global_io

        # Rates (per second)
        bytes_recv_rate = max(0.0, (cur_io.bytes_recv - prev_io.bytes_recv) / dt)
        bytes_sent_rate = max(0.0, (cur_io.bytes_sent - prev_io.bytes_sent) / dt)
        packets_recv_rate = max(0.0, (cur_io.packets_recv - prev_io.packets_recv) / dt)
        packets_sent_rate = max(0.0, (cur_io.packets_sent - prev_io.packets_sent) / dt)
        dropin_rate = max(0.0, (cur_io.dropin - prev_io.dropin) / dt)
        dropout_rate = max(0.0, (cur_io.dropout - prev_io.dropout) / dt)
        errin_rate = max(0.0, (cur_io.errin - prev_io.errin) / dt)
        errout_rate = max(0.0, (cur_io.errout - prev_io.errout) / dt)

        # Update previous metrics
        self.last_timestamp = current_time
        self.last_global_io = current_global_io
        self.last_pernic_io = current_pernic_io

        # Per-NIC speed breakdown
        nic_rates = {}
        for iface, now_io in current_pernic_io.items():
            old_io = self.last_pernic_io.get(iface, now_io)
            nic_rates[iface] = {
                "rx_rate_kb": round((now_io.bytes_recv - old_io.bytes_recv) / dt / 1024, 2),
                "tx_rate_kb": round((now_io.bytes_sent - old_io.bytes_sent) / dt / 1024, 2),
                "rx_total_mb": round(now_io.bytes_recv / (1024 * 1024), 2),
                "tx_total_mb": round(now_io.bytes_sent / (1024 * 1024), 2),
            }

        # Point for historical graph
        timestamp_str = time.strftime("%H:%M:%S", time.localtime(current_time))
        point = {
            "timestamp": timestamp_str,
            "epoch": current_time,
            "rx_kbps": round(bytes_recv_rate / 1024, 2),
            "tx_kbps": round(bytes_sent_rate / 1024, 2),
            "rx_mbps": round((bytes_recv_rate * 8) / (1000 * 1000), 3),
            "tx_mbps": round((bytes_sent_rate * 8) / (1000 * 1000), 3),
            "packets_in": round(packets_recv_rate, 1),
            "packets_out": round(packets_sent_rate, 1),
            "drops": round(dropin_rate + dropout_rate, 1),
            "errors": round(errin_rate + errout_rate, 1),
        }
        self.history.append(point)

        # Session totals
        session_elapsed = round(current_time - self.session_start, 1)
        session_rx_bytes = current_global_io.bytes_recv - self.initial_io.bytes_recv
        session_tx_bytes = current_global_io.bytes_sent - self.initial_io.bytes_sent

        return {
            "current": point,
            "history": list(self.history),
            "nic_rates": nic_rates,
            "session": {
                "elapsed_sec": session_elapsed,
                "rx_mb": round(session_rx_bytes / (1024 * 1024), 2),
                "tx_mb": round(session_tx_bytes / (1024 * 1024), 2),
                "total_mb": round((session_rx_bytes + session_tx_bytes) / (1024 * 1024), 2)
            }
        }
