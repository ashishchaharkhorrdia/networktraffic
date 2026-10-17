"""Active network socket connection monitor with process attribution."""

import socket
import psutil
import threading
from typing import Dict, Any, List, Optional
from collections import Counter
from app.config import COMMON_PORTS
from app.collector.geoip import GeoIPResolver

class ConnectionCollector:
    def __init__(self):
        self.geoip_resolver = GeoIPResolver()
        self._dns_cache: Dict[str, str] = {
            "127.0.0.1": "localhost",
            "::1": "localhost",
            "0.0.0.0": "all-interfaces",
            "::": "all-interfaces",
        }
        self._cache_lock = threading.Lock()
        self._pending_dns = set()

    def _resolve_dns_async(self, ip: str):
        """Asynchronously resolve IP to hostname to prevent blocking."""
        if ip.startswith("127.") or ip == "0.0.0.0" or ip.startswith("fe80:") or ip == "::":
            return
        
        with self._cache_lock:
            if ip in self._dns_cache or ip in self._pending_dns:
                return
            self._pending_dns.add(ip)

        def worker():
            hostname = ip
            try:
                # 1 second timeout for reverse DNS
                socket.setdefaulttimeout(1.0)
                resolved, _, _ = socket.gethostbyaddr(ip)
                hostname = resolved
            except Exception:
                hostname = ip
            
            with self._cache_lock:
                self._dns_cache[ip] = hostname
                if ip in self._pending_dns:
                    self._pending_dns.remove(ip)

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def get_hostname(self, ip: str) -> str:
        """Get cached hostname or initiate async lookup."""
        with self._cache_lock:
            if ip in self._dns_cache:
                return self._dns_cache[ip]
        self._resolve_dns_async(ip)
        return ip

    def get_connections(self, limit: int = 150) -> Dict[str, Any]:
        """Fetch and structure active network connections."""
        raw_conns = []
        try:
            raw_conns = psutil.net_connections(kind="all")
        except Exception as e:
            # Fallback if permission issue on some connection types
            try:
                raw_conns = psutil.net_connections(kind="inet")
            except Exception:
                pass

        results = []
        process_cache: Dict[int, str] = {}
        status_counts = Counter()
        remote_ip_counts = Counter()
        remote_port_counts = Counter()
        protocol_counts = Counter()

        for c in raw_conns:
            # Check family and protocol
            is_inet = hasattr(c, "family") and c.family in (socket.AF_INET, socket.AF_INET6)
            if is_inet:
                proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
            else:
                proto = "UNIX"
            
            protocol_counts[proto] += 1
            
            status = c.status if c.status else "NONE"
            status_counts[status] += 1

            l_ip = ""
            l_port = 0
            if c.laddr:
                if hasattr(c.laddr, "ip"):
                    l_ip = c.laddr.ip
                    l_port = getattr(c.laddr, "port", 0)
                elif isinstance(c.laddr, tuple) and len(c.laddr) >= 2:
                    l_ip = str(c.laddr[0])
                    l_port = int(c.laddr[1])
                elif isinstance(c.laddr, str):
                    l_ip = c.laddr

            r_ip = ""
            r_port = 0
            if c.raddr:
                if hasattr(c.raddr, "ip"):
                    r_ip = c.raddr.ip
                    r_port = getattr(c.raddr, "port", 0)
                elif isinstance(c.raddr, tuple) and len(c.raddr) >= 2:
                    r_ip = str(c.raddr[0])
                    r_port = int(c.raddr[1])
                elif isinstance(c.raddr, str):
                    r_ip = c.raddr

            if r_ip:
                remote_ip_counts[r_ip] += 1
                remote_port_counts[r_port] += 1

            # Process Name
            pid = c.pid
            pname = "-"
            if pid:
                if pid in process_cache:
                    pname = process_cache[pid]
                else:
                    try:
                        p = psutil.Process(pid)
                        pname = p.name()
                        process_cache[pid] = pname
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pname = f"PID {pid}"
                        process_cache[pid] = pname

            # Service identification
            target_port = r_port if r_port else l_port
            service = COMMON_PORTS.get(target_port, str(target_port) if target_port else "-")

            # Hostname lookup
            r_host = self.get_hostname(r_ip) if r_ip else ""

            # Classify connection category
            category = "Other"
            if target_port in [80, 443, 8080, 8443]:
                category = "Web (HTTP/S)"
            elif target_port == 53:
                category = "DNS"
            elif target_port in [22, 23]:
                category = "Remote Shell"
            elif target_port in [3306, 5432, 27017, 6379, 1433]:
                category = "Database"
            elif target_port in [25, 110, 143, 465, 587, 993, 995]:
                category = "Mail"
            elif proto == "UDP":
                category = "UDP Stream"

            geoip_info = self.geoip_resolver.resolve(r_ip) if r_ip else None

            results.append({
                "proto": proto,
                "local_ip": l_ip,
                "local_port": l_port,
                "remote_ip": r_ip,
                "remote_port": r_port,
                "remote_host": r_host,
                "status": status,
                "pid": pid,
                "process": pname,
                "service": service,
                "category": category,
                "geoip": geoip_info,
            })

        # Sort: ESTABLISHED first, then LISTEN, then others
        priority_order = {"ESTABLISHED": 0, "LISTEN": 1, "SYN_SENT": 2, "TIME_WAIT": 3, "CLOSE_WAIT": 4}
        results.sort(key=lambda x: (priority_order.get(x["status"], 5), x["remote_ip"] == "", x["process"]))

        # Top 5 remote talkers
        top_remote_ips = [
            {
                "ip": ip,
                "count": count,
                "host": self.get_hostname(ip),
                "geoip": self.geoip_resolver.resolve(ip)
            }
            for ip, count in remote_ip_counts.most_common(5)
        ]

        top_ports = [
            {"port": port, "service": COMMON_PORTS.get(port, str(port)), "count": count}
            for port, count in remote_port_counts.most_common(5)
        ]

        # Calculate country distribution
        remote_ips_list = [c["remote_ip"] for c in results if c.get("remote_ip")]
        country_distribution = self.geoip_resolver.get_distribution(remote_ips_list)

        return {
            "total": len(results),
            "established": status_counts.get("ESTABLISHED", 0),
            "listening": status_counts.get("LISTEN", 0),
            "time_wait": status_counts.get("TIME_WAIT", 0),
            "close_wait": status_counts.get("CLOSE_WAIT", 0),
            "status_distribution": dict(status_counts),
            "protocol_distribution": dict(protocol_counts),
            "country_distribution": country_distribution,
            "top_remote_ips": top_remote_ips,
            "top_ports": top_ports,
            "connections": results[:limit],
        }
