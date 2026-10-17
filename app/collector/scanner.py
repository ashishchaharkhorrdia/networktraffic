"""Live IP Finder, LAN Network Scanner, and Port Scanner."""

import asyncio
import socket
import ipaddress
import subprocess
import time
from typing import Dict, Any, List, Optional
from app.config import COMMON_PORTS, MAC_VENDORS

class NetworkScanner:
    def __init__(self):
        self.is_scanning = False
        self.last_results: List[Dict[str, Any]] = []
        self.last_scan_time: Optional[float] = None
        self.scan_progress: int = 0

    def detect_local_subnet(self) -> Dict[str, str]:
        """Detect local IP, netmask, and calculate subnet CIDR."""
        local_ip = "127.0.0.1"
        netmask = "255.255.255.0"
        subnet = "192.168.1.0/24"
        gateway = "192.168.1.1"

        try:
            # Read route to get default gateway and interface
            with open("/proc/net/route", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[1] == "00000000":
                        gw_hex = parts[2]
                        gw_bytes = bytes.fromhex(gw_hex)
                        gateway = f"{gw_bytes[3]}.{gw_bytes[2]}.{gw_bytes[1]}.{gw_bytes[0]}"
                        iface = parts[0]
                        break
        except Exception:
            gateway = "192.168.43.1"

        import psutil
        addrs = psutil.net_if_addrs()
        for iface, addr_list in addrs.items():
            if iface != "lo":
                for a in addr_list:
                    if a.family == socket.AF_INET and not a.address.startswith("127."):
                        local_ip = a.address
                        if a.netmask:
                            netmask = a.netmask
                            try:
                                net = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
                                subnet = str(net)
                            except Exception:
                                pass
                        break
                if local_ip != "127.0.0.1":
                    break

        return {
            "local_ip": local_ip,
            "netmask": netmask,
            "subnet": subnet,
            "gateway": gateway
        }

    def _read_arp_table(self) -> Dict[str, str]:
        """Parse Linux ARP cache to get IP -> MAC address mappings."""
        arp_cache = {}
        try:
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        mac = parts[3]
                        if mac != "00:00:00:00:00:00" and ":" in mac:
                            arp_cache[ip] = mac.lower()
        except Exception:
            pass

        # Try ip neigh as fallback
        try:
            res = subprocess.run(["ip", "-4", "neigh"], capture_output=True, text=True, timeout=2)
            for line in res.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 5 and "lladdr" in parts:
                    idx = parts.index("lladdr")
                    ip = parts[0]
                    mac = parts[idx + 1]
                    arp_cache[ip] = mac.lower()
        except Exception:
            pass

        return arp_cache

    def lookup_vendor(self, mac: str) -> str:
        """Lookup hardware vendor based on MAC prefix."""
        if not mac or mac == "00:00:00:00:00:00":
            return "Unknown"
        mac_clean = mac.lower().replace("-", ":")
        prefix = ":".join(mac_clean.split(":")[:3])
        return MAC_VENDORS.get(prefix, "Generic Network Device")

    async def _ping_host(self, ip: str, timeout: float = 0.8) -> Optional[float]:
        """Quickly ping a single host and return RTT in ms if online."""
        try:
            cmd = ["ping", "-c", "1", "-W", "1", str(ip)]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout + 0.3)
            if proc.returncode == 0:
                out = stdout.decode()
                # Extract time=XX.X ms
                if "time=" in out:
                    try:
                        time_part = out.split("time=")[1].split()[0]
                        return float(time_part)
                    except Exception:
                        return 1.0
                return 1.0
        except Exception:
            pass
        return None

    async def _tcp_probe(self, ip: str, port: int = 80, timeout: float = 0.5) -> bool:
        """Probe if a TCP port responds."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(str(ip), port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def _probe_single_host(self, ip_str: str, arp_cache: Dict[str, str], local_ip: str, gateway: str) -> Optional[Dict[str, Any]]:
        """Probe a single host via ping and TCP ports."""
        is_self = (ip_str == local_ip)
        is_gw = (ip_str == gateway)
        
        rtt = await self._ping_host(ip_str)
        is_alive = (rtt is not None)

        if not is_alive and not is_self:
            # Check fast TCP ports
            for port in [80, 443, 22, 139, 445, 8080]:
                if await self._tcp_probe(ip_str, port, timeout=0.3):
                    is_alive = True
                    rtt = 5.0
                    break

        # If IP is in ARP cache, it has communicated with us recently
        if not is_alive and ip_str in arp_cache:
            is_alive = True
            rtt = 10.0

        if not is_alive and not is_self:
            return None

        # Resolve hostname
        hostname = ip_str
        try:
            loop = asyncio.get_event_loop()
            res = await loop.run_in_executor(None, socket.getnameinfo, (ip_str, 0), socket.NI_NAMEREQD)
            hostname = res[0]
        except Exception:
            hostname = "Gateway Router" if is_gw else ("This Machine" if is_self else "Host")

        mac = arp_cache.get(ip_str, "Self Interface" if is_self else "Unknown")
        vendor = self.lookup_vendor(mac) if mac != "Self Interface" else "Local Adapter"

        role = "Host"
        if is_self:
            role = "This Machine (Local Host)"
        elif is_gw:
            role = "Default Gateway (Router)"

        return {
            "ip": ip_str,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "latency_ms": round(rtt, 2) if rtt is not None else 0.5,
            "status": "Online",
            "role": role,
            "is_self": is_self,
            "is_gateway": is_gw
        }

    async def scan_subnet(self, cidr: Optional[str] = None) -> List[Dict[str, Any]]:
        """Perform high-speed asynchronous parallel scan across subnet."""
        if self.is_scanning:
            return self.last_results

        self.is_scanning = True
        self.scan_progress = 0
        
        subnet_info = self.detect_local_subnet()
        target_subnet = cidr if cidr else subnet_info["subnet"]
        local_ip = subnet_info["local_ip"]
        gateway = subnet_info["gateway"]

        try:
            network = ipaddress.IPv4Network(target_subnet, strict=False)
            hosts = list(network.hosts())
            # Limit scan to max 512 hosts for performance
            if len(hosts) > 512:
                hosts = hosts[:512]
        except Exception:
            # Fallback to /24 around local IP
            base = ".".join(local_ip.split(".")[:3])
            hosts = [ipaddress.IPv4Address(f"{base}.{i}") for i in range(1, 255)]

        arp_cache = self._read_arp_table()
        
        # Parallel probe with semaphore to prevent socket exhaustion
        semaphore = asyncio.Semaphore(60)
        results = []
        completed = 0
        total = len(hosts)

        async def worker(host_ip):
            nonlocal completed
            async with semaphore:
                res = await self._probe_single_host(str(host_ip), arp_cache, local_ip, gateway)
                completed += 1
                self.scan_progress = int((completed / total) * 100)
                return res

        tasks = [worker(h) for h in hosts]
        probed_hosts = await asyncio.gather(*tasks, return_exceptions=True)

        for res in probed_hosts:
            if isinstance(res, dict) and res:
                results.append(res)

        # After scan, refresh ARP cache in case new entries were populated
        fresh_arp = self._read_arp_table()
        for r in results:
            if r["mac"] == "Unknown" and r["ip"] in fresh_arp:
                r["mac"] = fresh_arp[r["ip"]]
                r["vendor"] = self.lookup_vendor(r["mac"])

        # Sort: Local Machine first, then Gateway, then by IP
        results.sort(key=lambda x: (not x["is_self"], not x["is_gateway"], socket.inet_aton(x["ip"])))

        self.last_results = results
        self.last_scan_time = time.time()
        self.is_scanning = False
        self.scan_progress = 100
        return results

    async def scan_ports(self, target_ip: str, ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        """Fast asynchronous port scanner for a specific target IP."""
        if not ports:
            # Default to top 30 ports
            ports = [
                21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
                1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9000, 27017
            ]

        results = []
        semaphore = asyncio.Semaphore(40)

        async def check_port(port: int):
            async with semaphore:
                start_t = time.time()
                try:
                    conn = asyncio.open_connection(target_ip, port)
                    reader, writer = await asyncio.wait_for(conn, timeout=0.8)
                    rtt = round((time.time() - start_t) * 1000, 1)
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass
                    return {
                        "port": port,
                        "service": COMMON_PORTS.get(port, "Unknown"),
                        "state": "Open",
                        "latency_ms": rtt
                    }
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None

        tasks = [check_port(p) for p in ports]
        scanned = await asyncio.gather(*tasks, return_exceptions=True)
        
        for item in scanned:
            if isinstance(item, dict) and item:
                results.append(item)

        results.sort(key=lambda x: x["port"])
        return results
