"""Network Diagnostics, Ping Latency, Jitter, and DNS Resolution Benchmark."""

import time
import socket
import asyncio
import subprocess
from typing import Dict, Any, List

class DiagnosticsCollector:
    def __init__(self):
        self.latency_history: Dict[str, List[float]] = {
            "Gateway": [],
            "Google (8.8.8.8)": [],
            "Cloudflare (1.1.1.1)": []
        }

    async def ping_target(self, target: str, count: int = 1) -> Dict[str, Any]:
        """Ping a specific target and compute RTT, jitter, and status."""
        try:
            cmd = ["ping", "-c", str(count), "-W", "1", target]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=2.0)
            
            if proc.returncode == 0:
                output = stdout.decode()
                # Parse rtt min/avg/max/mdev = 3.452/4.501/5.551/1.049 ms
                rtt_val = 0.0
                mdev = 0.0
                if "min/avg/max/mdev" in output:
                    stats_line = [l for l in output.splitlines() if "min/avg/max" in l][0]
                    values = stats_line.split("=")[1].strip().split()[0].split("/")
                    rtt_val = float(values[1])
                    mdev = float(values[3])
                elif "time=" in output:
                    t_str = output.split("time=")[1].split()[0]
                    rtt_val = float(t_str)

                return {
                    "target": target,
                    "status": "Online",
                    "latency_ms": round(rtt_val, 2),
                    "jitter_ms": round(mdev, 2),
                    "packet_loss_pct": 0
                }
            else:
                return {
                    "target": target,
                    "status": "Timeout / Packet Loss",
                    "latency_ms": 0.0,
                    "jitter_ms": 0.0,
                    "packet_loss_pct": 100
                }
        except Exception:
            return {
                "target": target,
                "status": "Unreachable",
                "latency_ms": 0.0,
                "jitter_ms": 0.0,
                "packet_loss_pct": 100
            }

    async def get_multi_latency(self, gateway_ip: str = "192.168.43.118") -> List[Dict[str, Any]]:
        """Probe all key network targets concurrently."""
        targets = [
            {"name": "Local Gateway", "ip": gateway_ip},
            {"name": "Google DNS", "ip": "8.8.8.8"},
            {"name": "Cloudflare DNS", "ip": "1.1.1.1"}
        ]

        tasks = [self.ping_target(t["ip"]) for t in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        structured = []
        for i, res in enumerate(results):
            if isinstance(res, dict):
                structured.append({
                    "name": targets[i]["name"],
                    "ip": targets[i]["ip"],
                    "latency_ms": res.get("latency_ms", 0.0),
                    "jitter_ms": res.get("jitter_ms", 0.0),
                    "status": res.get("status", "Unknown"),
                    "loss_pct": res.get("packet_loss_pct", 0)
                })
        return structured

    async def benchmark_dns(self, domains: List[str] = None) -> List[Dict[str, Any]]:
        """Benchmark DNS resolution speeds across common domains."""
        if not domains:
            domains = ["google.com", "cloudflare.com", "github.com", "wikipedia.org", "amazon.com"]

        results = []
        loop = asyncio.get_event_loop()

        for domain in domains:
            start_t = time.time()
            try:
                # Resolve using socket getaddrinfo
                addrinfo = await loop.run_in_executor(None, socket.getaddrinfo, domain, 80)
                elapsed_ms = round((time.time() - start_t) * 1000, 2)
                resolved_ips = list(set([item[4][0] for item in addrinfo if item[0] == socket.AF_INET]))
                results.append({
                    "domain": domain,
                    "status": "Resolved",
                    "lookup_time_ms": elapsed_ms,
                    "ips": resolved_ips[:3]
                })
            except Exception as e:
                elapsed_ms = round((time.time() - start_t) * 1000, 2)
                results.append({
                    "domain": domain,
                    "status": "Failed",
                    "lookup_time_ms": elapsed_ms,
                    "ips": [],
                    "error": str(e)
                })

        return results
