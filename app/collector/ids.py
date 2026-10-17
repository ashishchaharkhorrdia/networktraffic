"""Intrusion Detection System (IDS) and Heuristic Threat Intelligence Engine for CyberNinjas."""

import time
import uuid
from collections import deque, defaultdict
from typing import Dict, Any, List, Optional

class IntrusionDetectionEngine:
    """Real-time network security anomaly detection and threat alert aggregator."""

    SUSPICIOUS_PORTS = {
        4444: ("Metasploit C2 Listener", "CRITICAL"),
        5555: ("Android Debug Bridge Remote Exploit", "HIGH"),
        6667: ("IRC Botnet Command & Control Channel", "HIGH"),
        1337: ("Elite Trojan Backdoor", "HIGH"),
        31337: ("Back Orifice Remote Access Trojan", "CRITICAL"),
        445: ("SMB Remote Execution / EternalBlue Probe", "HIGH"),
        23: ("Telnet Brute-Force Botnet Probe", "MEDIUM"),
        3389: ("External RDP Credential Spray", "MEDIUM"),
    }

    def __init__(self, firewall_manager=None, max_alerts: int = 150):
        self.firewall_manager = firewall_manager
        self.max_alerts = max_alerts
        self.alerts = deque(maxlen=max_alerts)
        
        # Sliding tracking windows for anomaly heuristics
        self._port_scan_tracker = defaultdict(lambda: {"ports": set(), "first_seen": 0.0})
        self._syn_tracker = defaultdict(int)

        # Pre-seed realistic threat alerts for instant SOC demonstration
        self._seed_default_threats()

    def _seed_default_threats(self):
        """Seed realistic enterprise threat detection events."""
        base_time = time.time()
        
        seeds = [
            {
                "id": "alt_probe_101",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(base_time - 320)),
                "severity": "CRITICAL",
                "category": "PORT_SCAN",
                "title": "Horizontal TCP Port Sweep Detected",
                "source_ip": "185.220.101.5",
                "target_port": "Multiple (22, 80, 443, 8080, 3306)",
                "description": "Remote scanner probed 5 distinct service ports within 1.8 seconds.",
                "mitigated": True,
                "action_recommended": "DROP traffic at gateway border"
            },
            {
                "id": "alt_probe_102",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(base_time - 180)),
                "severity": "HIGH",
                "category": "MALWARE_C2",
                "title": "Suspected Botnet C2 Beaconing",
                "source_ip": "198.51.100.23",
                "target_port": 6667,
                "description": "Periodic outbound TCP connection attempts to known IRC botnet port 6667.",
                "mitigated": False,
                "action_recommended": "Block source IP and terminate attributed PID"
            },
            {
                "id": "alt_probe_103",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(base_time - 75)),
                "severity": "HIGH",
                "category": "EXPLOIT_PROBE",
                "title": "Metasploit Reverse Handler Inbound Probe",
                "source_ip": "45.146.165.37",
                "target_port": 4444,
                "description": "Inbound SYN packet targeting default Metasploit payload listener port 4444.",
                "mitigated": False,
                "action_recommended": "Block target IP in firewall"
            },
            {
                "id": "alt_probe_104",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(base_time - 25)),
                "severity": "MEDIUM",
                "category": "DNS_ANOMALY",
                "title": "High-Entropy DNS Exfiltration Query",
                "source_ip": "192.168.1.105",
                "target_port": 53,
                "description": "DNS query length exceeded 52 bytes with base64 encoded subdomain pattern.",
                "mitigated": False,
                "action_recommended": "Inspect requesting application process"
            }
        ]

        for s in seeds:
            self.alerts.append(s)

    def analyze_connection(self, conn: Dict[str, Any]):
        """Inspect active socket connection for threat signatures."""
        r_ip = conn.get("remote_ip")
        r_port = conn.get("remote_port", 0)
        l_port = conn.get("local_port", 0)
        status = conn.get("status", "")

        if not r_ip or r_ip.startswith("127.") or r_ip in ["0.0.0.0", "::1", "::"]:
            return

        now = time.time()

        # Check 1: Known malware/exploit ports
        target_p = r_port if r_port else l_port
        if target_p in self.SUSPICIOUS_PORTS:
            desc, sev = self.SUSPICIOUS_PORTS[target_p]
            # Avoid duplicate spam for the same target
            if not any(a["source_ip"] == r_ip and a["target_port"] == target_p for a in list(self.alerts)[-10:]):
                self.create_alert(
                    severity=sev,
                    category="SUSPICIOUS_PORT",
                    title=f"Exploit Target Port Detected ({target_p})",
                    source_ip=r_ip,
                    target_port=target_p,
                    description=f"{desc} targeting port {target_p} (Status: {status})"
                )

        # Check 2: Port scanning heuristic (>= 4 ports in 15 seconds)
        record = self._port_scan_tracker[r_ip]
        if now - record["first_seen"] > 15:
            record["ports"] = set()
            record["first_seen"] = now

        if target_p:
            record["ports"].add(target_p)
            if len(record["ports"]) >= 4:
                if not any(a["source_ip"] == r_ip and a["category"] == "PORT_SCAN" for a in list(self.alerts)[-5:]):
                    ports_str = ", ".join(str(p) for p in sorted(list(record["ports"]))[:6])
                    self.create_alert(
                        severity="CRITICAL",
                        category="PORT_SCAN",
                        title="Port Scan Probe in Progress",
                        source_ip=r_ip,
                        target_port=f"Multiple ({ports_str})",
                        description=f"Host connected to {len(record['ports'])} distinct ports in under 15s."
                    )

    def create_alert(
        self,
        severity: str,
        category: str,
        title: str,
        source_ip: str,
        target_port: Any,
        description: str,
        action_recommended: str = "Add rule to Firewall blocklist"
    ) -> Dict[str, Any]:
        """Create and record a new threat event."""
        alert_id = f"alt_{int(time.time()*1000)}_{uuid.uuid4().hex[:4]}"
        alert = {
            "id": alert_id,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
            "severity": severity,
            "category": category,
            "title": title,
            "source_ip": source_ip,
            "target_port": target_port,
            "description": description,
            "mitigated": False,
            "action_recommended": action_recommended
        }
        self.alerts.appendleft(alert)
        return alert

    def mitigate_alert(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Mitigate threat by blocking its source IP in FirewallManager."""
        for alert in self.alerts:
            if alert["id"] == alert_id:
                alert["mitigated"] = True
                if self.firewall_manager and alert.get("source_ip"):
                    target = alert["source_ip"]
                    try:
                        self.firewall_manager.add_rule(
                            target=target,
                            target_type="ip",
                            reason=f"IDS Auto-Mitigation: {alert.get('title')}"
                        )
                    except Exception:
                        pass
                return alert
        return None

    def get_alerts(self, limit: int = 50, severity: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve recent alerts filtered by optional severity."""
        all_alerts = list(self.alerts)
        if severity and severity.upper() != "ALL":
            all_alerts = [a for a in all_alerts if a["severity"].upper() == severity.upper()]
        return all_alerts[:limit]

    def clear_alerts(self):
        """Flush the active alerts buffer."""
        self.alerts.clear()

    def get_stats(self) -> Dict[str, Any]:
        """Compute aggregated severity and mitigation metrics."""
        total = len(self.alerts)
        critical = sum(1 for a in self.alerts if a["severity"] == "CRITICAL")
        high = sum(1 for a in self.alerts if a["severity"] == "HIGH")
        medium = sum(1 for a in self.alerts if a["severity"] == "MEDIUM")
        info = sum(1 for a in self.alerts if a["severity"] == "INFO")
        mitigated = sum(1 for a in self.alerts if a.get("mitigated", False))
        unmitigated = total - mitigated

        return {
            "total_alerts": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "info": info,
            "mitigated": mitigated,
            "unmitigated": unmitigated,
            "threat_level": "ELEVATED" if (critical > 0 or high > 1) else ("GUARDED" if medium > 0 else "NORMAL")
        }
