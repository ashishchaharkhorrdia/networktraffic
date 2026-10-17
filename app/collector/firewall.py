"""Firewall, Access Control & Rule Blocker Module for CyberNinjas."""

import os
import json
import time
import re
from typing import Dict, Any, List, Optional

RULES_FILE = os.path.join(os.path.dirname(__file__), "..", "firewall_rules.json")

DEFAULT_RULES = [
    {
        "id": "rule_1",
        "target": "185.220.101.5",
        "target_type": "ip",
        "reason": "Known Tor Exit Node & Scanning Probe",
        "action": "DROP",
        "is_active": True,
        "created_at": "2026-10-17 14:20:00",
        "hits": 142
    },
    {
        "id": "rule_2",
        "target": "198.51.100.23",
        "target_type": "ip",
        "reason": "Repeated SSH Credential Brute-Force",
        "action": "DROP",
        "is_active": True,
        "created_at": "2026-10-17 16:45:12",
        "hits": 89
    },
    {
        "id": "rule_3",
        "target": "malware-traffic-telemetry.net",
        "target_type": "domain",
        "reason": "Suspected C2 Beacon & Ransomware Dropper",
        "action": "BLOCK",
        "is_active": True,
        "created_at": "2026-10-17 18:10:30",
        "hits": 215
    },
    {
        "id": "rule_4",
        "target": "adservice.tracker-analytics.com",
        "target_type": "domain",
        "reason": "Intrusive Cross-Site Behavioral Tracker",
        "action": "BLOCK",
        "is_active": True,
        "created_at": "2026-10-17 19:30:15",
        "hits": 540
    }
]

class FirewallManager:
    def __init__(self, persistence_file: str = RULES_FILE):
        self.persistence_file = persistence_file
        self.rules: List[Dict[str, Any]] = []
        self.load_rules()

    def load_rules(self):
        """Load persisted firewall rules or initialize defaults."""
        if os.path.exists(self.persistence_file):
            try:
                with open(self.persistence_file, "r", encoding="utf-8") as f:
                    self.rules = json.load(f)
                return
            except Exception:
                pass
        self.rules = list(DEFAULT_RULES)
        self.save_rules()

    def save_rules(self):
        """Persist rules to storage."""
        try:
            with open(self.persistence_file, "w", encoding="utf-8") as f:
                json.dump(self.rules, f, indent=2)
        except Exception as e:
            print(f"Error persisting firewall rules: {e}")

    def get_rules(self) -> List[Dict[str, Any]]:
        return self.rules

    def add_rule(self, target: str, target_type: Optional[str] = None, reason: str = "") -> Dict[str, Any]:
        """Add a new IP or Domain block rule."""
        target = target.strip().lower()
        if not target:
            raise ValueError("Target IP or Domain cannot be empty")

        # Auto-detect target type if not explicitly supplied
        if not target_type or target_type not in ["ip", "domain"]:
            ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$"
            target_type = "ip" if re.match(ip_pattern, target) else "domain"

        # Check if already exists
        for rule in self.rules:
            if rule["target"].lower() == target:
                rule["is_active"] = True
                rule["reason"] = reason or rule.get("reason", "Manual block")
                self.save_rules()
                return rule

        new_rule = {
            "id": f"rule_{int(time.time() * 1000)}",
            "target": target,
            "target_type": target_type,
            "reason": reason or f"Manual block rule for {target}",
            "action": "DROP" if target_type == "ip" else "BLOCK",
            "is_active": True,
            "created_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "hits": 0
        }
        self.rules.insert(0, new_rule)
        self.save_rules()
        return new_rule

    def remove_rule(self, rule_id: str) -> bool:
        """Remove a blocking rule by its ID."""
        initial_len = len(self.rules)
        self.rules = [r for r in self.rules if r["id"] != rule_id and r["target"] != rule_id]
        if len(self.rules) != initial_len:
            self.save_rules()
            return True
        return False

    def toggle_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Toggle active/inactive status of a rule."""
        for rule in self.rules:
            if rule["id"] == rule_id or rule["target"] == rule_id:
                rule["is_active"] = not rule["is_active"]
                self.save_rules()
                return rule
        return None

    def is_blocked(self, ip: Optional[str] = None, domain: Optional[str] = None) -> bool:
        """Check if an IP or domain matches any active block rule."""
        for rule in self.rules:
            if not rule.get("is_active", True):
                continue
            if ip and rule["target_type"] == "ip" and rule["target"] == ip:
                rule["hits"] = rule.get("hits", 0) + 1
                return True
            if domain and rule["target_type"] == "domain":
                d = domain.lower()
                target_d = rule["target"].lower()
                if d == target_d or d.endswith("." + target_d):
                    rule["hits"] = rule.get("hits", 0) + 1
                    return True
        return False

    def get_stats(self) -> Dict[str, Any]:
        """Summary statistics for dashboard."""
        total = len(self.rules)
        active = sum(1 for r in self.rules if r.get("is_active", True))
        ips = sum(1 for r in self.rules if r["target_type"] == "ip" and r.get("is_active", True))
        domains = sum(1 for r in self.rules if r["target_type"] == "domain" and r.get("is_active", True))
        total_hits = sum(r.get("hits", 0) for r in self.rules)
        return {
            "total_rules": total,
            "active_rules": active,
            "blocked_ips": ips,
            "blocked_domains": domains,
            "total_intercepted": total_hits
        }
