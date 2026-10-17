"""GeoIP and Autonomous System Number (ASN) Resolution Engine for CyberNinjas."""

import json
import socket
import ipaddress
import threading
import urllib.request
from typing import Dict, Any, Optional

class GeoIPResolver:
    """Thread-safe GeoIP and ASN intelligence resolver with local memory cache."""

    def __init__(self):
        self._cache_lock = threading.Lock()
        self._pending_lookups = set()
        
        # Pre-seeded cache for well-known infrastructure and private bogons
        self._cache: Dict[str, Dict[str, Any]] = {
            "127.0.0.1": {
                "ip": "127.0.0.1",
                "country": "Localhost",
                "country_code": "LOCAL",
                "city": "Internal Loopback",
                "org": "Loopback Device",
                "asn": "PRIVATE",
                "is_local": True
            },
            "::1": {
                "ip": "::1",
                "country": "Localhost",
                "country_code": "LOCAL",
                "city": "Internal Loopback",
                "org": "IPv6 Loopback",
                "asn": "PRIVATE",
                "is_local": True
            },
            "1.1.1.1": {
                "ip": "1.1.1.1",
                "country": "United States",
                "country_code": "US",
                "city": "Washington",
                "org": "Cloudflare, Inc.",
                "asn": "AS13335 Cloudflare",
                "is_local": False
            },
            "8.8.8.8": {
                "ip": "8.8.8.8",
                "country": "United States",
                "country_code": "US",
                "city": "Mountain View",
                "org": "Google LLC",
                "asn": "AS15169 Google",
                "is_local": False
            },
            "9.9.9.9": {
                "ip": "9.9.9.9",
                "country": "Switzerland",
                "country_code": "CH",
                "city": "Zurich",
                "org": "Quad9",
                "asn": "AS19281 Quad9",
                "is_local": False
            },
            "185.220.101.5": {
                "ip": "185.220.101.5",
                "country": "Germany",
                "country_code": "DE",
                "city": "Frankfurt am Main",
                "org": "Tor Exit Node Network",
                "asn": "AS60729 Zwiebelfreunde",
                "is_local": False
            }
        }

    def is_private_ip(self, ip_str: str) -> bool:
        """Check if an IP address belongs to RFC 1918 or private address spaces."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return (
                ip_obj.is_private or
                ip_obj.is_loopback or
                ip_obj.is_link_local or
                ip_obj.is_multicast or
                ip_obj.is_reserved or
                ip_str == "0.0.0.0" or
                ip_str == "::"
            )
        except ValueError:
            return False

    def _async_query(self, ip: str):
        """Asynchronously query public GeoIP API without blocking collector threads."""
        def worker():
            try:
                url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,city,as,org,query"
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "CyberNinjas-Network-SOC/1.0"}
                )
                with urllib.request.urlopen(req, timeout=2.0) as resp:
                    if resp.status == 200:
                        data = json.loads(resp.read().decode())
                        if data.get("status") == "success":
                            entry = {
                                "ip": ip,
                                "country": data.get("country", "Unknown"),
                                "country_code": data.get("countryCode", "UN"),
                                "city": data.get("city", "Unknown"),
                                "org": data.get("org", "Unknown ISP"),
                                "asn": data.get("as", "Unknown ASN"),
                                "is_local": False
                            }
                            with self._cache_lock:
                                self._cache[ip] = entry
            except Exception:
                # Fallback entry on network failure or rate limit
                with self._cache_lock:
                    if ip not in self._cache:
                        self._cache[ip] = {
                            "ip": ip,
                            "country": "Remote Internet",
                            "country_code": "NET",
                            "city": "Public Host",
                            "org": "External ISP",
                            "asn": "WAN",
                            "is_local": False
                        }
            finally:
                with self._cache_lock:
                    if ip in self._pending_lookups:
                        self._pending_lookups.remove(ip)

        t = threading.Thread(target=worker, daemon=True)
        t.start()

    def resolve(self, ip: str) -> Dict[str, Any]:
        """Resolve IP address to geographical and ASN metadata."""
        if not ip or ip == "-" or ip == "0.0.0.0" or ip == "::":
            return {
                "ip": ip or "-",
                "country": "Unassigned",
                "country_code": "NA",
                "city": "-",
                "org": "-",
                "asn": "-",
                "is_local": True
            }

        with self._cache_lock:
            if ip in self._cache:
                return self._cache[ip]

        # Check if local or private subnet
        if self.is_private_ip(ip):
            entry = {
                "ip": ip,
                "country": "Local Network",
                "country_code": "LAN",
                "city": "Internal Subnet",
                "org": "Private RFC 1918 Gateway",
                "asn": "INTERNAL",
                "is_local": True
            }
            with self._cache_lock:
                self._cache[ip] = entry
            return entry

        # Queue async lookup for public external addresses
        with self._cache_lock:
            if ip not in self._pending_lookups:
                self._pending_lookups.add(ip)
                self._async_query(ip)

        # Return provisional entry while resolving in background
        return {
            "ip": ip,
            "country": "Resolving...",
            "country_code": "...",
            "city": "Looking up",
            "org": "External Host",
            "asn": "Resolving ASN",
            "is_local": False
        }

    def get_distribution(self, ips: list) -> Dict[str, int]:
        """Calculate country distribution counts for given IP list."""
        distribution: Dict[str, int] = {}
        for ip in ips:
            info = self.resolve(ip)
            country = info.get("country", "Unknown")
            distribution[country] = distribution.get(country, 0) + 1
        return distribution
