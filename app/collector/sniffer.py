"""Packet Sniffer, Deep Packet Inspector, and PCAP Analysis Engine."""

import os
import time
import threading
from collections import deque, Counter
from typing import Dict, Any, List, Optional
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.utils import wrpcap, rdpcap
from app.config import SNIFFER_MAX_PACKETS, COMMON_PORTS

class PacketSniffer:
    def __init__(self, max_packets: int = SNIFFER_MAX_PACKETS):
        self.max_packets = max_packets
        self.packet_buffer: deque = deque(maxlen=max_packets)
        self.raw_packets: deque = deque(maxlen=max_packets)
        self.packet_counter: int = 0
        self.is_sniffing: bool = False
        self.bpf_filter: str = ""
        self.interface: Optional[str] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.lock = threading.Lock()
        
        # Test permission once at startup
        self.has_permission = self._check_permission()

    def _check_permission(self) -> bool:
        """Check if raw socket sniffing is permitted without throwing crash."""
        try:
            # Attempt a 0-second or 1-count sniff on loopback
            scapy.sniff(count=1, timeout=0.05, iface="lo", store=False)
            return True
        except Exception:
            return False

    def format_hexdump(self, data: bytes) -> str:
        """Format raw bytes as classic hexdump with offset, hex bytes, and ASCII."""
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            lines.append(f"{i:04x}   {hex_part:<48}   |{ascii_part}|")
        return "\n".join(lines)

    def _parse_packet(self, pkt) -> Dict[str, Any]:
        """Convert a Scapy packet into a structured dictionary."""
        self.packet_counter += 1
        pkt_id = self.packet_counter
        timestamp = time.strftime("%H:%M:%S", time.localtime(pkt.time if hasattr(pkt, "time") else time.time()))
        length = len(pkt)

        # Layer 2
        src_mac = pkt[Ether].src if Ether in pkt else "-"
        dst_mac = pkt[Ether].dst if Ether in pkt else "-"

        # Layer 3 / 4 Defaults
        src_ip = "-"
        dst_ip = "-"
        proto_name = "Other"
        src_port = 0
        dst_port = 0
        info = ""
        flags_str = ""
        ttl = 64

        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            ttl = pkt[IP].ttl
            proto_num = pkt[IP].proto
            if proto_num == 6:
                proto_name = "TCP"
            elif proto_num == 17:
                proto_name = "UDP"
            elif proto_num == 1:
                proto_name = "ICMP"
            else:
                proto_name = f"IP-{proto_num}"
        elif ARP in pkt:
            proto_name = "ARP"
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            op = "Who has" if pkt[ARP].op == 1 else "Is at"
            info = f"ARP: {op} {dst_ip}? Tell {src_ip}"

        # TCP Details
        if TCP in pkt:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            # Flags
            flags = []
            f = pkt[TCP].flags
            if f & 0x02: flags.append("SYN")
            if f & 0x10: flags.append("ACK")
            if f & 0x01: flags.append("FIN")
            if f & 0x04: flags.append("RST")
            if f & 0x08: flags.append("PSH")
            if f & 0x20: flags.append("URG")
            flags_str = ",".join(flags) if flags else "NONE"
            seq = pkt[TCP].seq
            ack = pkt[TCP].ack
            info = f"Seq={seq} Ack={ack} Flags=[{flags_str}] Win={pkt[TCP].window}"

            # Check HTTP or TLS
            if dst_port == 443 or src_port == 443:
                proto_name = "TLS/HTTPS"
            elif dst_port == 80 or src_port == 80:
                proto_name = "HTTP"
            elif dst_port == 22 or src_port == 22:
                proto_name = "SSH"

        # UDP Details
        elif UDP in pkt:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            if DNS in pkt:
                proto_name = "DNS"
                if pkt[DNS].qd:
                    qname = pkt[DNS].qd.qname.decode(errors="ignore") if hasattr(pkt[DNS].qd.qname, "decode") else str(pkt[DNS].qd.qname)
                    info = f"Standard query {qname}"
                else:
                    info = "DNS Packet"
            elif dst_port == 53 or src_port == 53:
                proto_name = "DNS"
                info = f"DNS Port 53 {src_port} -> {dst_port}"
            else:
                info = f"Len={pkt[UDP].len}"

        elif ICMP in pkt:
            proto_name = "ICMP"
            type_num = pkt[ICMP].type
            code_num = pkt[ICMP].code
            info = f"Type={type_num} Code={code_num}"

        if not info:
            info = f"{proto_name} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"

        raw_bytes = bytes(pkt)
        hexdump_str = self.format_hexdump(raw_bytes[:512])  # Truncate to first 512 bytes for display

        service = COMMON_PORTS.get(dst_port) or COMMON_PORTS.get(src_port) or "-"

        return {
            "id": pkt_id,
            "timestamp": timestamp,
            "length": length,
            "proto": proto_name,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "src_mac": src_mac,
            "dst_mac": dst_mac,
            "ttl": ttl,
            "flags": flags_str,
            "service": service,
            "info": info,
            "hexdump": hexdump_str,
            "summary": pkt.summary()
        }

    def start_sniffing(self, interface: Optional[str] = None, bpf_filter: str = "") -> Dict[str, Any]:
        """Start capturing packets in background thread."""
        if not self.has_permission:
            return {
                "success": False,
                "error": "Raw socket permission denied. Run tool with sudo or grant cap_net_raw: 'sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)'"
            }

        if self.is_sniffing:
            return {"success": True, "message": "Sniffer already running"}

        self._stop_event.clear()
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.is_sniffing = True

        def capture_worker():
            def packet_callback(pkt):
                if self._stop_event.is_set():
                    return True
                parsed = self._parse_packet(pkt)
                with self.lock:
                    self.packet_buffer.append(parsed)
                    self.raw_packets.append(pkt)

            try:
                sniff_kwargs = {
                    "prn": packet_callback,
                    "stop_filter": lambda _: self._stop_event.is_set(),
                    "store": False
                }
                if self.interface and self.interface != "all":
                    sniff_kwargs["iface"] = self.interface
                if self.bpf_filter:
                    sniff_kwargs["filter"] = self.bpf_filter

                scapy.sniff(**sniff_kwargs)
            except Exception as e:
                self.is_sniffing = False

        self._thread = threading.Thread(target=capture_worker, daemon=True)
        self._thread.start()

        return {"success": True, "message": "Live packet capture started"}

    def stop_sniffing(self) -> Dict[str, Any]:
        """Stop active packet sniffer."""
        if not self.is_sniffing:
            return {"success": True, "message": "Sniffer is not running"}

        self._stop_event.set()
        self.is_sniffing = False
        return {"success": True, "message": "Packet capture stopped"}

    def clear_buffer(self):
        """Clear captured packets."""
        with self.lock:
            self.packet_buffer.clear()
            self.raw_packets.clear()
            self.packet_counter = 0

    def get_packets(self, limit: int = 200, filter_proto: Optional[str] = None) -> Dict[str, Any]:
        """Get latest parsed packets with protocol statistics."""
        with self.lock:
            pkts = list(self.packet_buffer)

        # Statistics
        proto_counts = Counter(p["proto"] for p in pkts)
        total_bytes = sum(p["length"] for p in pkts)

        if filter_proto and filter_proto != "ALL":
            pkts = [p for p in pkts if p["proto"].upper() == filter_proto.upper()]

        return {
            "is_sniffing": self.is_sniffing,
            "has_permission": self.has_permission,
            "total_captured": len(self.packet_buffer),
            "total_bytes": total_bytes,
            "proto_distribution": dict(proto_counts),
            "packets": pkts[-limit:][::-1]  # Most recent first
        }

    def load_pcap_file(self, filepath: str) -> Dict[str, Any]:
        """Parse an uploaded PCAP file."""
        try:
            packets = rdpcap(filepath)
            with self.lock:
                self.clear_buffer()
                for pkt in packets:
                    parsed = self._parse_packet(pkt)
                    self.packet_buffer.append(parsed)
                    self.raw_packets.append(pkt)
            return {
                "success": True,
                "packet_count": len(packets),
                "message": f"Successfully parsed {len(packets)} packets from PCAP file."
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def export_pcap(self, target_filepath: str) -> str:
        """Export buffered raw packets to a PCAP file."""
        with self.lock:
            pkts = list(self.raw_packets)
        wrpcap(target_filepath, pkts)
        return target_filepath

    def generate_demo_packets(self, count: int = 25):
        """Generate representative demonstration packets for testing and offline display."""
        with self.lock:
            import random
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.l2 import Ether
            
            sample_protocols = [
                ("TCP", 443, "HTTPS Web Traffic"),
                ("TCP", 80, "HTTP Web Request"),
                ("UDP", 53, "DNS Query / Response"),
                ("TCP", 22, "SSH Remote Session"),
                ("ICMP", 0, "ICMP Echo Reply"),
                ("TCP", 3306, "MySQL Database Query")
            ]

            now = time.time()
            for i in range(count):
                proto_choice, port, desc = random.choice(sample_protocols)
                src = f"192.168.43.{random.randint(10, 200)}"
                dst = f"142.250.190.{random.randint(1, 100)}" if port == 443 else f"8.8.8.{random.randint(1, 8)}"
                
                if proto_choice == "TCP":
                    pkt = Ether()/IP(src=src, dst=dst)/TCP(sport=random.randint(30000, 60000), dport=port, flags="PA")/b"GET /api/v1/status HTTP/1.1\r\nHost: example.com\r\n\r\n"
                elif proto_choice == "UDP":
                    pkt = Ether()/IP(src=src, dst=dst)/UDP(sport=random.randint(30000, 60000), dport=port)/b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06google\x03com\x00\x00\x01\x00\x01"
                else:
                    pkt = Ether()/IP(src=src, dst=dst)/ICMP(type=8, code=0)/b"Echo Ping Payload 0123456789"
                
                parsed = self._parse_packet(pkt)
                self.packet_buffer.append(parsed)
                self.raw_packets.append(pkt)
