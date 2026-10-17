"""Unit and Integration Tests for CyberNinjas Collectors and API."""

import pytest
import asyncio
from app.collector.bandwidth import BandwidthCollector
from app.collector.connections import ConnectionCollector
from app.collector.scanner import NetworkScanner
from app.collector.sniffer import PacketSniffer
from app.collector.diagnostics import DiagnosticsCollector

def test_bandwidth_collector():
    collector = BandwidthCollector(history_len=10)
    data = collector.collect()
    assert "current" in data
    assert "history" in data
    assert "session" in data
    assert "rx_kbps" in data["current"]
    assert "tx_kbps" in data["current"]

    # Test interfaces info
    ifaces = collector.get_interfaces_info()
    assert isinstance(ifaces, list)
    assert len(ifaces) > 0
    # Make sure at least loopback or wlan0 is found
    names = [i["name"] for i in ifaces]
    assert "lo" in names

    # Default interface
    default_info = collector.get_default_interface()
    assert "interface" in default_info
    assert "gateway" in default_info

def test_connection_collector():
    collector = ConnectionCollector()
    data = collector.get_connections(limit=50)
    assert "total" in data
    assert "established" in data
    assert "listening" in data
    assert "connections" in data
    assert "protocol_distribution" in data
    assert isinstance(data["connections"], list)

    # Test DNS hostname cache
    hostname = collector.get_hostname("127.0.0.1")
    assert hostname == "localhost"

def test_network_scanner_subnet_detection():
    scanner = NetworkScanner()
    subnet_info = scanner.detect_local_subnet()
    assert "local_ip" in subnet_info
    assert "subnet" in subnet_info
    assert "/" in subnet_info["subnet"]

    # Test MAC vendor lookup
    vendor = scanner.lookup_vendor("b8:27:eb:11:22:33")
    assert "Raspberry Pi" in vendor

def test_network_scanner_port_scan():
    scanner = NetworkScanner()
    # Port scan localhost
    res = asyncio.run(scanner.scan_ports("127.0.0.1", ports=[9999, 54321]))
    assert isinstance(res, list)

def test_packet_sniffer():
    sniffer = PacketSniffer(max_packets=50)
    assert sniffer.packet_counter == 0

    # Test demo packet generation
    sniffer.generate_demo_packets(10)
    packets_data = sniffer.get_packets()
    assert packets_data["total_captured"] == 10
    assert len(packets_data["packets"]) == 10

    first_pkt = packets_data["packets"][0]
    assert "proto" in first_pkt
    assert "hexdump" in first_pkt
    assert "length" in first_pkt
    assert len(first_pkt["hexdump"]) > 0

    # Clear
    sniffer.clear_buffer()
    assert len(sniffer.get_packets()["packets"]) == 0

def test_diagnostics_dns_benchmark():
    diag = DiagnosticsCollector()
    results = asyncio.run(diag.benchmark_dns(domains=["google.com"]))
    assert len(results) == 1
    assert results[0]["domain"] == "google.com"
    assert "lookup_time_ms" in results[0]
