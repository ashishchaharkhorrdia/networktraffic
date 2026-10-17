"""Integration tests for FastAPI REST API endpoints."""

from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_root_serves_html():
    response = client.get("/")
    assert response.status_code == 200
    assert "CyberNinjas" in response.text
    assert "<!DOCTYPE html>" in response.text

def test_api_overview():
    response = client.get("/api/overview")
    assert response.status_code == 200
    data = response.json()
    assert "bandwidth" in data
    assert "connections" in data
    assert "interfaces" in data
    assert "subnet" in data
    assert "sniffer_status" in data

def test_api_interfaces():
    response = client.get("/api/interfaces")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) > 0

def test_api_interfaces_select():
    response = client.post("/api/interfaces/select", json={"interface": "lo"})
    assert response.status_code == 200
    data = response.json()
    assert data["selected_interface"] == "lo"

def test_api_connections():
    response = client.get("/api/connections?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "connections" in data

def test_api_sniffer():
    # Generate demo packets
    demo_res = client.post("/api/sniffer/demo?count=5")
    assert demo_res.status_code == 200

    # Fetch packets
    packets_res = client.get("/api/sniffer/packets?limit=10")
    assert packets_res.status_code == 200
    data = packets_res.json()
    assert len(data["packets"]) >= 5
    assert "proto_distribution" in data

def test_api_diagnostics():
    res = client.get("/api/diagnostics/latency")
    assert res.status_code == 200
    data = res.json()
    assert "targets" in data
    assert len(data["targets"]) == 3

def test_api_firewall():
    # Test getting rules
    res = client.get("/api/firewall/rules")
    assert res.status_code == 200
    data = res.json()
    assert "rules" in data
    assert "stats" in data

    # Test blocking IP
    block_res = client.post("/api/firewall/block", json={
        "target": "203.0.113.55",
        "target_type": "ip",
        "reason": "Suspicious scan"
    })
    assert block_res.status_code == 200
    rule = block_res.json()["rule"]
    rule_id = rule["id"]
    assert rule["target"] == "203.0.113.55"

    # Test toggling rule
    toggle_res = client.post("/api/firewall/toggle", json={"rule_id": rule_id})
    assert toggle_res.status_code == 200
    assert toggle_res.json()["rule"]["is_active"] is False

    # Test unblocking
    unblock_res = client.post("/api/firewall/unblock", json={"rule_id": rule_id})
    assert unblock_res.status_code == 200
    assert unblock_res.json()["success"] is True

def test_api_geoip():
    # Test local bogon
    res_local = client.get("/api/geoip/lookup?ip=127.0.0.1")
    assert res_local.status_code == 200
    data_local = res_local.json()
    assert data_local["is_local"] is True
    assert data_local["country"] == "Localhost"

    # Test pre-seeded public IP
    res_pub = client.get("/api/geoip/lookup?ip=1.1.1.1")
    assert res_pub.status_code == 200
    data_pub = res_pub.json()
    assert data_pub["is_local"] is False
    assert "Cloudflare" in data_pub["org"]

def test_api_ids():
    # Test alert listing
    res = client.get("/api/ids/alerts")
    assert res.status_code == 200
    data = res.json()
    assert "alerts" in data
    assert "stats" in data
    assert len(data["alerts"]) > 0

    # Test stats
    stats_res = client.get("/api/ids/stats")
    assert stats_res.status_code == 200
    assert "total_alerts" in stats_res.json()

    # Test mitigation
    alert_id = data["alerts"][0]["id"]
    mit_res = client.post("/api/ids/mitigate", json={"alert_id": alert_id})
    assert mit_res.status_code == 200
    assert mit_res.json()["alert"]["mitigated"] is True

def test_api_processes_top_talkers():
    res = client.get("/api/processes/top-talkers")
    assert res.status_code == 200
    data = res.json()
    assert "top_talkers" in data
    assert isinstance(data["top_talkers"], list)

def test_api_traceroute():
    res = client.post("/api/diagnostics/traceroute", json={"target": "127.0.0.1", "max_hops": 3})
    assert res.status_code == 200
    data = res.json()
    assert "hops" in data
    assert data["target"] == "127.0.0.1"
    assert len(data["hops"]) > 0
