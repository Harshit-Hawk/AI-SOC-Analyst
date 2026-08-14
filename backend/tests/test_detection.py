import pytest
from app.services.detection import RuleDetectionEngine
from app.simulator.attack_scenarios import AttackSimulator

def test_brute_force_rule_detection():
    engine = RuleDetectionEngine()
    events = AttackSimulator.generate_brute_force(count=10, src_ip="192.168.1.100")
    alerts = engine.analyze_events(events)
    assert len(alerts) >= 1
    assert any(a.category == "Brute Force" for a in alerts)
    assert alerts[0].mitre_technique_id == "T1110"

def test_port_scan_rule_detection():
    engine = RuleDetectionEngine()
    events = AttackSimulator.generate_port_scan(num_ports=20, src_ip="10.0.0.99")
    alerts = engine.analyze_events(events)
    assert len(alerts) >= 1
    assert any(a.category == "Port Scan" for a in alerts)
    assert alerts[0].mitre_technique_id == "T1046"

def test_dos_rule_detection():
    engine = RuleDetectionEngine()
    events = AttackSimulator.generate_dos(count=60, src_ip="172.16.0.50")
    alerts = engine.analyze_events(events)
    assert len(alerts) >= 1
    assert any(a.category == "DoS" for a in alerts)
    assert alerts[0].mitre_technique_id == "T1499"

def test_privilege_anomaly_detection():
    engine = RuleDetectionEngine()
    events = AttackSimulator.generate_privilege_anomaly(src_ip="192.168.1.50")
    alerts = engine.analyze_events(events)
    assert len(alerts) >= 1
    assert any(a.category == "Privilege Anomaly" for a in alerts)
    assert alerts[0].mitre_technique_id == "T1078"
