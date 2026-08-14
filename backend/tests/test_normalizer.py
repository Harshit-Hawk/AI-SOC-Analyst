import pytest
from app.services.normalizer import LogNormalizer

def test_json_normalization():
    json_data = {
        "src_ip": "192.168.1.10",
        "dest_ip": "10.0.0.1",
        "src_port": 1234,
        "dest_port": 80,
        "protocol": "tcp",
        "event_type": "network",
        "username": "john",
        "action": "connect",
        "status": "success",
        "message": "HTTP request"
    }
    res = LogNormalizer.process_raw_payload("json", json_data)
    assert res.normalized_count == 1
    assert res.failed_count == 0
    event = res.events[0]
    assert event.source_ip == "192.168.1.10"
    assert event.destination_ip == "10.0.0.1"
    assert event.destination_port == 80
    assert event.protocol == "TCP"

def test_syslog_normalization():
    syslog_str = "Feb 14 12:00:00 server sshd[4012]: Failed password for root from 192.168.1.50 port 55120 ssh2"
    res = LogNormalizer.process_raw_payload("syslog", syslog_str)
    assert res.normalized_count == 1
    event = res.events[0]
    assert event.source_ip == "192.168.1.50"
    assert event.username == "root"
    assert event.status == "failure"

def test_csv_normalization():
    csv_str = "source_ip,destination_ip,destination_port,protocol,event_type,username,action,status\n10.0.0.5,10.0.0.1,443,tcp,auth,admin,login,failure"
    res = LogNormalizer.process_raw_payload("csv", csv_str)
    assert res.normalized_count == 1
    assert res.events[0].username == "admin"
    assert res.events[0].status == "failure"

def test_malformed_log_handling():
    res = LogNormalizer.process_raw_payload("json", "INVALID_NOT_JSON")
    assert res.failed_count == 1
    assert len(res.errors) > 0
