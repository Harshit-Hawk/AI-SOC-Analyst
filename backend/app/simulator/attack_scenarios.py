from datetime import datetime, timedelta
from typing import List, Dict, Any
from app.schemas.events import StandardSecurityEvent

class AttackSimulator:
    """
    Safe synthetic attack simulator.
    Generates realistic security telemetry logs for demonstration & evaluation.
    Feeds events directly into the PRODUCTION detection pipeline.
    """

    @staticmethod
    def generate_brute_force(count: int = 12, src_ip: str = "192.168.1.105", target_user: str = "root") -> List[StandardSecurityEvent]:
        events = []
        now = datetime.utcnow()
        for i in range(count):
            events.append(StandardSecurityEvent(
                timestamp=now - timedelta(seconds=(count - i) * 5),
                source_ip=src_ip,
                destination_ip="10.0.4.15",
                source_port=45000 + i,
                destination_port=22,
                protocol="SSH",
                event_type="authentication",
                username=target_user,
                action="login",
                status="failure",
                message=f"Failed SSH password for {target_user} from {src_ip} port {45000+i} ssh2",
                severity="MEDIUM"
            ))
        return events

    @staticmethod
    def generate_port_scan(num_ports: int = 25, src_ip: str = "10.0.0.88", target_ip: str = "192.168.1.200") -> List[StandardSecurityEvent]:
        events = []
        now = datetime.utcnow()
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 9000, 9200, 27017]
        for i in range(min(num_ports, len(ports))):
            events.append(StandardSecurityEvent(
                timestamp=now - timedelta(seconds=(num_ports - i) * 2),
                source_ip=src_ip,
                destination_ip=target_ip,
                source_port=50000 + i,
                destination_port=ports[i],
                protocol="TCP",
                event_type="network",
                username="unknown",
                action="connect",
                status="denied",
                message=f"TCP SYN probe from {src_ip}:{50000+i} to {target_ip}:{ports[i]} (Connection refused)",
                severity="LOW"
            ))
        return events

    @staticmethod
    def generate_dos(count: int = 65, src_ip: str = "172.16.0.42", target_ip: str = "10.0.0.10") -> List[StandardSecurityEvent]:
        events = []
        now = datetime.utcnow()
        for i in range(count):
            events.append(StandardSecurityEvent(
                timestamp=now - timedelta(milliseconds=(count - i) * 400),
                source_ip=src_ip,
                destination_ip=target_ip,
                source_port=60000 + (i % 1000),
                destination_port=80,
                protocol="HTTP",
                event_type="network",
                username="anonymous",
                action="access",
                status="allowed",
                message=f"HTTP GET /api/v1/resource flood from {src_ip}",
                severity="MEDIUM"
            ))
        return events

    @staticmethod
    def generate_privilege_anomaly(src_ip: str = "192.168.1.55", target_user: str = "root") -> List[StandardSecurityEvent]:
        events = []
        now = datetime.utcnow()
        events.append(StandardSecurityEvent(
            timestamp=now - timedelta(seconds=120),
            source_ip=src_ip,
            destination_ip="10.0.0.5",
            destination_port=22,
            protocol="SSH",
            event_type="authentication",
            username=target_user,
            action="admin_login",
            status="success",
            message=f"Accepted publickey for root from {src_ip} port 52140 ssh2: RSA SHA256:unusual_fingerprint",
            severity="HIGH"
        ))
        events.append(StandardSecurityEvent(
            timestamp=now - timedelta(seconds=60),
            source_ip=src_ip,
            destination_ip="10.0.0.5",
            protocol="PROCESS",
            event_type="process",
            username=target_user,
            action="sudo_escalate",
            status="allowed",
            message=f"COMMAND=/bin/bash ; USER=root ; PWD=/etc/shadow ; privilege escalation detected",
            severity="CRITICAL"
        ))
        return events

    @classmethod
    def get_scenario_events(cls, scenario_name: str) -> List[StandardSecurityEvent]:
        name = scenario_name.lower().replace("-", "_").replace(" ", "_")
        if "brute" in name:
            return cls.generate_brute_force()
        elif "scan" in name or "port" in name:
            return cls.generate_port_scan()
        elif "dos" in name:
            return cls.generate_dos()
        elif "privilege" in name or "credential" in name or "anomaly" in name:
            return cls.generate_privilege_anomaly()
        else:
            return cls.generate_brute_force()
