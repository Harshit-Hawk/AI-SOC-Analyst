from typing import List, Dict, Tuple
from collections import defaultdict
from datetime import datetime, timedelta
from app.schemas.events import StandardSecurityEvent
from app.schemas.alerts import SecurityAlert, RuleAlertDetail
from app.config import settings

class RuleDetectionEngine:
    """
    Deterministic rule-based threat detection engine.
    Detects:
    1. Brute Force (High frequency failed authentications from same IP or user)
    2. Port Scanning (Single IP connecting to high number of distinct destination ports)
    3. Denial of Service (Extremely high request/event rate from an IP)
    4. Credential / Privilege Anomaly (Unusual root/admin logins, sensitive execution)
    """

    def __init__(self):
        self.brute_force_failed_threshold = settings.BRUTE_FORCE_FAILED_THRESHOLD
        self.brute_force_window = timedelta(seconds=settings.BRUTE_FORCE_WINDOW_SECONDS)
        
        self.port_scan_threshold = settings.PORT_SCAN_UNIQUE_PORTS_THRESHOLD
        self.port_scan_window = timedelta(seconds=settings.PORT_SCAN_WINDOW_SECONDS)
        
        self.dos_threshold = settings.DOS_EVENT_COUNT_THRESHOLD
        self.dos_window = timedelta(seconds=settings.DOS_WINDOW_SECONDS)
        
        self.sensitive_users = set(u.lower() for u in settings.PRIVILEGE_ANOMALY_SENSITIVE_USERS)

    def analyze_events(self, events: List[StandardSecurityEvent]) -> List[SecurityAlert]:
        alerts: List[SecurityAlert] = []
        if not events:
            return alerts

        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: e.timestamp)

        # 1. Check Brute Force
        alerts.extend(self._detect_brute_force(sorted_events))

        # 2. Check Port Scan
        alerts.extend(self._detect_port_scan(sorted_events))

        # 3. Check DoS
        alerts.extend(self._detect_dos(sorted_events))

        # 4. Check Privilege Anomaly
        alerts.extend(self._detect_privilege_anomaly(sorted_events))

        return alerts

    def _detect_brute_force(self, events: List[StandardSecurityEvent]) -> List[SecurityAlert]:
        alerts = []
        # Group failed logins by (source_ip, username)
        failed_logins: Dict[Tuple[str, str], List[StandardSecurityEvent]] = defaultdict(list)

        for event in events:
            if (event.event_type.lower() in ["authentication", "auth", "login"] or "login" in event.action.lower()) and event.status.lower() in ["failure", "failed", "denied"]:
                key = (event.source_ip, event.username)
                failed_logins[key].append(event)

        for (src_ip, username), ev_list in failed_logins.items():
            if len(ev_list) >= self.brute_force_failed_threshold:
                # Calculate time window span
                window_duration = (ev_list[-1].timestamp - ev_list[0].timestamp).total_seconds()
                if window_duration <= settings.BRUTE_FORCE_WINDOW_SECONDS:
                    alerts.append(SecurityAlert(
                        title=f"Brute Force Authentication Attempt detected from {src_ip}",
                        description=f"Detected {len(ev_list)} failed login attempts for account '{username}' within {int(window_duration)}s.",
                        detection_type="RULE",
                        severity="HIGH" if len(ev_list) < 15 else "CRITICAL",
                        category="Brute Force",
                        source_ip=src_ip,
                        username=username,
                        triggering_event_ids=[e.id for e in ev_list],
                        event_count=len(ev_list),
                        rule_details=RuleAlertDetail(
                            rule_name="RULE_BRUTE_FORCE_01",
                            rule_id="RULE-BF-101",
                            condition_matched=f"failed_logins >= {self.brute_force_failed_threshold} within window",
                            threshold_value=self.brute_force_failed_threshold,
                            actual_value=len(ev_list)
                        ),
                        mitre_technique_id="T1110",
                        mitre_technique_name="Brute Force"
                    ))

        return alerts

    def _detect_port_scan(self, events: List[StandardSecurityEvent]) -> List[SecurityAlert]:
        alerts = []
        # Group distinct destination ports by source_ip
        ip_ports: Dict[str, List[StandardSecurityEvent]] = defaultdict(list)

        for event in events:
            if event.destination_port is not None:
                ip_ports[event.source_ip].append(event)

        for src_ip, ev_list in ip_ports.items():
            unique_ports = set(e.destination_port for e in ev_list if e.destination_port is not None)
            if len(unique_ports) >= self.port_scan_threshold:
                window_duration = (ev_list[-1].timestamp - ev_list[0].timestamp).total_seconds()
                if window_duration <= settings.PORT_SCAN_WINDOW_SECONDS:
                    alerts.append(SecurityAlert(
                        title=f"Reconnaissance: Port Scanning detected from {src_ip}",
                        description=f"Source IP {src_ip} probed {len(unique_ports)} distinct destination ports within {int(window_duration)}s.",
                        detection_type="RULE",
                        severity="MEDIUM" if len(unique_ports) < 50 else "HIGH",
                        category="Port Scan",
                        source_ip=src_ip,
                        destination_ip=ev_list[0].destination_ip,
                        triggering_event_ids=[e.id for e in ev_list],
                        event_count=len(ev_list),
                        rule_details=RuleAlertDetail(
                            rule_name="RULE_PORT_SCAN_01",
                            rule_id="RULE-PS-201",
                            condition_matched=f"unique_destination_ports >= {self.port_scan_threshold} within window",
                            threshold_value=self.port_scan_threshold,
                            actual_value=len(unique_ports)
                        ),
                        mitre_technique_id="T1046",
                        mitre_technique_name="Network Service Discovery"
                    ))

        return alerts

    def _detect_dos(self, events: List[StandardSecurityEvent]) -> List[SecurityAlert]:
        alerts = []
        # Group high frequency requests by source_ip
        ip_requests: Dict[str, List[StandardSecurityEvent]] = defaultdict(list)

        for event in events:
            ip_requests[event.source_ip].append(event)

        for src_ip, ev_list in ip_requests.items():
            if len(ev_list) >= self.dos_threshold:
                window_duration = max(1.0, (ev_list[-1].timestamp - ev_list[0].timestamp).total_seconds())
                if window_duration <= settings.DOS_WINDOW_SECONDS:
                    req_rate = len(ev_list) / window_duration
                    alerts.append(SecurityAlert(
                        title=f"Denial of Service (DoS) Traffic Flood from {src_ip}",
                        description=f"High density traffic flood detected from {src_ip}: {len(ev_list)} events generated at {req_rate:.1f} req/s.",
                        detection_type="RULE",
                        severity="HIGH" if len(ev_list) < 100 else "CRITICAL",
                        category="DoS",
                        source_ip=src_ip,
                        destination_ip=ev_list[0].destination_ip,
                        triggering_event_ids=[e.id for e in ev_list],
                        event_count=len(ev_list),
                        rule_details=RuleAlertDetail(
                            rule_name="RULE_DOS_FLOOD_01",
                            rule_id="RULE-DOS-301",
                            condition_matched=f"event_volume >= {self.dos_threshold} within window",
                            threshold_value=self.dos_threshold,
                            actual_value=len(ev_list)
                        ),
                        mitre_technique_id="T1499",
                        mitre_technique_name="Endpoint Denial of Service"
                    ))

        return alerts

    def _detect_privilege_anomaly(self, events: List[StandardSecurityEvent]) -> List[SecurityAlert]:
        alerts = []
        for event in events:
            is_sensitive_user = event.username and event.username.lower() in self.sensitive_users
            is_privileged_action = any(kw in event.action.lower() for kw in ["sudo", "privilege", "escalate", "chmod", "admin_login", "token_impersonation"])
            is_unusual_status = event.status.lower() in ["success", "allowed"] and event.severity in ["HIGH", "CRITICAL"]

            if is_sensitive_user and (is_privileged_action or is_unusual_status or event.message.find("suspicious") >= 0):
                alerts.append(SecurityAlert(
                    title=f"Privilege / Account Anomaly for user '{event.username}' from {event.source_ip}",
                    description=f"Suspicious privileged activity detected for sensitive account '{event.username}' (Action: {event.action}, Status: {event.status}).",
                    detection_type="RULE",
                    severity="HIGH",
                    category="Privilege Anomaly",
                    source_ip=event.source_ip,
                    destination_ip=event.destination_ip,
                    username=event.username,
                    triggering_event_ids=[event.id],
                    event_count=1,
                    rule_details=RuleAlertDetail(
                        rule_name="RULE_PRIVILEGE_ANOMALY_01",
                        rule_id="RULE-PA-401",
                        condition_matched="privileged user performing elevated / unusual action",
                        threshold_value="sensitive_user_policy",
                        actual_value=f"user={event.username}, action={event.action}"
                    ),
                    mitre_technique_id="T1078",
                    mitre_technique_name="Valid Accounts"
                ))

        return alerts
