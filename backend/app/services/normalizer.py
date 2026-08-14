import re
import csv
import json
import io
from datetime import datetime
from typing import List, Dict, Any, Tuple
from app.schemas.events import StandardSecurityEvent, IngestionResponse

class LogNormalizer:
    """
    Normalizes heterogeneous raw security logs (JSON, CSV, Syslog, Auth logs, Firewall logs)
    into standardized StandardSecurityEvent objects.
    """

    @staticmethod
    def _parse_timestamp(val: Any) -> datetime:
        if isinstance(val, datetime):
            return val
        if isinstance(val, (int, float)):
            try:
                return datetime.utcfromtimestamp(val)
            except Exception:
                pass
        if isinstance(val, str):
            # Try ISO format
            try:
                return datetime.fromisoformat(val.replace("Z", "+00:00"))
            except Exception:
                pass
            # Try common datetime formats
            formats = [
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%b %d %H:%M:%S",
                "%d/%b/%Y:%H:%M:%S",
                "%Y/%m/%d %H:%M:%S"
            ]
            for fmt in formats:
                try:
                    dt = datetime.strptime(val.strip(), fmt)
                    if dt.year == 1900:  # If year missing like Syslog
                        dt = dt.replace(year=datetime.utcnow().year)
                    return dt
                except ValueError:
                    continue
        return datetime.utcnow()

    @classmethod
    def normalize_dict(cls, data: Dict[str, Any]) -> StandardSecurityEvent:
        """
        Normalizes a key-value dictionary into StandardSecurityEvent.
        """
        source_ip = (
            data.get("source_ip") or data.get("src_ip") or data.get("srcip") or 
            data.get("client_ip") or data.get("source") or "0.0.0.0"
        )
        destination_ip = (
            data.get("destination_ip") or data.get("dest_ip") or data.get("dstip") or 
            data.get("server_ip") or data.get("target_ip") or data.get("destination") or "0.0.0.0"
        )
        
        src_port = data.get("source_port") or data.get("src_port") or data.get("srcport")
        dst_port = data.get("destination_port") or data.get("dest_port") or data.get("dstport")
        
        try:
            src_port = int(src_port) if src_port is not None else None
        except (ValueError, TypeError):
            src_port = None

        try:
            dst_port = int(dst_port) if dst_port is not None else None
        except (ValueError, TypeError):
            dst_port = None

        protocol = str(data.get("protocol") or data.get("proto") or "TCP").upper()
        event_type = str(data.get("event_type") or data.get("category") or data.get("type") or "network")
        username = str(data.get("username") or data.get("user") or data.get("account") or "unknown")
        action = str(data.get("action") or data.get("event") or "access")
        status = str(data.get("status") or data.get("outcome") or data.get("result") or "success").lower()
        message = str(data.get("message") or data.get("msg") or data.get("log") or "")
        severity = str(data.get("severity") or "LOW").upper()
        timestamp = cls._parse_timestamp(data.get("timestamp") or data.get("time") or data.get("@timestamp"))

        # Preserve extra keys in metadata
        reserved_keys = {
            "id", "timestamp", "time", "@timestamp", "source_ip", "src_ip", "srcip", "client_ip", "source",
            "destination_ip", "dest_ip", "dstip", "server_ip", "target_ip", "destination",
            "source_port", "src_port", "srcport", "destination_port", "dest_port", "dstport",
            "protocol", "proto", "event_type", "category", "type", "username", "user", "account",
            "action", "event", "status", "outcome", "result", "message", "msg", "log", "severity"
        }
        metadata = {k: v for k, v in data.items() if k not in reserved_keys}

        return StandardSecurityEvent(
            timestamp=timestamp,
            source_ip=str(source_ip),
            destination_ip=str(destination_ip),
            source_port=src_port,
            destination_port=dst_port,
            protocol=protocol,
            event_type=event_type,
            username=username,
            action=action,
            status=status,
            message=message,
            severity=severity,
            metadata=metadata
        )

    @classmethod
    def parse_syslog(cls, line: str) -> StandardSecurityEvent:
        """
        Parses Syslog format strings (e.g., 'Feb 14 12:00:00 host sshd[123]: Failed password for root from 192.168.1.50 port 45210 ssh2')
        """
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, line)
        src_ip = ips[0] if len(ips) > 0 else "127.0.0.1"
        dst_ip = ips[1] if len(ips) > 1 else "10.0.0.1"

        port_match = re.search(r'port\s+(\d+)', line, re.IGNORECASE)
        dst_port = int(port_match.group(1)) if port_match else None

        user_match = re.search(r'for\s+(invalid user\s+)?([a-zA-Z0-9_\-\.]+)', line, re.IGNORECASE)
        username = user_match.group(2) if user_match else "unknown"

        status = "failure" if "failed" in line.lower() or "denied" in line.lower() or "error" in line.lower() else "success"
        action = "authentication" if "password" in line.lower() or "login" in line.lower() or "auth" in line.lower() else "syslog_event"

        return StandardSecurityEvent(
            source_ip=src_ip,
            destination_ip=dst_ip,
            destination_port=dst_port,
            protocol="SSH" if "ssh" in line.lower() else "TCP",
            event_type="authentication",
            username=username,
            action=action,
            status=status,
            message=line,
            severity="MEDIUM" if status == "failure" else "LOW"
        )

    @classmethod
    def parse_csv(cls, csv_text: str) -> List[StandardSecurityEvent]:
        events = []
        reader = csv.DictReader(io.StringIO(csv_text.strip()))
        for row in reader:
            events.append(cls.normalize_dict(row))
        return events

    @classmethod
    def process_raw_payload(cls, log_format: str, raw_data: Any) -> IngestionResponse:
        events: List[StandardSecurityEvent] = []
        errors: List[str] = []
        failed_count = 0

        fmt = log_format.lower()

        try:
            if fmt == "json":
                if isinstance(raw_data, str):
                    parsed = json.loads(raw_data)
                else:
                    parsed = raw_data

                if isinstance(parsed, list):
                    for idx, item in enumerate(parsed):
                        try:
                            events.append(cls.normalize_dict(item))
                        except Exception as e:
                            failed_count += 1
                            errors.append(f"Item #{idx} failed normalization: {str(e)}")
                elif isinstance(parsed, dict):
                    events.append(cls.normalize_dict(parsed))
                else:
                    failed_count += 1
                    errors.append("JSON payload must be an object or list of objects")

            elif fmt == "csv":
                if not isinstance(raw_data, str):
                    raw_data = str(raw_data)
                events.extend(cls.parse_csv(raw_data))

            elif fmt in ["syslog", "auth_log", "firewall_log"]:
                lines = raw_data.splitlines() if isinstance(raw_data, str) else [str(raw_data)]
                for idx, line in enumerate(lines):
                    if not line.strip():
                        continue
                    try:
                        events.append(cls.parse_syslog(line))
                    except Exception as e:
                        failed_count += 1
                        errors.append(f"Line #{idx+1} failed syslog parse: {str(e)}")

            else:
                # Default fallback: string/json inspection
                if isinstance(raw_data, dict):
                    events.append(cls.normalize_dict(raw_data))
                elif isinstance(raw_data, list):
                    for item in raw_data:
                        events.append(cls.normalize_dict(item))
                elif isinstance(raw_data, str):
                    events.append(cls.parse_syslog(raw_data))
                else:
                    failed_count += 1
                    errors.append(f"Unsupported format: {log_format}")

        except Exception as global_e:
            failed_count += 1
            errors.append(f"Global ingestion error: {str(global_e)}")

        return IngestionResponse(
            total_received=len(events) + failed_count,
            normalized_count=len(events),
            failed_count=failed_count,
            errors=errors,
            events=events
        )
