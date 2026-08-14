from pydantic import BaseModel, Field, field_validator
from typing import Optional, Dict, Any, List
from datetime import datetime
import uuid

class StandardSecurityEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_ip: str = Field(..., description="Source IPv4/IPv6 address or hostname")
    destination_ip: str = Field(..., description="Destination IPv4/IPv6 address or hostname")
    source_port: Optional[int] = Field(default=None, ge=0, le=65535)
    destination_port: Optional[int] = Field(default=None, ge=0, le=65535)
    protocol: str = Field(default="TCP", description="Network protocol (TCP, UDP, ICMP, HTTP, SSH, etc.)")
    event_type: str = Field(..., description="Category of event (authentication, firewall, process, network)")
    username: Optional[str] = Field(default="unknown", description="User or principal associated with event")
    action: str = Field(..., description="Action taken (login, connect, drop, execute, access)")
    status: str = Field(..., description="Status outcome (success, failure, denied, allowed)")
    message: str = Field(default="", description="Log entry descriptive message")
    severity: str = Field(default="LOW", description="LOW, MEDIUM, HIGH, CRITICAL")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Arbitrary additional key-value telemetry")

    @field_validator('severity')

    def validate_severity(cls, v):
        allowed = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        upper_v = v.upper()
        if upper_v not in allowed:
            return "LOW"
        return upper_v

    @field_validator('protocol')

    def validate_protocol(cls, v):
        return v.upper()

class RawLogPayload(BaseModel):
    format: str = Field(default="json", description="Log format: json, csv, syslog, auth_log, firewall_log")
    raw_data: Any = Field(..., description="Raw string log or JSON object/list")

class IngestionResponse(BaseModel):
    total_received: int
    normalized_count: int
    failed_count: int
    errors: List[str] = Field(default_factory=list)
    events: List[StandardSecurityEvent] = Field(default_factory=list)
