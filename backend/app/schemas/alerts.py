from pydantic import BaseModel, Field, ConfigDict
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid

class RuleAlertDetail(BaseModel):
    rule_name: str
    rule_id: str
    condition_matched: str
    threshold_value: Any
    actual_value: Any

class MLAlertDetail(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    model_name: str = "IsolationForest"
    anomaly_score: float  # Score from -1 to 1 or 0 to 100
    confidence: float     # 0 to 100 percentage confidence
    top_feature_contributions: Dict[str, float] = Field(default_factory=dict)

class SecurityAlert(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    title: str
    description: str
    detection_type: str = Field(..., description="RULE, ML, or HYBRID")
    severity: str = Field(..., description="LOW, MEDIUM, HIGH, CRITICAL")
    category: str = Field(..., description="Brute Force, Port Scan, DoS, Privilege Anomaly, Anomaly")
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    triggering_event_ids: List[str] = Field(default_factory=list)
    event_count: int = 1
    rule_details: Optional[RuleAlertDetail] = None
    ml_details: Optional[MLAlertDetail] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
