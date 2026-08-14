from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid
from app.schemas.events import StandardSecurityEvent
from app.schemas.alerts import SecurityAlert

class MITREMapping(BaseModel):
    technique_id: str          # e.g., T1110
    technique_name: str        # e.g., Brute Force
    tactic: str               # e.g., Credential Access
    description: str
    reason: str

class RiskFactor(BaseModel):
    factor: str
    weight: float
    contribution: float
    description: str

class RiskScoreBreakdown(BaseModel):
    total_score: float         # 0 to 100
    risk_level: str            # LOW, MEDIUM, HIGH, CRITICAL
    factors: List[RiskFactor] = Field(default_factory=list)

class AIInvestigationResult(BaseModel):
    analysis_mode: str = Field(..., description="LIVE_LLM or RULE_BASED_FALLBACK")
    summary: str
    threat_type: str
    severity: str
    confidence: float          # 0 to 100
    evidence: List[str] = Field(default_factory=list)
    attack_explanation: str
    affected_entities: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)

class SecurityIncident(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    title: str
    description: str
    severity: str = Field(..., description="LOW, MEDIUM, HIGH, CRITICAL")
    status: str = Field(default="OPEN", description="OPEN, INVESTIGATING, MITIGATED, CLOSED")
    threat_category: str
    source_entities: List[str] = Field(default_factory=list)  # IPs, users
    target_entities: List[str] = Field(default_factory=list)  # Target IPs, services
    alerts: List[SecurityAlert] = Field(default_factory=list)
    events: List[StandardSecurityEvent] = Field(default_factory=list)
    mitre_mappings: List[MITREMapping] = Field(default_factory=list)
    risk_score: Optional[RiskScoreBreakdown] = None
    ai_investigation: Optional[AIInvestigationResult] = None

class BenchmarkMetrics(BaseModel):
    mode: str                  # Rule-Based, ML-Based, Hybrid
    total_samples: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    false_positive_rate: float
    detection_rate: float
    scenario_performance: Dict[str, Dict[str, float]] = Field(default_factory=dict)
