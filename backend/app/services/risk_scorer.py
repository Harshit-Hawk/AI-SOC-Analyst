from typing import List
from app.schemas.incidents import SecurityIncident, RiskScoreBreakdown, RiskFactor

class RiskScorer:
    """
    Transparent, multi-factor Risk Scoring Engine (0-100 score).
    Factors:
    1. Base Threat Severity (CRITICAL=40, HIGH=30, MEDIUM=20, LOW=10)
    2. Event Density & Frequency Volume (0 to 20 pts)
    3. Machine Learning Anomaly Score (0 to 20 pts)
    4. Affected Entity Criticality & User Role (0 to 10 pts)
    5. Detection Evidence Strength & Multi-Vector Match (0 to 10 pts)
    """

    @classmethod
    def calculate_risk(cls, incident: SecurityIncident) -> RiskScoreBreakdown:
        factors: List[RiskFactor] = []
        total_score = 0.0

        # 1. Base Severity Factor
        sev_map = {"CRITICAL": 40.0, "HIGH": 30.0, "MEDIUM": 20.0, "LOW": 10.0}
        base_sev_score = sev_map.get(incident.severity.upper(), 10.0)
        factors.append(RiskFactor(
            factor="Threat Severity",
            weight=0.40,
            contribution=base_sev_score,
            description=f"Incident evaluated with baseline {incident.severity.upper()} threat rating."
        ))
        total_score += base_sev_score

        # 2. Event Volume & Frequency Factor
        ev_count = len(incident.events)
        vol_score = min(20.0, ev_count * 1.5)
        factors.append(RiskFactor(
            factor="Event Frequency & Volume",
            weight=0.20,
            contribution=round(vol_score, 1),
            description=f"Correlated {ev_count} security events within attack window."
        ))
        total_score += vol_score

        # 3. ML Anomaly Score Factor
        ml_alerts = [a for a in incident.alerts if a.ml_details is not None]
        if ml_alerts:
            max_conf = max(a.ml_details.confidence for a in ml_alerts)
            ml_score = (max_conf / 100.0) * 20.0
            factors.append(RiskFactor(
                factor="ML Anomaly Confidence",
                weight=0.20,
                contribution=round(ml_score, 1),
                description=f"Isolation Forest ML engine assigned max anomaly confidence of {max_conf:.1f}%."
            ))
            total_score += ml_score
        else:
            factors.append(RiskFactor(
                factor="ML Anomaly Confidence",
                weight=0.20,
                contribution=5.0,
                description="Rule-based trigger only; baseline ML anomaly contribution applied."
            ))
            total_score += 5.0

        # 4. Sensitive Entity Criticality
        sensitive_users = {"root", "admin", "administrator", "system", "sudo"}
        has_sensitive = any(
            (e.username and e.username.lower() in sensitive_users) or 
            any(s.lower() in sensitive_users for s in incident.source_entities)
            for e in incident.events
        )
        entity_score = 10.0 if has_sensitive else 4.0
        factors.append(RiskFactor(
            factor="Entity Criticality",
            weight=0.10,
            contribution=entity_score,
            description="Privileged root/admin account involved." if has_sensitive else "Standard user/host entities involved."
        ))
        total_score += entity_score

        # 5. Evidence Strength & Multi-Vector Correlated Match
        num_alerts = len(incident.alerts)
        num_types = len(set(a.detection_type for a in incident.alerts))
        evidence_score = min(10.0, (num_alerts * 3.0) + (5.0 if num_types > 1 else 0.0))
        factors.append(RiskFactor(
            factor="Evidence & Multi-Vector Match",
            weight=0.10,
            contribution=round(evidence_score, 1),
            description=f"Supported by {num_alerts} distinct alert triggers across {num_types} detection layer(s)."
        ))
        total_score += evidence_score

        final_score = min(100.0, max(0.0, round(total_score, 1)))

        if final_score >= 76.0:
            risk_level = "CRITICAL"
        elif final_score >= 51.0:
            risk_level = "HIGH"
        elif final_score >= 26.0:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return RiskScoreBreakdown(
            total_score=final_score,
            risk_level=risk_level,
            factors=factors
        )
