import numpy as np
from typing import List, Dict, Tuple, Optional
from collections import defaultdict
from sklearn.ensemble import IsolationForest
from app.schemas.events import StandardSecurityEvent
from app.schemas.alerts import SecurityAlert, MLAlertDetail
from app.config import settings

FEATURE_NAMES = [
    "failed_auth_count",
    "event_frequency",
    "unique_dst_ports",
    "unique_dst_ips",
    "privilege_user_flag",
    "high_severity_count",
    "avg_port_num"
]

class MLDetectionEngine:
    """
    Machine Learning Anomaly Detection Engine using Isolation Forest.
    Extracts statistical feature vectors per source IP / entity and detects multivariate statistical anomalies.
    """

    def __init__(self):
        self.model = IsolationForest(
            contamination=settings.ML_CONTAMINATION,
            random_state=settings.ML_RANDOM_STATE,
            n_estimators=100
        )
        self.is_trained = False
        self._bootstrap_model()

    def _bootstrap_model(self):
        """
        Pre-trains the model on synthetic benign event distributions so ML predictions are operational immediately.
        """
        np.random.seed(settings.ML_RANDOM_STATE)
        # Generate 200 normal behavioral feature vectors
        normal_samples = []
        for _ in range(200):
            failed_auth = np.random.poisson(lam=0.2)
            event_freq = np.random.normal(loc=2.0, scale=0.8)
            unique_ports = np.random.poisson(lam=1.5)
            unique_ips = np.random.poisson(lam=1.2)
            priv_flag = 1.0 if np.random.rand() < 0.05 else 0.0
            high_sev = 0.0
            avg_port = np.random.choice([80, 443, 22, 8080, 53])
            
            normal_samples.append([
                max(0, failed_auth),
                max(0.1, event_freq),
                max(1, unique_ports),
                max(1, unique_ips),
                priv_flag,
                high_sev,
                float(avg_port)
            ])

        X = np.array(normal_samples)
        self.model.fit(X)
        self.is_trained = True

    def extract_features(self, events: List[StandardSecurityEvent]) -> Dict[str, Tuple[List[float], List[StandardSecurityEvent]]]:
        """
        Groups events by source IP and extracts a numerical feature vector per source IP.
        Returns: {source_ip: (feature_vector, event_list)}
        """
        ip_groups: Dict[str, List[StandardSecurityEvent]] = defaultdict(list)
        for ev in events:
            ip_groups[ev.source_ip].append(ev)

        result = {}
        for src_ip, ev_list in ip_groups.items():
            failed_auth = sum(1 for e in ev_list if e.status.lower() in ["failure", "failed", "denied"])
            
            t_min = min(e.timestamp for e in ev_list)
            t_max = max(e.timestamp for e in ev_list)
            duration = max(1.0, (t_max - t_min).total_seconds())
            event_freq = len(ev_list) / duration

            unique_ports = len(set(e.destination_port for e in ev_list if e.destination_port is not None)) or 1
            unique_ips = len(set(e.destination_ip for e in ev_list if e.destination_ip)) or 1
            
            sensitive_users = set(u.lower() for u in settings.PRIVILEGE_ANOMALY_SENSITIVE_USERS)
            priv_flag = 1.0 if any(e.username and e.username.lower() in sensitive_users for e in ev_list) else 0.0
            
            high_sev = float(sum(1 for e in ev_list if e.severity in ["HIGH", "CRITICAL"]))
            
            valid_ports = [e.destination_port for e in ev_list if e.destination_port is not None]
            avg_port = float(np.mean(valid_ports)) if valid_ports else 80.0

            vec = [
                float(failed_auth),
                float(event_freq),
                float(unique_ports),
                float(unique_ips),
                priv_flag,
                high_sev,
                avg_port
            ]
            result[src_ip] = (vec, ev_list)

        return result

    def detect_anomalies(self, events: List[StandardSecurityEvent]) -> List[SecurityAlert]:
        alerts: List[SecurityAlert] = []
        if not events or not self.is_trained:
            return alerts

        features_by_ip = self.extract_features(events)
        if not features_by_ip:
            return alerts

        ips = list(features_by_ip.keys())
        X = np.array([features_by_ip[ip][0] for ip in ips])

        # Predict anomaly labels (-1 = anomaly, 1 = normal)
        predictions = self.model.predict(X)
        # Decision function raw anomaly scores (lower/more negative = more anomalous)
        raw_scores = self.model.decision_function(X)

        for i, ip in enumerate(ips):
            is_anomaly = predictions[i] == -1
            raw_score = float(raw_scores[i])
            vec, ev_list = features_by_ip[ip]

            # Convert raw score to 0 - 100 confidence rating
            # Decision function for anomaly is negative (e.g. -0.2 to -0.01)
            # Map score to percentage: -0.25 -> ~95%, 0.0 -> ~50%, 0.2 -> ~10%
            confidence = float(np.clip((0.15 - raw_score) * 200, 50.0, 99.0)) if is_anomaly else float(np.clip((0.15 - raw_score) * 100, 0.0, 49.0))

            if is_anomaly and confidence >= 60.0:
                # Calculate feature contributions
                feature_contribs = {}
                for idx, fname in enumerate(FEATURE_NAMES):
                    val = vec[idx]
                    feature_contribs[fname] = round(val, 2)

                severity = "CRITICAL" if confidence >= 85.0 else ("HIGH" if confidence >= 75.0 else "MEDIUM")

                alerts.append(SecurityAlert(
                    title=f"ML Anomaly Detected from {ip} (Confidence: {confidence:.1f}%)",
                    description=f"Isolation Forest ML Engine detected statistical behavior anomaly from source IP {ip}. Multivariate feature score deviates from baseline.",
                    detection_type="ML",
                    severity=severity,
                    category="Anomaly",
                    source_ip=ip,
                    destination_ip=ev_list[0].destination_ip if ev_list else None,
                    triggering_event_ids=[e.id for e in ev_list],
                    event_count=len(ev_list),
                    ml_details=MLAlertDetail(
                        model_name="IsolationForest",
                        anomaly_score=round(raw_score, 4),
                        confidence=round(confidence, 1),
                        top_feature_contributions=feature_contribs
                    )
                ))

        return alerts
