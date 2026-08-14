from typing import List, Dict, Tuple, Any
from app.schemas.events import StandardSecurityEvent
from app.schemas.incidents import BenchmarkMetrics
from app.services.detection import RuleDetectionEngine
from app.services.ml_detector import MLDetectionEngine
from app.simulator.attack_scenarios import AttackSimulator
from datetime import datetime, timedelta

class BenchmarkEvaluator:
    """
    Evaluates threat detection performance across Rule-based, ML-based, and Hybrid detection strategies.
    Uses controlled synthetic security scenarios (Benign + Malicious samples).
    """

    def __init__(self):
        self.rule_engine = RuleDetectionEngine()
        self.ml_engine = MLDetectionEngine()

    def generate_benign_traffic(self, count: int = 40) -> List[StandardSecurityEvent]:
        events = []
        now = datetime.utcnow()
        for i in range(count):
            events.append(StandardSecurityEvent(
                timestamp=now - timedelta(seconds=(count - i) * 10),
                source_ip=f"192.168.1.{(i % 5) + 10}",
                destination_ip="10.0.0.1",
                source_port=30000 + i,
                destination_port=80 if i % 2 == 0 else 443,
                protocol="TCP",
                event_type="network",
                username=f"user{(i%3)+1}",
                action="connect",
                status="success",
                message="Normal HTTP session telemetry",
                severity="LOW"
            ))
        return events

    def evaluate_all(self) -> Dict[str, BenchmarkMetrics]:
        # Build test dataset
        benign_events = self.generate_benign_traffic(40)
        bf_events = AttackSimulator.generate_brute_force(10, src_ip="192.168.1.199")
        ps_events = AttackSimulator.generate_port_scan(20, src_ip="10.0.0.77")
        dos_events = AttackSimulator.generate_dos(55, src_ip="172.16.0.99")
        pa_events = AttackSimulator.generate_privilege_anomaly(src_ip="192.168.1.250")

        scenarios = {
            "Benign Traffic": (benign_events, False),
            "Brute Force Attack": (bf_events, True),
            "Port Scan Recon": (ps_events, True),
            "DoS Traffic Surge": (dos_events, True),
            "Privilege Escalation": (pa_events, True),
        }

        results = {}
        for mode in ["Rule-Based", "ML-Based", "Hybrid"]:
            results[mode] = self._evaluate_mode(mode, scenarios)

        return results

    def _evaluate_mode(self, mode: str, scenarios: Dict[str, Tuple[List[StandardSecurityEvent], bool]]) -> BenchmarkMetrics:
        tp, fp, tn, fn = 0, 0, 0, 0
        scenario_perf = {}

        for sc_name, (events, is_malicious) in scenarios.items():
            rule_alerts = self.rule_engine.analyze_events(events) if mode in ["Rule-Based", "Hybrid"] else []
            ml_alerts = self.ml_engine.detect_anomalies(events) if mode in ["ML-Based", "Hybrid"] else []

            combined_alerts = rule_alerts + ml_alerts
            detected_positive = len(combined_alerts) > 0

            if is_malicious:
                if detected_positive:
                    tp += 1
                    sc_detected = 1.0
                else:
                    fn += 1
                    sc_detected = 0.0
            else:
                if detected_positive:
                    fp += 1
                    sc_detected = 0.0  # False alarm
                else:
                    tn += 1
                    sc_detected = 1.0

            scenario_perf[sc_name] = {
                "detected": sc_detected,
                "alerts_generated": float(len(combined_alerts))
            }

        total = tp + fp + tn + fn
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / total if total > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        detection_rate = recall

        return BenchmarkMetrics(
            mode=mode,
            total_samples=total,
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            accuracy=round(accuracy, 4),
            false_positive_rate=round(fpr, 4),
            detection_rate=round(detection_rate, 4),
            scenario_performance=scenario_perf
        )
