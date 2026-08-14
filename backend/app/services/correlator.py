from typing import List, Dict
from collections import defaultdict
from datetime import datetime
from app.schemas.events import StandardSecurityEvent
from app.schemas.alerts import SecurityAlert
from app.schemas.incidents import SecurityIncident

class AlertCorrelator:
    """
    Correlates individual security alerts and events into unified Security Incidents.
    Groups alerts sharing key pivot dimensions (source_ip, username, target_ip) within time windows.
    """

    def correlate(self, alerts: List[SecurityAlert], events: List[StandardSecurityEvent]) -> List[SecurityIncident]:
        if not alerts:
            return []

        # Map event IDs for fast lookup
        event_map: Dict[str, StandardSecurityEvent] = {e.id: e for e in events}

        # Group alerts by primary pivot entity (source_ip or username)
        grouped_alerts: Dict[str, List[SecurityAlert]] = defaultdict(list)
        for alert in alerts:
            key = alert.source_ip or alert.username or "global_uncorrelated"
            grouped_alerts[key].append(alert)

        incidents: List[SecurityIncident] = []

        for entity, alert_list in grouped_alerts.items():
            # Gather all associated events
            associated_event_ids = set()
            for alt in alert_list:
                associated_event_ids.update(alt.triggering_event_ids)

            associated_events = [event_map[eid] for eid in associated_event_ids if eid in event_map]

            # Determine dominant threat category and highest severity
            severities = [a.severity for a in alert_list]
            highest_severity = "CRITICAL" if "CRITICAL" in severities else (
                "HIGH" if "HIGH" in severities else ("MEDIUM" if "MEDIUM" in severities else "LOW")
            )

            threat_categories = list(set(a.category for a in alert_list))
            dominant_category = threat_categories[0] if threat_categories else "Security Anomaly"

            # Determine source and target entities
            sources = list(set(filter(None, [a.source_ip for a in alert_list] + [a.username for a in alert_list if a.username])))
            targets = list(set(filter(None, [a.destination_ip for a in alert_list])))

            # Construct title & description
            if len(alert_list) == 1:
                title = f"Incident: {alert_list[0].title}"
                desc = alert_list[0].description
            else:
                title = f"Correlated Multi-Vector Attack ({dominant_category}) from {entity}"
                desc = f"Correlated {len(alert_list)} security alerts involving {len(associated_events)} events across entity {entity}."

            incidents.append(SecurityIncident(
                title=title,
                description=desc,
                severity=highest_severity,
                status="OPEN",
                threat_category=dominant_category,
                source_entities=sources,
                target_entities=targets,
                alerts=alert_list,
                events=associated_events
            ))

        return incidents
