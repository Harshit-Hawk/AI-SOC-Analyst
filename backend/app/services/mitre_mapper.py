from typing import List
from app.schemas.incidents import MITREMapping, SecurityIncident

MITRE_KNOWLEDGE_BASE = {
    "Brute Force": MITREMapping(
        technique_id="T1110",
        technique_name="Brute Force",
        tactic="Credential Access",
        description="Adversaries may use brute force techniques to attempt access to valid accounts when passwords or credentials are unknown.",
        reason="Repeated authentication failures detected against accounts within a short time frame."
    ),
    "Port Scan": MITREMapping(
        technique_id="T1046",
        technique_name="Network Service Discovery",
        tactic="Discovery",
        description="Adversaries may attempt to get a listing of services running on remote hosts to discover potential vulnerabilities.",
        reason="Multiple distinct destination ports probed sequentially or randomly from a single source host."
    ),
    "DoS": MITREMapping(
        technique_id="T1499",
        technique_name="Endpoint Denial of Service",
        tactic="Impact",
        description="Adversaries may perform Endpoint DoS attacks to degrade or disrupt the availability of services.",
        reason="Excessive request rates and event frequency exceeding volumetric capacity thresholds."
    ),
    "Privilege Anomaly": MITREMapping(
        technique_id="T1078",
        technique_name="Valid Accounts",
        tactic="Defense Evasion, Persistence, Privilege Escalation, Initial Access",
        description="Adversaries may obtain and abuse credentials of existing valid accounts to gain access or elevate privileges.",
        reason="Unusual access patterns or unauthorized action executed by sensitive root/admin accounts."
    ),
    "Exfiltration": MITREMapping(
        technique_id="T1041",
        technique_name="Exfiltration Over C2 Channel",
        tactic="Exfiltration",
        description="Adversaries may steal data by transferring it over an existing command and control channel.",
        reason="Unusually large outbound data transfer volumes detected to untrusted external IP addresses."
    )
}

class MITREMapper:
    """
    Maps threat categories and alert parameters to MITRE ATT&CK framework techniques.
    """

    @classmethod
    def map_incident(cls, incident: SecurityIncident) -> List[MITREMapping]:
        mappings: List[MITREMapping] = []
        categories = set(a.category for a in incident.alerts)
        if incident.threat_category:
            categories.add(incident.threat_category)

        for cat in categories:
            if cat in MITRE_KNOWLEDGE_BASE:
                mappings.append(MITRE_KNOWLEDGE_BASE[cat])

        # Default fallback mapping if category not explicitly mapped
        if not mappings:
            mappings.append(MITREMapping(
                technique_id="T1204",
                technique_name="User Execution",
                tactic="Execution",
                description="Adversaries may rely on actions by a user to execute malicious code or trigger events.",
                reason="Unclassified security event sequence observed across network entities."
            ))

        return mappings
