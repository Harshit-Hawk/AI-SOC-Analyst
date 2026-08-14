import json
import httpx
from typing import Optional, Dict, Any, List
from app.schemas.incidents import SecurityIncident, AIInvestigationResult
from app.config import settings

class AISOCAnalystAgent:
    """
    AI SOC Investigation Agent.
    Converts security incident context (Triggering Alerts, Events, Timeline, ML Score, MITRE Context)
    into structured SOC investigation findings, attack explanations, evidence lists, and remediation steps.
    
    Supports:
    - LIVE_LLM mode (when LLM_API_KEY is supplied)
    - RULE_BASED_FALLBACK mode (deterministic SOC analyst reasoning when offline or key missing)
    """

    def __init__(self):
        self.api_key = settings.LLM_API_KEY
        self.provider = settings.LLM_PROVIDER.lower()
        self.model = settings.LLM_MODEL

    def build_context(self, incident: SecurityIncident) -> Dict[str, Any]:
        """
        Assembles rich, structured context payload for AI investigation.
        """
        events_summary = []
        for e in incident.events[:15]:  # Top 15 events
            events_summary.append({
                "timestamp": e.timestamp.isoformat(),
                "src": f"{e.source_ip}:{e.source_port or ''}",
                "dst": f"{e.destination_ip}:{e.destination_port or ''}",
                "user": e.username,
                "action": e.action,
                "status": e.status,
                "message": e.message
            })

        alerts_summary = []
        for a in incident.alerts:
            alt_dict = {
                "title": a.title,
                "detection_type": a.detection_type,
                "severity": a.severity,
                "category": a.category
            }
            if a.rule_details:
                alt_dict["rule"] = a.rule_details.dict()
            if a.ml_details:
                alt_dict["ml"] = a.ml_details.dict()
            alerts_summary.append(alt_dict)

        mitre_summary = [m.dict() for m in incident.mitre_mappings]
        risk_score = incident.risk_score.total_score if incident.risk_score else None

        return {
            "incident_id": incident.id,
            "title": incident.title,
            "threat_category": incident.threat_category,
            "severity": incident.severity,
            "sources": incident.source_entities,
            "targets": incident.target_entities,
            "risk_score": risk_score,
            "alerts": alerts_summary,
            "events_sample": events_summary,
            "mitre_mappings": mitre_summary
        }

    async def investigate(self, incident: SecurityIncident) -> AIInvestigationResult:
        context = self.build_context(incident)

        if self.api_key and len(self.api_key.strip()) > 5:
            try:
                result = await self._call_live_llm(context)
                if result:
                    return result
            except Exception as e:
                # Log or handle exception gracefully and fall through to fallback mode
                pass

        # Use transparent deterministic fallback SOC agent reasoning
        return self._generate_rule_fallback(incident, context)

    async def _call_live_llm(self, context: Dict[str, Any]) -> Optional[AIInvestigationResult]:
        prompt = f"""
You are an expert Senior Security Operations Center (SOC) Analyst investigating a security incident.
Analyze the following structured incident telemetry context and return ONLY a valid JSON object matching this schema:

{{
  "summary": "Brief 1-2 sentence executive summary of the incident",
  "threat_type": "Classification of the threat (e.g. Brute Force, Port Scanning, DoS, Privilege Escalation)",
  "severity": "LOW, MEDIUM, HIGH, or CRITICAL",
  "confidence": 95.0,
  "evidence": ["Bullet point list of concrete confirmed facts from the events"],
  "attack_explanation": "Technical step-by-step description of what occurred based strictly on the provided telemetry",
  "affected_entities": ["List of affected IPs, hostnames, or usernames"],
  "mitre_techniques": ["List of MITRE IDs and names e.g. T1110 - Brute Force"],
  "recommended_actions": ["Immediate containment and remediation steps"]
}}

RULES:
- Do NOT invent or fabricate evidence that is not in the context.
- Distinguish clearly between confirmed facts and likelihood.

INCIDENT TELEMETRY CONTEXT:
{json.dumps(context, indent=2)}
"""
        async with httpx.AsyncClient(timeout=15.0) as client:
            if self.provider == "google":
                # Google Gemini API
                url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent?key={self.api_key}"
                resp = await client.post(url, json={
                    "contents": [{"parts": [{"text": prompt}]}]
                })
                if resp.status_code == 200:
                    data = resp.json()
                    raw_text = data['candidates'][0]['content']['parts'][0]['text']
                    return self._parse_json_result(raw_text, "LIVE_LLM")

            elif self.provider in ["openai", "groq", "openrouter"]:
                # OpenAI-compatible API
                base_url = "https://api.openai.com/v1/chat/completions"
                if self.provider == "groq":
                    base_url = "https://api.groq.com/openai/v1/chat/completions"
                elif self.provider == "openrouter":
                    base_url = "https://openrouter.ai/api/v1/chat/completions"

                resp = await client.post(base_url, headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                }, json={
                    "model": self.model if self.provider != "openai" else "gpt-4o-mini",
                    "messages": [{"role": "user", "content": prompt}],
                    "temperature": 0.2
                })
                if resp.status_code == 200:
                    data = resp.json()
                    raw_text = data['choices'][0]['message']['content']
                    return self._parse_json_result(raw_text, "LIVE_LLM")

        return None

    def _parse_json_result(self, raw_text: str, mode: str) -> Optional[AIInvestigationResult]:
        try:
            # Strip markdown ```json codeblocks if present
            cleaned = raw_text.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.split("\n", 1)[1]
                if cleaned.endswith("```"):
                    cleaned = cleaned.rsplit("```", 1)[0]
            
            parsed = json.loads(cleaned.strip())
            return AIInvestigationResult(
                analysis_mode=mode,
                summary=parsed.get("summary", ""),
                threat_type=parsed.get("threat_type", "Security Incident"),
                severity=parsed.get("severity", "MEDIUM"),
                confidence=float(parsed.get("confidence", 85.0)),
                evidence=parsed.get("evidence", []),
                attack_explanation=parsed.get("attack_explanation", ""),
                affected_entities=parsed.get("affected_entities", []),
                mitre_techniques=parsed.get("mitre_techniques", []),
                recommended_actions=parsed.get("recommended_actions", [])
            )
        except Exception:
            return None

    def _generate_rule_fallback(self, incident: SecurityIncident, context: Dict[str, Any]) -> AIInvestigationResult:
        """
        Deterministic Rule-Based SOC Analyst Reasoning fallback engine.
        Executed when no LLM key is provided or external API call fails.
        """
        cat = incident.threat_category.lower()
        ev_count = len(incident.events)
        sources = ", ".join(incident.source_entities) or "Unknown Source"
        targets = ", ".join(incident.target_entities) or "Unknown Target"

        evidence = [
            f"Observed {ev_count} security telemetry log entries associated with entity {sources}.",
            f"Detection triggered by {len(incident.alerts)} distinct alert signature(s)."
        ]

        if incident.events:
            first_time = incident.events[0].timestamp.strftime("%H:%M:%S UTC")
            last_time = incident.events[-1].timestamp.strftime("%H:%M:%S UTC")
            evidence.append(f"Attack activity window spanned from {first_time} to {last_time}.")

        for a in incident.alerts:
            if a.rule_details:
                evidence.append(f"Rule match: {a.rule_details.rule_name} ({a.rule_details.condition_matched}).")
            if a.ml_details:
                evidence.append(f"ML Isolation Forest anomaly detected with confidence {a.ml_details.confidence:.1f}%.")

        if "brute" in cat:
            threat_type = "Brute Force Authentication Attack"
            summary = f"Detected high-volume authentication failure burst originating from {sources} targeting account/host systems."
            explanation = f"An attacker at IP address {sources} conducted automated password guessing / dictionary attack against system authentication services. {ev_count} failed login attempts were registered before detection rules triggered."
            mitre_techs = ["T1110 - Brute Force", "T1078 - Valid Accounts"]
            remediations = [
                f"Immediately block incoming traffic from source IP {sources} at perimeter firewall.",
                "Enforce mandatory account lockout policies after 5 failed authentication attempts.",
                "Require Multi-Factor Authentication (MFA) across all remote access services.",
                "Audit target account credentials for potential compromise."
            ]

        elif "scan" in cat:
            threat_type = "Network Reconnaissance / Service Discovery"
            summary = f"Identified active port scanning activity from host {sources} probing network target {targets}."
            explanation = f"Reconnaissance scanning detected: Source {sources} systematically probed multiple destination network ports on {targets} to identify open services and potential vulnerability entry points."
            mitre_techs = ["T1046 - Network Service Discovery"]
            remediations = [
                f"Apply temporary IP shun / quarantine rule for host {sources}.",
                "Verify host firewall rules and ensure unnecessary listening ports are closed or restricted.",
                "Review intrusion prevention system (IPS) signatures for port scanning activity."
            ]

        elif "dos" in cat:
            threat_type = "Denial of Service (DoS) Traffic Flood"
            summary = f"Detected volumetric traffic flood from {sources} designed to exhaust system resources on {targets}."
            explanation = f"A volumetric Denial of Service event was detected originating from {sources}. Event ingestion rates spiked to abnormal levels ({ev_count} events), exceeding baseline request thresholds."
            mitre_techs = ["T1499 - Endpoint Denial of Service"]
            remediations = [
                f"Deploy rate-limiting and ACL drop rules for source IP {sources} at ingress router/firewall.",
                "Activate web application firewall (WAF) or DDoS mitigation protection layer.",
                "Monitor host CPU, memory, and bandwidth utilization stats."
            ]

        elif "privilege" in cat or "account" in cat:
            threat_type = "Privilege / Account Anomaly"
            summary = f"Unusual privileged access activity detected for user/account on host {sources}."
            explanation = f"Security monitoring detected elevated privilege actions or unauthorized access attempts associated with sensitive user credentials on entity {sources}."
            mitre_techs = ["T1078 - Valid Accounts", "T1548 - Abuse Elevation Control Mechanism"]
            remediations = [
                "Immediately revoke active sessions for affected privileged accounts.",
                "Force credential reset and mandate hardware token MFA.",
                "Audit privilege escalation logs (`sudo`, `su`, Windows Event ID 4672) for unauthorized modifications."
            ]

        else:
            threat_type = "Unclassified Security Anomaly"
            summary = f"Security anomaly detected across network telemetry from {sources}."
            explanation = f"Statistical behavioral anomaly detected across telemetry logs from {sources}. Multiple events deviated from baseline operational norms."
            mitre_techs = ["T1204 - User Execution"]
            remediations = [
                "Quarantine affected host systems and isolate network segment.",
                "Collect memory forensic dump and review active process execution trees."
            ]

        return AIInvestigationResult(
            analysis_mode="RULE_BASED_FALLBACK",
            summary=summary,
            threat_type=threat_type,
            severity=incident.severity,
            confidence=88.5,
            evidence=evidence,
            attack_explanation=explanation,
            affected_entities=list(set(incident.source_entities + incident.target_entities)),
            mitre_techniques=mitre_techs,
            recommended_actions=remediations
        )
