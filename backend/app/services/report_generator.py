import json
from typing import Dict, Any
from app.schemas.incidents import SecurityIncident

class IncidentReportGenerator:
    """
    Generates incident reports in Markdown, JSON, and HTML printable formats.
    """

    @classmethod
    def to_markdown(cls, incident: SecurityIncident) -> str:
        ai = incident.ai_investigation
        risk = incident.risk_score

        md = []
        md.append(f"# INCIDENT REPORT: {incident.title}")
        md.append(f"**Incident ID:** `{incident.id}`  ")
        md.append(f"**Severity:** `{incident.severity}` | **Status:** `{incident.status}` | **Threat Category:** `{incident.threat_category}`  ")
        md.append(f"**Created At:** {incident.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}  ")
        md.append("")
        
        md.append("## 1. Executive Summary")
        if ai:
            md.append(f"> **[{ai.analysis_mode}]** {ai.summary}")
        else:
            md.append(incident.description)
        md.append("")

        md.append("## 2. Risk Assessment")
        if risk:
            md.append(f"- **Overall Risk Score:** `{risk.total_score}/100` ({risk.risk_level})")
            md.append("### Risk Factors Breakdown:")
            for f in risk.factors:
                md.append(f"  - **{f.factor}** (Weight: {int(f.weight*100)}%): `+{f.contribution} pts` — {f.description}")
        md.append("")

        md.append("## 3. Threat Classification & MITRE ATT&CK Mapping")
        for m in incident.mitre_mappings:
            md.append(f"- **[{m.technique_id}] {m.technique_name}** (Tactic: *{m.tactic}*)")
            md.append(f"  - *Reason:* {m.reason}")
            md.append(f"  - *Description:* {m.description}")
        md.append("")

        if ai:
            md.append("## 4. Technical Investigation & Evidence")
            md.append(f"### Attack Explanation\n{ai.attack_explanation}\n")
            md.append("### Confirmed Telemetry Evidence:")
            for ev in ai.evidence:
                md.append(f"- {ev}")
            md.append("")

            md.append("## 5. Recommended Incident Response Actions")
            for act in ai.recommended_actions:
                md.append(f"- [ ] {act}")
            md.append("")

        md.append("## 6. Correlated Telemetry & Alert Summary")
        md.append(f"- **Total Correlated Events:** {len(incident.events)}")
        md.append(f"- **Total Security Alerts:** {len(incident.alerts)}")
        md.append(f"- **Source Entities:** {', '.join(incident.source_entities) or 'N/A'}")
        md.append(f"- **Target Entities:** {', '.join(incident.target_entities) or 'N/A'}")
        md.append("")

        return "\n".join(md)

    @classmethod
    def to_json(cls, incident: SecurityIncident) -> Dict[str, Any]:
        return incident.dict()

    @classmethod
    def to_html(cls, incident: SecurityIncident) -> str:
        md_text = cls.to_markdown(incident)
        # Convert simple markdown bullet points / headers to clean styled printable HTML
        body_html = md_text.replace("\n# ", "<h1>").replace("\n## ", "<h2>").replace("\n### ", "<h3>").replace("\n- ", "<li>")
        
        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Incident Report - {incident.id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1e293b; max-width: 900px; margin: 40px auto; padding: 0 20px; }}
        h1 {{ color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; }}
        h2 {{ color: #1e293b; margin-top: 24px; border-bottom: 1px solid #cbd5e1; padding-bottom: 4px; }}
        code {{ background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-family: monospace; font-size: 0.9em; }}
        blockquote {{ background: #f8fafc; border-left: 4px solid #3b82f6; margin: 0; padding: 12px 16px; font-style: italic; }}
        li {{ margin-bottom: 4px; }}
    </style>
</head>
<body>
    {body_html}
</body>
</html>"""
