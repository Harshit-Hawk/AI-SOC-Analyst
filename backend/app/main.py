from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Query, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, HTMLResponse
from typing import List, Optional, Dict, Any
from datetime import datetime

from app.config import settings
from app.schemas.events import StandardSecurityEvent, RawLogPayload, IngestionResponse
from app.schemas.alerts import SecurityAlert
from app.schemas.incidents import SecurityIncident, BenchmarkMetrics
from app.services.normalizer import LogNormalizer
from app.services.detection import RuleDetectionEngine
from app.services.ml_detector import MLDetectionEngine
from app.services.correlator import AlertCorrelator
from app.services.mitre_mapper import MITREMapper
from app.services.risk_scorer import RiskScorer
from app.services.ai_agent import AISOCAnalystAgent
from app.services.report_generator import IncidentReportGenerator
from app.simulator.attack_scenarios import AttackSimulator
from app.benchmark.evaluator import BenchmarkEvaluator

# In-Memory Database State
class SOCDatabase:
    def __init__(self):
        self.events: List[StandardSecurityEvent] = []
        self.alerts: List[SecurityAlert] = []
        self.incidents: List[SecurityIncident] = []

db = SOCDatabase()

# Services Initialization
rule_engine = RuleDetectionEngine()
ml_engine = MLDetectionEngine()
correlator = AlertCorrelator()
ai_agent = AISOCAnalystAgent()
benchmark_evaluator = BenchmarkEvaluator()

async def process_event_pipeline(events: List[StandardSecurityEvent]) -> List[SecurityIncident]:
    """
    Executes the COMPLETE production SOC pipeline:
    Events -> Normalizer -> Rule & ML Detection -> Correlator -> Incident -> MITRE -> Risk -> AI Investigation
    """
    db.events.extend(events)

    # 1. Threat Detection (Rule + ML)
    rule_alerts = rule_engine.analyze_events(events)
    ml_alerts = ml_engine.detect_anomalies(events)
    new_alerts = rule_alerts + ml_alerts
    db.alerts.extend(new_alerts)

    # 2. Event & Alert Correlation
    new_incidents = correlator.correlate(new_alerts, events)

    # 3. MITRE Mapping, Risk Scoring, & AI Investigation for each incident
    for inc in new_incidents:
        inc.mitre_mappings = MITREMapper.map_incident(inc)
        inc.risk_score = RiskScorer.calculate_risk(inc)
        inc.ai_investigation = await ai_agent.investigate(inc)
        db.incidents.append(inc)

    return new_incidents

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup seed telemetry
    demo_bf_events = AttackSimulator.generate_brute_force(count=8, src_ip="192.168.1.105")
    demo_ps_events = AttackSimulator.generate_port_scan(num_ports=18, src_ip="10.0.0.88")
    
    await process_event_pipeline(demo_bf_events)
    await process_event_pipeline(demo_ps_events)
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="AI-Powered SOC Analyst for Automated Threat Detection and Incident Investigation",
    lifespan=lifespan
)

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/v1/health")
def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "ai_mode": "LIVE_LLM" if settings.LLM_API_KEY else "RULE_BASED_FALLBACK",
        "total_events": len(db.events),
        "total_alerts": len(db.alerts),
        "total_incidents": len(db.incidents)
    }

@app.post("/api/v1/events/ingest", response_model=IngestionResponse)
async def ingest_logs(payload: RawLogPayload):
    res = LogNormalizer.process_raw_payload(payload.format, payload.raw_data)
    if res.events:
        await process_event_pipeline(res.events)
    return res

@app.get("/api/v1/events", response_model=List[StandardSecurityEvent])
def get_events(limit: int = Query(100, ge=1, le=1000)):
    return db.events[-limit:]

@app.get("/api/v1/alerts", response_model=List[SecurityAlert])
def get_alerts(limit: int = Query(100, ge=1, le=1000)):
    return db.alerts[-limit:]

@app.get("/api/v1/incidents", response_model=List[SecurityIncident])
def get_incidents(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None
):
    results = db.incidents
    if severity:
        results = [i for i in results if i.severity.upper() == severity.upper()]
    if status:
        results = [i for i in results if i.status.upper() == status.upper()]
    if search:
        s = search.lower()
        results = [
            i for i in results if s in i.title.lower() or s in i.description.lower() or s in i.threat_category.lower()
        ]
    return sorted(results, key=lambda i: i.created_at, reverse=True)

@app.get("/api/v1/incidents/{incident_id}", response_model=SecurityIncident)
def get_incident(incident_id: str):
    for inc in db.incidents:
        if inc.id == incident_id:
            return inc
    raise HTTPException(status_code=404, detail="Incident not found")

@app.post("/api/v1/incidents/{incident_id}/investigate", response_model=SecurityIncident)
async def retrigger_investigation(incident_id: str):
    for inc in db.incidents:
        if inc.id == incident_id:
            inc.ai_investigation = await ai_agent.investigate(inc)
            inc.updated_at = datetime.utcnow()
            return inc
    raise HTTPException(status_code=404, detail="Incident not found")

@app.get("/api/v1/incidents/{incident_id}/report")
def export_report(incident_id: str, format: str = Query("markdown", pattern="^(markdown|json|html)$")):
    inc = get_incident(incident_id)
    if format == "json":
        return IncidentReportGenerator.to_json(inc)
    elif format == "html":
        return HTMLResponse(content=IncidentReportGenerator.to_html(inc))
    else:
        return PlainTextResponse(content=IncidentReportGenerator.to_markdown(inc))

@app.post("/api/v1/simulator/run")
async def run_simulation(scenario: str = Query("brute_force")):
    """
    Triggers an attack simulation.
    Generates synthetic security events and feeds them through the production pipeline.
    """
    raw_events = AttackSimulator.get_scenario_events(scenario)
    new_incidents = await process_event_pipeline(raw_events)
    return {
        "scenario": scenario,
        "events_generated": len(raw_events),
        "alerts_generated": sum(len(inc.alerts) for inc in new_incidents),
        "incidents_created": len(new_incidents),
        "new_incidents": new_incidents
    }

@app.get("/api/v1/benchmark/evaluate", response_model=Dict[str, BenchmarkMetrics])
def evaluate_benchmark():
    return benchmark_evaluator.evaluate_all()

@app.post("/api/v1/system/reset")
def reset_system():
    db.events.clear()
    db.alerts.clear()
    db.incidents.clear()
    return {"status": "success", "message": "Telemetry database reset successfully."}
