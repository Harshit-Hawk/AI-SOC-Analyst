export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000/api/v1";

export interface SecurityEvent {
  id: string;
  timestamp: string;
  source_ip: string;
  destination_ip: string;
  source_port?: number;
  destination_port?: number;
  protocol: string;
  event_type: string;
  username?: string;
  action: string;
  status: string;
  message: string;
  severity: string;
  metadata: Record<string, any>;
}

export interface SecurityAlert {
  id: string;
  timestamp: string;
  title: string;
  description: string;
  detection_type: "RULE" | "ML" | "HYBRID";
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  category: string;
  source_ip?: string;
  destination_ip?: string;
  username?: string;
  triggering_event_ids: string[];
  event_count: number;
  rule_details?: {
    rule_name: string;
    rule_id: string;
    condition_matched: string;
    threshold_value: any;
    actual_value: any;
  };
  ml_details?: {
    model_name: string;
    anomaly_score: number;
    confidence: number;
    top_feature_contributions: Record<string, number>;
  };
  mitre_technique_id?: string;
  mitre_technique_name?: string;
}

export interface MITREMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  description: string;
  reason: string;
}

export interface RiskFactor {
  factor: string;
  weight: number;
  contribution: number;
  description: string;
}

export interface RiskScoreBreakdown {
  total_score: number;
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  factors: RiskFactor[];
}

export interface AIInvestigationResult {
  analysis_mode: "LIVE_LLM" | "RULE_BASED_FALLBACK";
  summary: string;
  threat_type: string;
  severity: string;
  confidence: number;
  evidence: string[];
  attack_explanation: string;
  affected_entities: string[];
  mitre_techniques: string[];
  recommended_actions: string[];
}

export interface SecurityIncident {
  id: string;
  created_at: string;
  updated_at: string;
  title: string;
  description: string;
  severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
  status: "OPEN" | "INVESTIGATING" | "MITIGATED" | "CLOSED";
  threat_category: string;
  source_entities: string[];
  target_entities: string[];
  alerts: SecurityAlert[];
  events: SecurityEvent[];
  mitre_mappings: MITREMapping[];
  risk_score?: RiskScoreBreakdown;
  ai_investigation?: AIInvestigationResult;
}

export interface BenchmarkMetrics {
  mode: string;
  total_samples: number;
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  precision: number;
  recall: number;
  f1_score: number;
  accuracy: number;
  false_positive_rate: number;
  detection_rate: number;
  scenario_performance: Record<string, { detected: number; alerts_generated: number }>;
}

export async function fetchHealth() {
  const res = await fetch(`${API_BASE_URL}/health`, { cache: 'no-store' });
  if (!res.ok) throw new Error("Backend connection failed");
  return res.json();
}

export async function fetchEvents(limit = 100): Promise<SecurityEvent[]> {
  const res = await fetch(`${API_BASE_URL}/events?limit=${limit}`, { cache: 'no-store' });
  if (!res.ok) return [];
  return res.json();
}

export async function fetchAlerts(limit = 100): Promise<SecurityAlert[]> {
  const res = await fetch(`${API_BASE_URL}/alerts?limit=${limit}`, { cache: 'no-store' });
  if (!res.ok) return [];
  return res.json();
}

export async function fetchIncidents(severity?: string, status?: string, search?: string): Promise<SecurityIncident[]> {
  const params = new URLSearchParams();
  if (severity) params.append("severity", severity);
  if (status) params.append("status", status);
  if (search) params.append("search", search);
  
  const res = await fetch(`${API_BASE_URL}/incidents?${params.toString()}`, { cache: 'no-store' });
  if (!res.ok) return [];
  return res.json();
}

export async function fetchIncidentById(id: string): Promise<SecurityIncident | null> {
  const res = await fetch(`${API_BASE_URL}/incidents/${id}`, { cache: 'no-store' });
  if (!res.ok) return null;
  return res.json();
}

export async function retriggerInvestigation(id: string): Promise<SecurityIncident | null> {
  const res = await fetch(`${API_BASE_URL}/incidents/${id}/investigate`, { method: "POST" });
  if (!res.ok) return null;
  return res.json();
}

export async function runSimulation(scenario: string) {
  const res = await fetch(`${API_BASE_URL}/simulator/run?scenario=${scenario}`, { method: "POST" });
  if (!res.ok) throw new Error("Simulation failed");
  return res.json();
}

export async function fetchBenchmark(): Promise<Record<string, BenchmarkMetrics>> {
  const res = await fetch(`${API_BASE_URL}/benchmark/evaluate`, { cache: 'no-store' });
  if (!res.ok) return {};
  return res.json();
}

export async function resetTelemetry() {
  const res = await fetch(`${API_BASE_URL}/system/reset`, { method: "POST" });
  return res.json();
}
