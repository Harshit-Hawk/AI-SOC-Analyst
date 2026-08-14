"use client";

import React, { useState } from "react";
import Link from "next/link";
import { runSimulation } from "@/lib/api";
import { 
  Zap, 
  ShieldAlert, 
  Terminal, 
  CheckCircle2, 
  ArrowRight, 
  Play, 
  Cpu, 
  Bot, 
  FileText,
  AlertTriangle
} from "lucide-react";

export default function SimulatorPage() {
  const [activeScenario, setActiveScenario] = useState<string | null>(null);
  const [simulationResult, setSimulationResult] = useState<any | null>(null);
  const [loading, setLoading] = useState(false);
  const [stage, setStage] = useState<number>(0);

  const scenarios = [
    {
      id: "brute_force",
      title: "Brute Force Authentication",
      mitre: "T1110",
      description: "Generates high-frequency failed SSH login attempts from a single source IP against account 'root'.",
      expectedDetection: "Rule-Based Threshold (RULE-BF-101) + Isolation Forest ML Anomaly score > 80%",
      severity: "HIGH",
      color: "border-red-500/40 bg-red-500/5 text-red-400"
    },
    {
      id: "port_scan",
      title: "Port Scanning Reconnaissance",
      mitre: "T1046",
      description: "Generates rapid TCP SYN connection probes across 25 distinct destination ports from host 10.0.0.88.",
      expectedDetection: "Rule-Based Discovery Threshold (RULE-PS-201) + Network Service Discovery Mapping",
      severity: "MEDIUM",
      color: "border-orange-500/40 bg-orange-500/5 text-orange-400"
    },
    {
      id: "dos",
      title: "Denial of Service (DoS)",
      mitre: "T1499",
      description: "Generates a volumetric HTTP request burst (65+ requests) within a 5-second window from 172.16.0.42.",
      expectedDetection: "Volumetric Flood Threshold (RULE-DOS-301) + Isolation Forest Anomaly Trigger",
      severity: "CRITICAL",
      color: "border-amber-500/40 bg-amber-500/5 text-amber-300"
    },
    {
      id: "privilege_anomaly",
      title: "Credential & Privilege Anomaly",
      mitre: "T1078",
      description: "Generates sensitive account root logins and sudo escalation telemetry from unusual IP 192.168.1.55.",
      expectedDetection: "Sensitive Account Policy (RULE-PA-401) + MITRE Valid Accounts Mapping",
      severity: "HIGH",
      color: "border-purple-500/40 bg-purple-500/5 text-purple-300"
    }
  ];

  const handleRunSimulation = async (scenarioId: string) => {
    setActiveScenario(scenarioId);
    setLoading(true);
    setSimulationResult(null);
    setStage(1); // Stage 1: Ingestion

    setTimeout(() => setStage(2), 600); // Stage 2: Normalization & Detection
    setTimeout(() => setStage(3), 1200); // Stage 3: Correlation & Risk Scoring
    setTimeout(() => setStage(4), 1800); // Stage 4: AI Investigation

    try {
      const res = await runSimulation(scenarioId);
      setTimeout(() => {
        setSimulationResult(res);
        setStage(5); // Complete
        setLoading(false);
      }, 2400);
    } catch (err) {
      setLoading(false);
      setStage(0);
      alert("Simulation failed. Ensure backend API is running.");
    }
  };

  const pipelineStages = [
    { num: 1, label: "Event Ingestion & Normalization" },
    { num: 2, label: "Rule & ML Detection" },
    { num: 3, label: "Correlation & Risk Scoring" },
    { num: 4, label: "AI SOC Agent Investigation" },
    { num: 5, label: "Incident Dashboard Synchronized" }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
          <Zap className="w-6 h-6 text-amber-400" />
          <span>Interactive Attack Simulator</span>
        </h1>
        <p className="text-sm text-slate-400">
          Simulate realistic cybersecurity attack scenarios. All synthetic logs pass through the <strong>EXACT production SOC pipeline</strong>.
        </p>
      </div>

      {/* Scenario Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {scenarios.map((sc) => (
          <div key={sc.id} className={`bg-slate-900 border rounded-xl p-5 flex flex-col justify-between ${sc.color}`}>
            <div>
              <div className="flex items-center justify-between mb-2">
                <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-slate-950/80 border border-slate-800">
                  MITRE {sc.mitre}
                </span>
                <span className="text-xs font-bold uppercase tracking-wider">{sc.severity}</span>
              </div>
              <h2 className="text-base font-bold text-slate-100 mb-1">{sc.title}</h2>
              <p className="text-xs text-slate-300 leading-relaxed mb-3">{sc.description}</p>
              <div className="text-[11px] font-mono text-slate-400 bg-slate-950/60 p-2.5 rounded border border-slate-800 mb-4">
                <strong>Expected Detection:</strong> {sc.expectedDetection}
              </div>
            </div>

            <button
              onClick={() => handleRunSimulation(sc.id)}
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 py-2.5 bg-blue-600 hover:bg-blue-500 text-white font-semibold text-xs rounded-lg shadow transition-colors disabled:opacity-50"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              <span>{loading && activeScenario === sc.id ? "Simulating Pipeline..." : "Run Attack Simulation"}</span>
            </button>
          </div>
        ))}
      </div>

      {/* Real-time Pipeline Execution Visualizer */}
      {stage > 0 && (
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-4">
          <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider flex items-center gap-2">
            <Cpu className="w-4 h-4 text-blue-400" />
            <span>Production SOC Pipeline Execution Flow</span>
          </h2>

          <div className="grid grid-cols-1 md:grid-cols-5 gap-3">
            {pipelineStages.map((stg) => {
              const isDone = stage > stg.num || stage === 5;
              const isCurrent = stage === stg.num && stage < 5;
              return (
                <div
                  key={stg.num}
                  className={`p-3 rounded-lg border text-center font-mono text-xs transition-all ${
                    isDone
                      ? "bg-emerald-500/15 border-emerald-500/40 text-emerald-300"
                      : isCurrent
                      ? "bg-blue-600/20 border-blue-500/50 text-blue-300 animate-pulse"
                      : "bg-slate-950/40 border-slate-800 text-slate-400"
                  }`}
                >
                  <div className="font-bold text-[10px] uppercase tracking-wider mb-1">Stage {stg.num}</div>
                  <div className="text-[11px] leading-tight font-semibold">{stg.label}</div>
                </div>
              );
            })}
          </div>

          {/* Simulation Output Summary */}
          {simulationResult && (
            <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-5 mt-4 space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                  <CheckCircle2 className="w-5 h-5" />
                  <span>Pipeline Execution Successful</span>
                </div>
                <span className="text-xs font-mono text-slate-400">Scenario: {simulationResult.scenario}</span>
              </div>

              <div className="grid grid-cols-3 gap-4 text-xs font-mono bg-slate-900 p-3 rounded border border-slate-800">
                <div>Events Ingested: <strong className="text-slate-100">{simulationResult.events_generated}</strong></div>
                <div>Alerts Triggered: <strong className="text-amber-400">{simulationResult.alerts_generated}</strong></div>
                <div>Incidents Created: <strong className="text-red-400">{simulationResult.incidents_created}</strong></div>
              </div>

              {simulationResult.new_incidents?.length > 0 && (
                <div className="flex justify-end pt-2">
                  <Link
                    href={`/investigation?incident_id=${simulationResult.new_incidents[0].id}`}
                    className="inline-flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg transition-colors"
                  >
                    <span>Investigate Generated Incident</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </Link>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
