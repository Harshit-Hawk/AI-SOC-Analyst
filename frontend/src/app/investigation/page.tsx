"use client";

import React, { useEffect, useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import { fetchIncidents, retriggerInvestigation, SecurityIncident } from "@/lib/api";
import { SeverityBadge } from "@/components/SeverityBadge";
import { 
  ShieldAlert, 
  Bot, 
  CheckCircle2, 
  AlertOctagon, 
  Crosshair, 
  Sparkles,
  RefreshCw
} from "lucide-react";

function InvestigationContent() {
  const searchParams = useSearchParams();
  const incidentIdParam = searchParams.get("incident_id");

  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<SecurityIncident | null>(null);
  const [loading, setLoading] = useState(true);
  const [reinvestigating, setReinvestigating] = useState(false);

  const loadIncidents = async () => {
    setLoading(true);
    const data = await fetchIncidents();
    setIncidents(data);
    
    if (data.length > 0) {
      if (incidentIdParam) {
        const matched = data.find(i => i.id === incidentIdParam);
        setSelectedIncident(matched || data[0]);
      } else {
        setSelectedIncident(data[0]);
      }
    }
    setLoading(false);
  };

  useEffect(() => {
    loadIncidents();
  }, [incidentIdParam]);

  const handleRetrigger = async () => {
    if (!selectedIncident) return;
    setReinvestigating(true);
    const updated = await retriggerInvestigation(selectedIncident.id);
    if (updated) {
      setSelectedIncident(updated);
    }
    setReinvestigating(false);
  };

  const ai = selectedIncident?.ai_investigation;
  const risk = selectedIncident?.risk_score;

  return (
    <div className="flex flex-col lg:flex-row gap-6 h-[calc(100vh-6rem)]">
      {/* Left Pane: Incident Selector */}
      <div className="w-full lg:w-80 bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col shrink-0 overflow-y-auto">
        <div className="flex items-center justify-between mb-3 pb-2 border-b border-slate-800">
          <h2 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Active Incidents ({incidents.length})</h2>
          <button onClick={loadIncidents} className="text-slate-400 hover:text-slate-200">
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>

        {incidents.length === 0 ? (
          <div className="text-xs text-slate-400 py-6 text-center">No incidents available.</div>
        ) : (
          <div className="space-y-2">
            {incidents.map((inc) => {
              const isSelected = selectedIncident?.id === inc.id;
              return (
                <button
                  key={inc.id}
                  onClick={() => setSelectedIncident(inc)}
                  className={`w-full text-left p-3 rounded-lg border transition-all text-xs ${
                    isSelected
                      ? "bg-blue-600/20 border-blue-500/50 text-slate-100 shadow-sm"
                      : "bg-slate-950/40 border-slate-800 text-slate-400 hover:bg-slate-800/40 hover:text-slate-200"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <SeverityBadge severity={inc.severity} />
                    <span className="font-mono text-[10px] text-slate-400">
                      {new Date(inc.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </span>
                  </div>
                  <div className="font-semibold line-clamp-1">{inc.title}</div>
                  <div className="text-[11px] text-slate-400 mt-1 font-mono">
                    Src: {inc.source_entities.join(", ") || "Unknown"}
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Main Investigation Workspace */}
      <div className="flex-1 bg-slate-900 border border-slate-800 rounded-xl p-6 overflow-y-auto space-y-6">
        {!selectedIncident ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-400 text-sm">
            <ShieldAlert className="w-12 h-12 text-slate-600 mb-3" />
            <p>Select an incident from the left sidebar to begin deep investigation.</p>
          </div>
        ) : (
          <>
            {/* Header Banner */}
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={selectedIncident.severity} />
                  <span className="text-xs font-mono text-slate-400">ID: {selectedIncident.id}</span>
                  <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700 font-mono">
                    Category: {selectedIncident.threat_category}
                  </span>
                </div>
                <h1 className="text-xl font-bold text-slate-100">{selectedIncident.title}</h1>
              </div>

              <div className="flex items-center gap-3">
                <button
                  onClick={handleRetrigger}
                  disabled={reinvestigating}
                  className="flex items-center gap-2 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg shadow-sm transition-colors"
                >
                  <Sparkles className={`w-3.5 h-3.5 ${reinvestigating ? "animate-spin" : ""}`} />
                  <span>Re-run AI Analysis</span>
                </button>
              </div>
            </div>

            {/* AI Investigation Findings Box */}
            <div className="bg-gradient-to-r from-slate-950 via-slate-900 to-slate-950 border border-blue-500/30 rounded-xl p-5 shadow-md">
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <Bot className="w-5 h-5 text-blue-400" />
                  <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider">AI SOC Agent Analysis</h2>
                </div>
                {ai && (
                  <span className={`px-2.5 py-0.5 rounded text-[11px] font-mono font-bold uppercase tracking-wider border ${
                    ai.analysis_mode === "LIVE_LLM"
                      ? "bg-purple-500/20 text-purple-300 border-purple-500/40"
                      : "bg-blue-500/20 text-blue-300 border-blue-500/40"
                  }`}>
                    Mode: {ai.analysis_mode === "LIVE_LLM" ? "Live LLM Engine" : "Rule-Based SOC Analysis"}
                  </span>
                )}
              </div>

              {ai ? (
                <div className="space-y-4">
                  {/* Executive Summary */}
                  <div className="bg-slate-950/80 p-3.5 rounded-lg border border-slate-800 text-xs leading-relaxed text-slate-200">
                    <strong className="text-blue-400 block mb-1">EXECUTIVE SUMMARY:</strong>
                    {ai.summary}
                  </div>

                  {/* Confirmed Evidence Badges */}
                  <div>
                    <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Confirmed Telemetry Evidence</h3>
                    <div className="space-y-1.5">
                      {ai.evidence.map((ev, idx) => (
                        <div key={idx} className="flex items-start gap-2 text-xs bg-slate-950/40 px-3 py-1.5 rounded border border-slate-800/60 text-slate-300 font-mono">
                          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0 mt-0.5" />
                          <span>{ev}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Attack Explanation */}
                  <div className="bg-slate-950/50 p-4 rounded-lg border border-slate-800">
                    <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-1.5">Technical Attack Narrative</h3>
                    <p className="text-xs text-slate-300 leading-relaxed font-sans">{ai.attack_explanation}</p>
                  </div>

                  {/* Recommended Response Actions */}
                  <div>
                    <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Recommended Incident Response Actions</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {ai.recommended_actions.map((act, idx) => (
                        <div key={idx} className="flex items-start gap-2 bg-slate-950/60 p-2.5 rounded border border-slate-800 text-xs text-slate-200">
                          <span className="w-4 h-4 rounded bg-blue-600/20 text-blue-400 flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5">
                            {idx + 1}
                          </span>
                          <span>{act}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-xs text-slate-400 py-4">AI Analysis pending...</div>
              )}
            </div>

            {/* MITRE ATT&CK Cards & Risk Score */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* MITRE ATT&CK Matrix Card */}
              <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-5">
                <div className="flex items-center gap-2 mb-4">
                  <Crosshair className="w-4 h-4 text-purple-400" />
                  <h2 className="text-sm font-bold text-slate-200 tracking-wide">MITRE ATT&CK Knowledge Mapping</h2>
                </div>

                <div className="space-y-3">
                  {selectedIncident.mitre_mappings.map((m, idx) => (
                    <div key={idx} className="p-3.5 bg-slate-900 rounded-lg border border-slate-800 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="px-2 py-0.5 bg-purple-500/20 text-purple-300 border border-purple-500/30 rounded font-mono text-xs font-bold">
                          {m.technique_id} • {m.technique_name}
                        </span>
                        <span className="text-[11px] text-slate-400 font-mono">Tactic: {m.tactic}</span>
                      </div>
                      <p className="text-xs text-slate-300 font-sans mt-1"><strong>Reason:</strong> {m.reason}</p>
                      <p className="text-[11px] text-slate-400 leading-normal">{m.description}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Transparent Risk Score Breakdown */}
              <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <AlertOctagon className="w-4 h-4 text-orange-400" />
                    <h2 className="text-sm font-bold text-slate-200 tracking-wide">Multi-Factor Risk Score Breakdown</h2>
                  </div>
                  {risk && (
                    <span className="text-lg font-extrabold font-mono text-orange-400">
                      {risk.total_score}/100 ({risk.risk_level})
                    </span>
                  )}
                </div>

                {risk ? (
                  <div className="space-y-3">
                    <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full transition-all duration-500 ${
                          risk.total_score >= 76 ? "bg-red-500" : risk.total_score >= 51 ? "bg-orange-500" : "bg-amber-500"
                        }`}
                        style={{ width: `${risk.total_score}%` }}
                      ></div>
                    </div>

                    <div className="divide-y divide-slate-800 text-xs">
                      {risk.factors.map((f, idx) => (
                        <div key={idx} className="py-2 flex items-center justify-between">
                          <div>
                            <span className="font-semibold text-slate-200">{f.factor}</span>
                            <p className="text-[11px] text-slate-400">{f.description}</p>
                          </div>
                          <span className="font-mono font-bold text-slate-300 ml-2">
                            +{f.contribution} pts
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="text-xs text-slate-400">Calculating risk...</div>
                )}
              </div>
            </div>

            {/* Detection Rule & ML Details */}
            <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-5">
              <h2 className="text-sm font-bold text-slate-200 tracking-wide mb-4">Hybrid Detection Layer Triggers</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {selectedIncident.alerts.map((alt) => (
                  <div key={alt.id} className="p-4 bg-slate-900 rounded-lg border border-slate-800 space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-slate-200">{alt.title}</span>
                      <span className={`px-2 py-0.5 text-[10px] font-mono font-bold rounded ${
                        alt.detection_type === "RULE" ? "bg-blue-500/20 text-blue-300" : "bg-purple-500/20 text-purple-300"
                      }`}>
                        {alt.detection_type} ENGINE
                      </span>
                    </div>
                    <p className="text-xs text-slate-400">{alt.description}</p>

                    {alt.rule_details && (
                      <div className="p-2.5 bg-slate-950 rounded border border-slate-800 text-xs font-mono space-y-1 text-slate-300">
                        <div>Rule Name: <span className="text-blue-400">{alt.rule_details.rule_name}</span></div>
                        <div>Condition: <span className="text-slate-200">{alt.rule_details.condition_matched}</span></div>
                        <div>Actual Value: <span className="text-amber-400">{alt.rule_details.actual_value}</span> (Threshold: {alt.rule_details.threshold_value})</div>
                      </div>
                    )}

                    {alt.ml_details && (
                      <div className="p-2.5 bg-slate-950 rounded border border-slate-800 text-xs font-mono space-y-1 text-slate-300">
                        <div>Model: <span className="text-purple-400">{alt.ml_details.model_name}</span></div>
                        <div>Anomaly Score: <span className="text-slate-200">{alt.ml_details.anomaly_score}</span></div>
                        <div>Confidence: <span className="text-purple-300 font-bold">{alt.ml_details.confidence}%</span></div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {/* Correlated Raw Events Table */}
            <div className="bg-slate-950/60 border border-slate-800 rounded-xl p-5">
              <h2 className="text-sm font-bold text-slate-200 tracking-wide mb-3">Correlated Raw Telemetry Events ({selectedIncident.events.length})</h2>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-900 text-slate-400 uppercase tracking-wider border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Timestamp</th>
                      <th className="py-2.5 px-3">Source → Target</th>
                      <th className="py-2.5 px-3">Protocol</th>
                      <th className="py-2.5 px-3">User</th>
                      <th className="py-2.5 px-3">Action</th>
                      <th className="py-2.5 px-3">Status</th>
                      <th className="py-2.5 px-3">Raw Log Message</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800 text-slate-300">
                    {selectedIncident.events.map((e) => (
                      <tr key={e.id} className="hover:bg-slate-900/60">
                        <td className="py-2 px-3 text-slate-400">
                          {new Date(e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                        </td>
                        <td className="py-2 px-3 text-blue-300">
                          {e.source_ip}:{e.source_port || ''} → {e.destination_ip}:{e.destination_port || ''}
                        </td>
                        <td className="py-2 px-3">{e.protocol}</td>
                        <td className="py-2 px-3 font-semibold text-amber-300">{e.username}</td>
                        <td className="py-2 px-3">{e.action}</td>
                        <td className="py-2 px-3">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] ${
                            e.status.toLowerCase() === "failure" || e.status.toLowerCase() === "denied"
                              ? "bg-red-500/20 text-red-400"
                              : "bg-emerald-500/20 text-emerald-400"
                          }`}>
                            {e.status}
                          </span>
                        </td>
                        <td className="py-2 px-3 text-slate-400 truncate max-w-xs">{e.message}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default function InvestigationPage() {
  return (
    <Suspense fallback={<div className="text-slate-400 text-xs p-6">Loading investigation workspace...</div>}>
      <InvestigationContent />
    </Suspense>
  );
}
