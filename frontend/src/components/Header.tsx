"use client";

import React, { useEffect, useState } from "react";
import { fetchHealth, resetTelemetry } from "@/lib/api";
import { RefreshCw, Bot, Wifi, AlertTriangle } from "lucide-react";

export const Header: React.FC = () => {
  const [health, setHealth] = useState<any>(null);
  const [loading, setLoading] = useState(false);

  const loadHealth = async () => {
    try {
      const data = await fetchHealth();
      setHealth(data);
    } catch {
      setHealth(null);
    }
  };

  useEffect(() => {
    loadHealth();
    const interval = setInterval(loadHealth, 5000);
    return () => clearInterval(interval);
  }, []);

  const handleReset = async () => {
    if (confirm("Reset all stored events, alerts, and incidents?")) {
      setLoading(true);
      await resetTelemetry();
      await loadHealth();
      setLoading(false);
      window.location.reload();
    }
  };

  return (
    <header className="h-16 bg-slate-900/80 backdrop-blur-md border-b border-slate-800 px-6 flex items-center justify-between sticky top-0 z-10">
      {/* Ticker / Status */}
      <div className="flex items-center gap-4 text-xs font-mono text-slate-300">
        <div className="flex items-center gap-2">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span className="text-slate-300 font-semibold">SOC ENGINE ONLINE</span>
        </div>
        <span className="text-slate-400">|</span>
        <div className="flex items-center gap-1.5 text-slate-300">
          <Bot className="w-3.5 h-3.5 text-blue-400" />
          <span>AI Mode:</span>
          <span className={`px-2 py-0.5 rounded font-mono text-[11px] font-bold ${
            health?.ai_mode === "LIVE_LLM"
              ? "bg-purple-500/20 text-purple-300 border border-purple-500/30"
              : "bg-blue-500/20 text-blue-300 border border-blue-500/30"
          }`}>
            {health?.ai_mode || "INITIALIZING"}
          </span>
        </div>
      </div>

      {/* Stats & Controls */}
      <div className="flex items-center gap-4">
        <div className="flex items-center gap-3 text-xs bg-slate-950/60 px-3 py-1.5 rounded-lg border border-slate-800 font-mono">
          <span className="text-slate-400">Events: <strong className="text-slate-200">{health?.total_events ?? 0}</strong></span>
          <span className="text-slate-400">•</span>
          <span className="text-slate-400">Alerts: <strong className="text-amber-400">{health?.total_alerts ?? 0}</strong></span>
          <span className="text-slate-400">•</span>
          <span className="text-slate-400">Incidents: <strong className="text-red-400">{health?.total_incidents ?? 0}</strong></span>
        </div>

        <button
          onClick={handleReset}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-400 hover:text-slate-200 bg-slate-800 hover:bg-slate-700 border border-slate-700 rounded-lg transition-colors"
          title="Reset Telemetry Data"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          <span>Reset Telemetry</span>
        </button>
      </div>
    </header>
  );
};
