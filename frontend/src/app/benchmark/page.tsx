"use client";

import React, { useEffect, useState } from "react";
import { fetchBenchmark, BenchmarkMetrics } from "@/lib/api";
import { 
  BarChart3, 
  CheckCircle2, 
  XCircle, 
  AlertTriangle, 
  Layers, 
  Zap,
  RefreshCw
} from "lucide-react";
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend 
} from "recharts";

export default function BenchmarkPage() {
  const [data, setData] = useState<Record<string, BenchmarkMetrics>>({});
  const [loading, setLoading] = useState(true);

  const loadBenchmark = async () => {
    setLoading(true);
    const res = await fetchBenchmark();
    setData(res);
    setLoading(false);
  };

  useEffect(() => {
    loadBenchmark();
  }, []);

  const chartData = [
    {
      metric: "Precision",
      "Rule-Based": (data["Rule-Based"]?.precision || 0) * 100,
      "ML-Based": (data["ML-Based"]?.precision || 0) * 100,
      "Hybrid": (data["Hybrid"]?.precision || 0) * 100,
    },
    {
      metric: "Recall",
      "Rule-Based": (data["Rule-Based"]?.recall || 0) * 100,
      "ML-Based": (data["ML-Based"]?.recall || 0) * 100,
      "Hybrid": (data["Hybrid"]?.recall || 0) * 100,
    },
    {
      metric: "F1 Score",
      "Rule-Based": (data["Rule-Based"]?.f1_score || 0) * 100,
      "ML-Based": (data["ML-Based"]?.f1_score || 0) * 100,
      "Hybrid": (data["Hybrid"]?.f1_score || 0) * 100,
    },
    {
      metric: "Accuracy",
      "Rule-Based": (data["Rule-Based"]?.accuracy || 0) * 100,
      "ML-Based": (data["ML-Based"]?.accuracy || 0) * 100,
      "Hybrid": (data["Hybrid"]?.accuracy || 0) * 100,
    }
  ];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
            <BarChart3 className="w-6 h-6 text-purple-400" />
            <span>Detection Engine Performance Benchmarks</span>
          </h1>
          <p className="text-sm text-slate-400">Comparative evaluation of Rule-Based, ML-Based, and Hybrid Detection layers against controlled synthetic telemetry scenarios.</p>
        </div>

        <button
          onClick={loadBenchmark}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-lg border border-slate-700 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          <span>Re-Evaluate Engines</span>
        </button>
      </div>

      {/* Overview Cards per Mode */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {["Rule-Based", "ML-Based", "Hybrid"].map((mode) => {
          const metrics = data[mode];
          return (
            <div key={mode} className={`bg-slate-900 border rounded-xl p-5 shadow-sm ${
              mode === "Hybrid" ? "border-purple-500/50 bg-purple-950/10" : "border-slate-800"
            }`}>
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">{mode} Engine</span>
                {mode === "Hybrid" && (
                  <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30 text-[10px] font-bold">
                    RECOMMENDED
                  </span>
                )}
              </div>

              {metrics ? (
                <div className="space-y-3">
                  <div className="grid grid-cols-2 gap-2 text-center">
                    <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                      <div className="text-[10px] text-slate-400 uppercase font-mono">F1 Score</div>
                      <div className="text-xl font-bold font-mono text-emerald-400">{(metrics.f1_score * 100).toFixed(1)}%</div>
                    </div>
                    <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                      <div className="text-[10px] text-slate-400 uppercase font-mono">Precision</div>
                      <div className="text-xl font-bold font-mono text-blue-400">{(metrics.precision * 100).toFixed(1)}%</div>
                    </div>
                  </div>

                  <div className="divide-y divide-slate-800 text-xs font-mono text-slate-300">
                    <div className="py-1.5 flex justify-between">
                      <span>Recall / Detection Rate:</span>
                      <strong className="text-slate-100">{(metrics.recall * 100).toFixed(1)}%</strong>
                    </div>
                    <div className="py-1.5 flex justify-between">
                      <span>False Positive Rate (FPR):</span>
                      <strong className={metrics.false_positive_rate === 0 ? "text-emerald-400" : "text-amber-400"}>
                        {(metrics.false_positive_rate * 100).toFixed(1)}%
                      </strong>
                    </div>
                    <div className="py-1.5 flex justify-between">
                      <span>Accuracy:</span>
                      <strong className="text-slate-100">{(metrics.accuracy * 100).toFixed(1)}%</strong>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-xs text-slate-400 py-4">Evaluating...</div>
              )}
            </div>
          );
        })}
      </div>

      {/* Comparative Bar Chart */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider mb-4">Comparative Metric Benchmark (% Rating)</h2>
        <div className="h-64 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="metric" stroke="#64748b" fontSize={11} />
              <YAxis stroke="#64748b" fontSize={11} domain={[0, 100]} />
              <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", color: "#f8fafc" }} />
              <Legend />
              <Bar dataKey="Rule-Based" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              <Bar dataKey="ML-Based" fill="#eab308" radius={[4, 4, 0, 0]} />
              <Bar dataKey="Hybrid" fill="#a855f7" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Confusion Matrices */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
        <h2 className="text-sm font-bold text-slate-200 uppercase tracking-wider">Confusion Matrices Breakdown</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {["Rule-Based", "ML-Based", "Hybrid"].map((mode) => {
            const m = data[mode];
            if (!m) return null;
            return (
              <div key={mode} className="bg-slate-950/80 p-4 rounded-lg border border-slate-800 font-mono text-xs">
                <div className="font-bold text-slate-300 text-center mb-3 border-b border-slate-800 pb-2">{mode} Matrix</div>
                <div className="grid grid-cols-2 gap-2 text-center">
                  <div className="p-2 bg-emerald-500/10 border border-emerald-500/30 rounded">
                    <div className="text-[10px] text-emerald-400 font-bold">TRUE POSITIVES (TP)</div>
                    <div className="text-lg font-bold text-emerald-300 mt-1">{m.true_positives}</div>
                  </div>
                  <div className="p-2 bg-amber-500/10 border border-amber-500/30 rounded">
                    <div className="text-[10px] text-amber-400 font-bold">FALSE POSITIVES (FP)</div>
                    <div className="text-lg font-bold text-amber-300 mt-1">{m.false_positives}</div>
                  </div>
                  <div className="p-2 bg-red-500/10 border border-red-500/30 rounded">
                    <div className="text-[10px] text-red-400 font-bold">FALSE NEGATIVES (FN)</div>
                    <div className="text-lg font-bold text-red-300 mt-1">{m.false_negatives}</div>
                  </div>
                  <div className="p-2 bg-blue-500/10 border border-blue-500/30 rounded">
                    <div className="text-[10px] text-blue-400 font-bold">TRUE NEGATIVES (TN)</div>
                    <div className="text-lg font-bold text-blue-300 mt-1">{m.true_negatives}</div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
