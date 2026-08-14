"use client";

import React, { useEffect, useState } from "react";
import Link from "next/link";
import { fetchEvents, fetchAlerts, fetchIncidents, SecurityEvent, SecurityAlert, SecurityIncident } from "@/lib/api";
import { SeverityBadge } from "@/components/SeverityBadge";
import { 
  ShieldAlert, 
  AlertTriangle, 
  Activity, 
  Flame, 
  ArrowUpRight, 
  Zap, 
  CheckCircle2,
  RefreshCw
} from "lucide-react";
import { 
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip, 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, AreaChart, Area 
} from "recharts";

export default function SOCDashboard() {
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [loading, setLoading] = useState(true);

  const loadData = async () => {
    setLoading(true);
    const [evData, altData, incData] = await Promise.all([
      fetchEvents(100),
      fetchAlerts(100),
      fetchIncidents()
    ]);
    setEvents(evData);
    setAlerts(altData);
    setIncidents(incData);
    setLoading(false);
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, []);

  const totalEvents = events.length;
  const totalAlerts = alerts.length;
  const criticalCount = incidents.filter(i => i.severity === "CRITICAL").length;
  const highCount = incidents.filter(i => i.severity === "HIGH").length;

  // Pie chart threat distribution
  const threatCounts: Record<string, number> = {};
  incidents.forEach(inc => {
    const cat = inc.threat_category || "Anomaly";
    threatCounts[cat] = (threatCounts[cat] || 0) + 1;
  });
  const pieData = Object.keys(threatCounts).map(cat => ({ name: cat, value: threatCounts[cat] }));
  const PIE_COLORS = ["#ef4444", "#f97316", "#eab308", "#3b82f6", "#8b5cf6"];

  // Bar chart severity distribution
  const severityData = [
    { name: "CRITICAL", count: incidents.filter(i => i.severity === "CRITICAL").length, fill: "#ef4444" },
    { name: "HIGH", count: incidents.filter(i => i.severity === "HIGH").length, fill: "#f97316" },
    { name: "MEDIUM", count: incidents.filter(i => i.severity === "MEDIUM").length, fill: "#eab308" },
    { name: "LOW", count: incidents.filter(i => i.severity === "LOW").length, fill: "#22c55e" },
  ];

  // Timeline mock/recent events density
  const timelineData = events.slice(-20).map((e, idx) => ({
    time: new Date(e.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    events: idx + 1,
    severityScore: e.severity === "CRITICAL" ? 4 : e.severity === "HIGH" ? 3 : e.severity === "MEDIUM" ? 2 : 1
  }));

  return (
    <div className="space-y-6">
      {/* Top Banner / Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 tracking-tight">Security Operations Command Center</h1>
          <p className="text-sm text-slate-400">Real-time Automated Threat Detection, Event Normalization & Incident Correlation</p>
        </div>
        <button
          onClick={loadData}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium rounded-lg border border-slate-700 transition-colors"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh Live Feed
        </button>
      </div>

      {/* Metric Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs font-semibold uppercase tracking-wider">
            <span>Total Ingested Events</span>
            <Activity className="w-4 h-4 text-blue-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-slate-100 font-mono">{totalEvents}</span>
            <span className="text-xs text-emerald-400 font-medium">Standardized</span>
          </div>
          <p className="text-xs text-slate-400 mt-1">Multi-format Normalized Logs</p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs font-semibold uppercase tracking-wider">
            <span>Active Alerts</span>
            <AlertTriangle className="w-4 h-4 text-amber-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-amber-400 font-mono">{totalAlerts}</span>
            <span className="text-xs text-slate-400">Rule + ML</span>
          </div>
          <p className="text-xs text-slate-400 mt-1">Hybrid Detection Layer Triggers</p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs font-semibold uppercase tracking-wider">
            <span>Critical Incidents</span>
            <Flame className="w-4 h-4 text-red-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-red-400 font-mono">{criticalCount}</span>
            <span className="text-xs text-red-400 font-medium">Immediate Action</span>
          </div>
          <p className="text-xs text-slate-400 mt-1">Correlated High Risk Threats</p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 shadow-sm">
          <div className="flex items-center justify-between text-slate-400 text-xs font-semibold uppercase tracking-wider">
            <span>High Severity Threats</span>
            <ShieldAlert className="w-4 h-4 text-orange-400" />
          </div>
          <div className="mt-3 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-orange-400 font-mono">{highCount}</span>
            <span className="text-xs text-slate-400">Investigating</span>
          </div>
          <p className="text-xs text-slate-400 mt-1">Requires SOC Review</p>
        </div>
      </div>

      {/* Analytics Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Threat Distribution Donut */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <h2 className="text-sm font-semibold text-slate-200 tracking-wide mb-4">Threat Category Breakdown</h2>
          <div className="h-56 w-full">
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={55}
                    outerRadius={80}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={PIE_COLORS[index % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", color: "#f8fafc" }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-400">No incident data</div>
            )}
          </div>
          <div className="mt-2 flex flex-wrap justify-center gap-3 text-xs">
            {pieData.map((d, i) => (
              <div key={d.name} className="flex items-center gap-1.5">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: PIE_COLORS[i % PIE_COLORS.length] }}></span>
                <span className="text-slate-300 font-medium">{d.name} ({d.value})</span>
              </div>
            ))}
          </div>
        </div>

        {/* Severity Bar Chart */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <h2 className="text-sm font-semibold text-slate-200 tracking-wide mb-4">Severity Distribution</h2>
          <div className="h-56 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={severityData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} />
                <YAxis stroke="#64748b" fontSize={11} allowDecimals={false} />
                <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", color: "#f8fafc" }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Timeline Area Chart */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex flex-col justify-between">
          <h2 className="text-sm font-semibold text-slate-200 tracking-wide mb-4">Telemetry Event Density</h2>
          <div className="h-56 w-full">
            {timelineData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timelineData}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis dataKey="time" stroke="#64748b" fontSize={10} />
                  <YAxis stroke="#64748b" fontSize={10} />
                  <Tooltip contentStyle={{ backgroundColor: "#0f172a", borderColor: "#334155", color: "#f8fafc" }} />
                  <Area type="monotone" dataKey="severityScore" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.2} />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-slate-400">Waiting for live events...</div>
            )}
          </div>
        </div>
      </div>

      {/* Live Security Incidents / Alerts Table */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-base font-semibold text-slate-100">Correlated Security Incidents Feed</h2>
            <p className="text-xs text-slate-400">Showing incidents synthesized by sliding-window correlation engine</p>
          </div>
          <Link
            href="/incidents"
            className="text-xs font-semibold text-blue-400 hover:text-blue-300 flex items-center gap-1"
          >
            View All Reports <ArrowUpRight className="w-3.5 h-3.5" />
          </Link>
        </div>

        {incidents.length === 0 ? (
          <div className="py-8 text-center text-slate-400 text-sm">
            No active incidents. Run a scenario from the <Link href="/simulator" className="text-blue-400 underline">Attack Simulator</Link>.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-950/60 text-slate-400 uppercase tracking-wider font-semibold border-b border-slate-800">
                <tr>
                  <th className="py-3 px-4">Severity</th>
                  <th className="py-3 px-4">Incident Title & Category</th>
                  <th className="py-3 px-4">Sources</th>
                  <th className="py-3 px-4">Risk Score</th>
                  <th className="py-3 px-4">MITRE Mapping</th>
                  <th className="py-3 px-4 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {incidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4">
                      <SeverityBadge severity={inc.severity} />
                    </td>
                    <td className="py-3 px-4">
                      <div className="font-semibold text-slate-200">{inc.title}</div>
                      <div className="text-[11px] text-slate-400 font-mono mt-0.5">{inc.threat_category} • {inc.alerts.length} alert(s)</div>
                    </td>
                    <td className="py-3 px-4 font-mono text-slate-300">
                      {inc.source_entities.join(", ") || "Unknown"}
                    </td>
                    <td className="py-3 px-4 font-bold font-mono text-slate-200">
                      {inc.risk_score ? (
                        <span className={`px-2 py-0.5 rounded ${
                          inc.risk_score.total_score >= 76 ? "bg-red-500/20 text-red-400" :
                          inc.risk_score.total_score >= 51 ? "bg-orange-500/20 text-orange-400" : "bg-amber-500/20 text-amber-300"
                        }`}>
                          {inc.risk_score.total_score}/100
                        </span>
                      ) : (
                        "N/A"
                      )}
                    </td>
                    <td className="py-3 px-4">
                      {inc.mitre_mappings.length > 0 ? (
                        <span className="px-2 py-0.5 bg-blue-900/40 text-blue-300 border border-blue-700/50 rounded font-mono text-[11px]">
                          {inc.mitre_mappings[0].technique_id} ({inc.mitre_mappings[0].technique_name})
                        </span>
                      ) : (
                        "Unmapped"
                      )}
                    </td>
                    <td className="py-3 px-4 text-right">
                      <Link
                        href={`/investigation?incident_id=${inc.id}`}
                        className="inline-flex items-center gap-1 px-2.5 py-1 bg-blue-600 hover:bg-blue-500 text-white rounded font-medium transition-colors"
                      >
                        <span>Investigate</span>
                        <ArrowUpRight className="w-3 h-3" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
