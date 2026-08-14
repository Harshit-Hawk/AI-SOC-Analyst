"use client";

import React, { useEffect, useState } from "react";
import { fetchIncidents, SecurityIncident, API_BASE_URL } from "@/lib/api";
import { SeverityBadge } from "@/components/SeverityBadge";
import { 
  FileText, 
  Search, 
  Download, 
  Printer, 
  Filter, 
  ExternalLink,
  ChevronRight
} from "lucide-react";

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<SecurityIncident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<SecurityIncident | null>(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [loading, setLoading] = useState(true);
  const [reportMarkdown, setReportMarkdown] = useState<string>("");

  const loadIncidents = async () => {
    setLoading(true);
    const data = await fetchIncidents(severityFilter || undefined, undefined, search || undefined);
    setIncidents(data);
    if (data.length > 0 && (!selectedIncident || !data.some(i => i.id === selectedIncident.id))) {
      setSelectedIncident(data[0]);
    }
    setLoading(false);
  };

  useEffect(() => {
    loadIncidents();
  }, [search, severityFilter]);

  useEffect(() => {
    if (selectedIncident) {
      fetch(`${API_BASE_URL}/incidents/${selectedIncident.id}/report?format=markdown`)
        .then(r => r.text())
        .then(text => setReportMarkdown(text))
        .catch(() => setReportMarkdown("Error fetching report markdown"));
    }
  }, [selectedIncident]);

  const downloadFile = (filename: string, content: string, type: string) => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  const handleExportMarkdown = () => {
    if (!selectedIncident) return;
    downloadFile(`Incident_Report_${selectedIncident.id}.md`, reportMarkdown, "text/markdown");
  };

  const handleExportJSON = () => {
    if (!selectedIncident) return;
    downloadFile(`Incident_Telemetry_${selectedIncident.id}.json`, JSON.stringify(selectedIncident, null, 2), "application/json");
  };

  const handlePrintHTML = () => {
    if (!selectedIncident) return;
    window.open(`${API_BASE_URL}/incidents/${selectedIncident.id}/report?format=html`, "_blank");
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-slate-100 tracking-tight flex items-center gap-2">
          <FileText className="w-6 h-6 text-blue-400" />
          <span>Incident Reports & Compliance Export</span>
        </h1>
        <p className="text-sm text-slate-400">Filter, review, and export forensic incident reports in Markdown, JSON, and PDF formats.</p>
      </div>

      {/* Filters Bar */}
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row gap-4 items-center justify-between">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search title, category, or IP..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-4 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex items-center gap-3 w-full md:w-auto">
          <Filter className="w-4 h-4 text-slate-400" />
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-slate-300 text-xs rounded-lg px-3 py-1.5 focus:outline-none focus:border-blue-500"
          >
            <option value="">All Severities</option>
            <option value="CRITICAL">CRITICAL</option>
            <option value="HIGH">HIGH</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="LOW">LOW</option>
          </select>
        </div>
      </div>

      {/* Main Split View */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[calc(100vh-16rem)]">
        {/* Incident Table / List */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 overflow-y-auto space-y-2">
          <h2 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2">Filtered Incidents ({incidents.length})</h2>

          {incidents.length === 0 ? (
            <div className="text-xs text-slate-400 py-8 text-center">No matching incidents.</div>
          ) : (
            incidents.map((inc) => {
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
                  <div className="flex items-center justify-between mb-1">
                    <SeverityBadge severity={inc.severity} />
                    <span className="font-mono text-[10px] text-slate-400">
                      {new Date(inc.created_at).toLocaleDateString()}
                    </span>
                  </div>
                  <div className="font-semibold line-clamp-1">{inc.title}</div>
                  <div className="text-[11px] text-slate-400 mt-1 font-mono">
                    Category: {inc.threat_category}
                  </div>
                </button>
              );
            })
          )}
        </div>

        {/* Report Preview Canvas */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col overflow-y-auto">
          {!selectedIncident ? (
            <div className="h-full flex items-center justify-center text-slate-400 text-sm">
              Select an incident to view and export report.
            </div>
          ) : (
            <div className="space-y-4">
              {/* Report Controls Toolbar */}
              <div className="flex items-center justify-between pb-4 border-b border-slate-800">
                <div>
                  <h2 className="text-base font-bold text-slate-100">{selectedIncident.title}</h2>
                  <p className="text-xs text-slate-400 font-mono">ID: {selectedIncident.id}</p>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    onClick={handleExportMarkdown}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg border border-slate-700 transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>Markdown</span>
                  </button>

                  <button
                    onClick={handleExportJSON}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium rounded-lg border border-slate-700 transition-colors"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>JSON</span>
                  </button>

                  <button
                    onClick={handlePrintHTML}
                    className="flex items-center gap-1.5 px-3 py-1.5 bg-blue-600 hover:bg-blue-500 text-white text-xs font-semibold rounded-lg shadow transition-colors"
                  >
                    <Printer className="w-3.5 h-3.5" />
                    <span>Printable HTML/PDF</span>
                  </button>
                </div>
              </div>

              {/* Report Markdown Container */}
              <div className="bg-slate-950/80 border border-slate-800 rounded-lg p-6 font-mono text-xs text-slate-300 whitespace-pre-wrap leading-relaxed overflow-x-auto max-h-[calc(100vh-24rem)]">
                {reportMarkdown}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
