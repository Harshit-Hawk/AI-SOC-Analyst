import React from "react";

interface Props {
  severity: string;
  className?: string;
}

export const SeverityBadge: React.FC<Props> = ({ severity, className = "" }) => {
  const s = severity.toUpperCase();
  let bg = "bg-slate-700/50 text-slate-300 border-slate-600";
  
  if (s === "CRITICAL") {
    bg = "bg-red-500/20 text-red-400 border-red-500/40 shadow-sm shadow-red-950";
  } else if (s === "HIGH") {
    bg = "bg-orange-500/20 text-orange-400 border-orange-500/40";
  } else if (s === "MEDIUM") {
    bg = "bg-amber-500/20 text-amber-300 border-amber-500/40";
  } else if (s === "LOW") {
    bg = "bg-emerald-500/20 text-emerald-400 border-emerald-500/40";
  }

  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-md text-xs font-semibold uppercase tracking-wider border ${bg} ${className}`}>
      {s}
    </span>
  );
};
