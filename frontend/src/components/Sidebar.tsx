"use client";

import React from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { 
  ShieldAlert, 
  Search, 
  Zap, 
  FileText, 
  BarChart3, 
  Activity,
  Cpu
} from "lucide-react";

export const Sidebar: React.FC = () => {
  const pathname = usePathname();

  const navItems = [
    { name: "SOC Overview", href: "/", icon: Activity },
    { name: "Alert Investigation", href: "/investigation", icon: Search },
    { name: "Attack Simulator", href: "/simulator", icon: Zap },
    { name: "Incident Reports", href: "/incidents", icon: FileText },
    { name: "Engine Benchmark", href: "/benchmark", icon: BarChart3 },
  ];

  return (
    <aside className="w-64 bg-slate-900 border-r border-slate-800 flex flex-col h-screen shrink-0 sticky top-0">
      {/* Brand Header */}
      <div className="p-5 border-b border-slate-800 flex items-center gap-3">
        <div className="p-2 bg-blue-600/20 border border-blue-500/40 rounded-lg text-blue-400">
          <ShieldAlert className="w-6 h-6" />
        </div>
        <div>
          <h1 className="font-bold text-slate-100 tracking-wide text-sm">AI SOC ANALYST</h1>
          <p className="text-xs text-slate-400 font-mono">v1.0 • Defense Ops</p>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 p-4 space-y-1 overflow-y-auto">
        <div className="px-3 py-2 text-[10px] font-semibold text-slate-400 uppercase tracking-wider">
          Command Center
        </div>

        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = pathname === item.href;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                isActive
                  ? "bg-blue-600/15 text-blue-400 border border-blue-500/30 shadow-sm"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/60"
              }`}
            >
              <Icon className={`w-4 h-4 ${isActive ? "text-blue-400" : "text-slate-400"}`} />
              <span>{item.name}</span>
            </Link>
          );
        })}
      </nav>

      {/* Pipeline Status Indicator */}
      <div className="p-4 border-t border-slate-800 bg-slate-950/40">
        <div className="flex items-center gap-2 text-xs text-slate-400">
          <Cpu className="w-4 h-4 text-emerald-400 animate-pulse" />
          <span>Pipeline: <strong className="text-emerald-400">Active</strong></span>
        </div>
        <p className="text-[11px] text-slate-400 mt-1 font-mono">
          Detection: Rule + ML Engine
        </p>
      </div>
    </aside>
  );
};
