"use client";

import { useState, useEffect, useMemo } from "react";
import {
  History,
  Search,
  Filter,
  ChevronDown,
  ChevronRight,
  Calendar,
  Loader2,
  Shield,
} from "lucide-react";
import type { ThreatLevel } from "@/lib/algorithms/types";
import { createBrowserClient } from "@/lib/supabase/client";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ScanRow {
  id: string;
  created_at: string;
  input_type: "url" | "text" | "screenshot";
  input_preview: string | null;
  score: number | null;
  category: string | null;
  threat_level: string | null;
  result_json: {
    evidence?: { finding: string; severity: string }[];
  } | null;
}

type ThreatFilter = "all" | ThreatLevel;

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [threatFilter, setThreatFilter] = useState<ThreatFilter>("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  useEffect(() => {
    const supabase = createBrowserClient();
    supabase
      .from("scans")
      .select("id, created_at, input_type, input_preview, score, category, threat_level, result_json")
      .order("created_at", { ascending: false })
      .limit(200)
      .then(({ data }) => {
        setScans((data as ScanRow[]) ?? []);
        setLoading(false);
      });
  }, []);

  const categories = useMemo(
    () => [...new Set(scans.map((s) => s.category).filter(Boolean) as string[])],
    [scans],
  );

  const levels: ThreatLevel[] = ["SAFE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

  const filtered = useMemo(() => {
    return scans.filter((scan) => {
      if (threatFilter !== "all" && scan.threat_level !== threatFilter) return false;
      if (categoryFilter !== "all" && scan.category !== categoryFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          (scan.input_preview ?? "").toLowerCase().includes(q) ||
          (scan.category ?? "").toLowerCase().includes(q) ||
          (scan.threat_level ?? "").toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [scans, search, threatFilter, categoryFilter]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-text-primary flex items-center gap-2">
          <History className="w-6 h-6 text-shield" />
          Scan History
        </h1>
        <p className="text-text-secondary text-sm mt-1">
          Review and search your past scans
        </p>
      </div>

      {loading ? (
        <div className="flex items-center gap-2 text-text-muted text-sm py-12 justify-center">
          <Loader2 size={16} className="animate-spin" />
          Loading history…
        </div>
      ) : scans.length === 0 ? (
        <div className="glass-card p-12 text-center space-y-2">
          <Shield className="w-10 h-10 text-shield mx-auto mb-3 opacity-40" />
          <p className="text-text-primary font-medium">No scan history yet</p>
          <p className="text-text-muted text-sm">
            Run your first scan from the home page — results will appear here.
          </p>
        </div>
      ) : (
        <>
          {/* Filters */}
          <div className="glass-card p-4 flex flex-wrap items-center gap-4">
            {/* Search */}
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
              <input
                type="text"
                placeholder="Search scans..."
                aria-label="Search scans"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="w-full pl-10 pr-4 py-2 bg-slate-deep border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-shield/50 transition-colors"
              />
            </div>

            {/* Threat Level Filter */}
            <div className="flex items-center gap-2">
              <Filter className="w-4 h-4 text-text-muted" />
              <select
                value={threatFilter}
                onChange={(e) => setThreatFilter(e.target.value as ThreatFilter)}
                aria-label="Filter by threat level"
                className="bg-slate-deep border border-border rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-shield/50"
              >
                <option value="all">All Levels</option>
                {levels.map((l) => (
                  <option key={l} value={l}>{l}</option>
                ))}
              </select>
            </div>

            {/* Category Filter */}
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              aria-label="Filter by category"
              className="bg-slate-deep border border-border rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-shield/50"
            >
              <option value="all">All Categories</option>
              {categories.map((c) => (
                <option key={c} value={c}>{c.replaceAll("_", " ")}</option>
              ))}
            </select>

            <button className="flex items-center gap-2 bg-slate-deep border border-border rounded-lg px-3 py-2 text-sm text-text-secondary hover:text-text-primary hover:border-shield/30 transition-colors">
              <Calendar className="w-4 h-4" />
              Date Range
            </button>
          </div>

          {/* Results count */}
          <p className="text-text-muted text-xs font-mono">
            Showing {filtered.length} of {scans.length} scans
          </p>

          {/* Scan List */}
          <div className="space-y-2">
            {filtered.length === 0 ? (
              <div className="glass-card p-12 text-center">
                <p className="text-text-muted">No scans match your filters.</p>
              </div>
            ) : (
              filtered.map((scan) => {
                const isExpanded = expandedId === scan.id;
                const evidence = scan.result_json?.evidence ?? [];

                return (
                  <div key={scan.id} className="glass-card overflow-hidden">
                    <button
                      onClick={() => setExpandedId(isExpanded ? null : scan.id)}
                      className="w-full flex items-center gap-4 px-5 py-4 text-left hover:bg-slate-deep/50 transition-colors"
                    >
                      <span className="text-text-muted shrink-0">
                        {isExpanded ? (
                          <ChevronDown className="w-4 h-4" />
                        ) : (
                          <ChevronRight className="w-4 h-4" />
                        )}
                      </span>

                      <span className="text-text-muted text-xs font-mono w-[140px] shrink-0">
                        {new Date(scan.created_at).toLocaleString()}
                      </span>

                      <TypeTag type={scan.input_type} />

                      <span className="text-text-secondary text-sm flex-1 truncate">
                        {scan.input_preview ?? "—"}
                      </span>

                      <ScoreIndicator score={scan.score ?? 0} />

                      <span className="text-text-muted text-xs font-mono w-[120px] text-right hidden md:block">
                        {scan.category?.replaceAll("_", " ") ?? "—"}
                      </span>

                      <LevelBadge level={(scan.threat_level as ThreatLevel) ?? "SAFE"} />
                    </button>

                    {isExpanded && (
                      <div className="px-5 pb-5 border-t border-border/50 pt-4">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                          <div>
                            <h3 className="text-xs font-mono text-text-muted uppercase tracking-wider mb-2">
                              Input Preview
                            </h3>
                            <p className="text-text-secondary text-sm bg-slate-deep rounded-lg p-3 font-mono break-all">
                              {scan.input_preview ?? "—"}
                            </p>
                          </div>

                          {evidence.length > 0 && (
                            <div>
                              <h3 className="text-xs font-mono text-text-muted uppercase tracking-wider mb-2">
                                Evidence
                              </h3>
                              <ul className="space-y-2">
                                {evidence.map((ev, i) => (
                                  <li key={i} className="flex items-start gap-2 text-sm">
                                    <SeverityDot severity={ev.severity} />
                                    <span className="text-text-secondary">{ev.finding}</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function TypeTag({ type }: { type: "url" | "text" | "screenshot" }) {
  const styles = {
    url: "bg-shield/10 text-shield border-shield/20",
    text: "bg-caution/10 text-caution border-caution/20",
    screenshot: "bg-safe/10 text-safe border-safe/20",
  };
  return (
    <span className={`shrink-0 inline-block px-2 py-0.5 text-[10px] font-mono uppercase rounded border ${styles[type]}`}>
      {type}
    </span>
  );
}

function ScoreIndicator({ score }: { score: number }) {
  let color = "text-safe";
  if (score > 80) color = "text-critical";
  else if (score > 60) color = "text-danger";
  else if (score > 30) color = "text-caution";
  return (
    <span className={`font-mono font-bold text-sm w-[40px] text-right shrink-0 ${color}`}>
      {score}
    </span>
  );
}

function LevelBadge({ level }: { level: ThreatLevel }) {
  const styles: Record<ThreatLevel, string> = {
    SAFE: "bg-safe/10 text-safe border-safe/20",
    LOW: "bg-safe/10 text-safe border-safe/20",
    MEDIUM: "bg-caution/10 text-caution border-caution/20",
    HIGH: "bg-danger/10 text-danger border-danger/20",
    CRITICAL: "bg-critical/10 text-critical border-critical/20",
  };
  return (
    <span className={`shrink-0 inline-block px-2 py-0.5 text-[10px] font-mono uppercase rounded border ${styles[level]}`}>
      {level}
    </span>
  );
}

function SeverityDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    low: "bg-safe",
    medium: "bg-caution",
    high: "bg-danger",
    critical: "bg-critical",
  };
  return (
    <span className={`w-2 h-2 rounded-full shrink-0 mt-1.5 ${colors[severity] ?? "bg-slate-light"}`} />
  );
}
