"use client";

import { useState, useEffect } from "react";
import {
  Shield,
  AlertTriangle,
  Activity,
  Target,
  Clock,
  Eye,
  ChevronDown,
  ChevronUp,
  Loader2,
  TrendingUp,
  Zap,
  Radio,
} from "lucide-react";
import type { ThreatCategory, ThreatLevel } from "@/lib/algorithms/types";
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
}

interface ThreatIntelData {
  trendingCategories: { category: string; velocity: number; count: number }[];
  emergingPatterns: { pattern: string; category: string; velocity: number; zScore: number }[];
  outbreaks: { pattern: string; category: string; velocity: number; zScore: number }[];
  predictions: { category: string; pattern: string; confidence: number; riskLevel: string }[];
  dataPointCount: number;
  message?: string;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function DashboardPage() {
  const [scans, setScans] = useState<ScanRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");
  const [intel, setIntel] = useState<ThreatIntelData | null>(null);
  const [intelLoading, setIntelLoading] = useState(true);

  useEffect(() => {
    const supabase = createBrowserClient();
    supabase
      .from("scans")
      .select("id, created_at, input_type, input_preview, score, category, threat_level")
      .order("created_at", { ascending: false })
      .limit(50)
      .then(({ data }) => {
        setScans((data as ScanRow[]) ?? []);
        setLoading(false);
      });

    fetch("/api/threat-intel")
      .then((r) => r.json())
      .then((d) => setIntel(d))
      .catch(() => setIntel(null))
      .finally(() => setIntelLoading(false));
  }, []);

  // Derived stats
  const total = scans.length;
  const threats = scans.filter((s) => s.threat_level && !["SAFE", "LOW"].includes(s.threat_level)).length;
  const avgScore =
    total > 0
      ? Math.round(scans.reduce((sum, s) => sum + (s.score ?? 0), 0) / total)
      : 0;

  // Threat distribution
  const catCounts: Record<string, number> = {};
  for (const s of scans) {
    if (s.category) catCounts[s.category] = (catCounts[s.category] ?? 0) + 1;
  }
  const distribution = Object.entries(catCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);
  const maxCount = distribution.length > 0 ? distribution[0][1] : 1;

  const topThreat =
    distribution.length > 0
      ? distribution[0][0].replaceAll("_", " ")
      : "—";

  const sortedScans = [...scans]
    .sort((a, b) =>
      sortDir === "desc"
        ? (b.score ?? 0) - (a.score ?? 0)
        : (a.score ?? 0) - (b.score ?? 0),
    )
    .slice(0, 20);

  return (
    <div className="space-y-8">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-text-primary flex items-center gap-2">
          <Activity className="w-6 h-6 text-shield" />
          Dashboard
        </h1>
        <p className="text-text-secondary text-sm mt-1">
          Real-time overview of scan activity and threat detection
        </p>
      </div>

      {loading ? (
        <div className="flex items-center gap-2 text-text-muted text-sm py-12 justify-center">
          <Loader2 size={16} className="animate-spin" />
          Loading scan data…
        </div>
      ) : total === 0 ? (
        <div className="glass-card p-12 text-center space-y-2">
          <Shield className="w-10 h-10 text-shield mx-auto mb-3 opacity-40" />
          <p className="text-text-primary font-medium">No scans yet</p>
          <p className="text-text-muted text-sm">
            Run your first scan from the home page — results will appear here.
          </p>
        </div>
      ) : (
        <>
          {/* Stat Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4" data-tour="dashboard-stats">
            <DashStatCard
              icon={<Eye className="w-5 h-5" />}
              label="Total Scans"
              value={total.toString()}
              detail="your history"
              accent="shield"
            />
            <DashStatCard
              icon={<AlertTriangle className="w-5 h-5" />}
              label="Threats Detected"
              value={threats.toString()}
              detail={`${total > 0 ? Math.round((threats / total) * 100) : 0}% detection rate`}
              accent="danger"
            />
            <DashStatCard
              icon={<Target className="w-5 h-5" />}
              label="Avg Threat Score"
              value={avgScore.toString()}
              detail="out of 100"
              accent="caution"
            />
            <DashStatCard
              icon={<Shield className="w-5 h-5" />}
              label="Top Threat"
              value={topThreat}
              detail={distribution.length > 0 ? `${distribution[0][1]} instances` : "—"}
              accent="critical"
            />
          </div>

          {/* Two-column layout: table + chart */}
          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            {/* Recent Scans Table */}
            <div className="xl:col-span-2 glass-card p-0 overflow-hidden" data-tour="recent-scans">
              <div className="px-5 py-4 border-b border-border flex items-center justify-between">
                <h2 className="font-semibold text-text-primary flex items-center gap-2">
                  <Clock className="w-4 h-4 text-shield" />
                  Recent Scans
                </h2>
                <button
                  onClick={() => setSortDir((d) => (d === "desc" ? "asc" : "desc"))}
                  className="text-text-muted hover:text-text-secondary text-xs font-mono flex items-center gap-1 transition-colors"
                >
                  Score
                  {sortDir === "desc" ? (
                    <ChevronDown className="w-3 h-3" />
                  ) : (
                    <ChevronUp className="w-3 h-3" />
                  )}
                </button>
              </div>

              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-text-muted text-xs font-mono uppercase tracking-wider border-b border-border">
                      <th className="text-left px-5 py-3">Time</th>
                      <th className="text-left px-5 py-3">Input</th>
                      <th className="text-left px-5 py-3">Score</th>
                      <th className="text-left px-5 py-3">Category</th>
                      <th className="text-left px-5 py-3">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sortedScans.map((scan) => (
                      <tr
                        key={scan.id}
                        className="border-b border-border/50 hover:bg-slate-deep/50 transition-colors"
                      >
                        <td className="px-5 py-3 text-text-muted font-mono text-xs whitespace-nowrap">
                          {relativeTime(scan.created_at)}
                        </td>
                        <td className="px-5 py-3 text-text-secondary max-w-[250px] truncate">
                          <span className="inline-flex items-center gap-2">
                            <TypeBadge type={scan.input_type} />
                            {scan.input_preview ?? "—"}
                          </span>
                        </td>
                        <td className="px-5 py-3">
                          <ScoreBadge score={scan.score ?? 0} />
                        </td>
                        <td className="px-5 py-3 text-text-secondary font-mono text-xs">
                          {scan.category?.replaceAll("_", " ") ?? "—"}
                        </td>
                        <td className="px-5 py-3">
                          <ThreatBadge level={(scan.threat_level as ThreatLevel) ?? "SAFE"} />
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Threat Distribution Chart */}
            <div className="glass-card p-5" data-tour="threat-distribution">
              <h2 className="font-semibold text-text-primary mb-5 flex items-center gap-2">
                <Target className="w-4 h-4 text-shield" />
                Threat Distribution
              </h2>

              {distribution.length === 0 ? (
                <p className="text-text-muted text-sm">No data yet.</p>
              ) : (
                <div className="space-y-3">
                  {distribution.map(([cat, count]) => (
                    <div key={cat}>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-text-secondary">{cat.replaceAll("_", " ")}</span>
                        <span className="text-text-muted font-mono">{count}</span>
                      </div>
                      <div className="w-full h-2 bg-slate-deep rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full bg-shield transition-all duration-700"
                          style={{ width: `${(count / maxCount) * 100}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              )}

              <div className="mt-6 pt-4 border-t border-border">
                <p className="text-text-muted text-xs font-mono">
                  Total threats: {threats}
                </p>
              </div>
            </div>
          </div>

          {/* Live Threat Intelligence */}
          <div className="glass-card p-5">
            <div className="flex items-center gap-2 mb-5">
              <TrendingUp className="w-4 h-4 text-shield" />
              <h2 className="font-semibold text-text-primary">Live Threat Intelligence</h2>
              <span className="ml-auto text-[10px] font-mono text-text-muted">7-day window · refreshes every 5 min</span>
            </div>

            {intelLoading ? (
              <div className="flex items-center gap-2 text-text-muted text-sm py-4">
                <Loader2 size={14} className="animate-spin" />
                Analyzing patterns…
              </div>
            ) : !intel || intel.message ? (
              <p className="text-text-muted text-sm">{intel?.message ?? "No data available."}</p>
            ) : (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">

                {/* Trending Categories */}
                {intel.trendingCategories.length > 0 && (
                  <div data-tour="trending-categories">
                    <div className="flex items-center gap-1.5 mb-3">
                      <Activity size={12} className="text-caution" />
                      <span className="text-xs font-medium text-text-muted uppercase tracking-wider">Trending</span>
                    </div>
                    <div className="space-y-2">
                      {intel.trendingCategories.slice(0, 5).map((cat, i) => (
                        <div key={cat.category} className="flex items-center gap-2">
                          <span className="text-[10px] font-mono text-text-muted w-3">{i + 1}</span>
                          <div className="flex-1 min-w-0">
                            <div className="flex justify-between text-xs mb-0.5">
                              <span className="text-text-secondary truncate">{cat.category.replace(/_/g, " ")}</span>
                              <span className="text-text-muted font-mono">{cat.count}</span>
                            </div>
                            <div className="h-1 bg-slate-deep rounded-full overflow-hidden">
                              <div
                                className="h-full rounded-full bg-caution/70"
                                style={{ width: `${Math.min(100, cat.velocity * 25)}%` }}
                              />
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Outbreaks */}
                {intel.outbreaks.length > 0 && (
                  <div data-tour="active-outbreaks">
                    <div className="flex items-center gap-1.5 mb-3">
                      <Radio size={12} className="text-danger" />
                      <span className="text-xs font-medium text-text-muted uppercase tracking-wider">Active Outbreaks</span>
                    </div>
                    <div className="space-y-2">
                      {intel.outbreaks.map((ob) => (
                        <div key={ob.pattern} className="px-3 py-2 rounded-lg bg-danger/5 border border-danger/15">
                          <div className="text-xs font-medium text-danger truncate">{ob.pattern.replace(/-/g, " ").toUpperCase()}</div>
                          <div className="text-[10px] font-mono text-text-muted mt-0.5">
                            z-score: {ob.zScore} · vel: {ob.velocity}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Predictions */}
                {intel.predictions.length > 0 && (
                  <div data-tour="predictions">
                    <div className="flex items-center gap-1.5 mb-3">
                      <Zap size={12} className="text-shield" />
                      <span className="text-xs font-medium text-text-muted uppercase tracking-wider">Next Wave</span>
                    </div>
                    <div className="space-y-2">
                      {intel.predictions.map((pred) => (
                        <div key={pred.pattern} className="px-3 py-2 rounded-lg bg-shield/5 border border-shield/15">
                          <div className="flex items-center justify-between gap-2 mb-0.5">
                            <span className="text-xs text-text-secondary truncate">{pred.category.replace(/_/g, " ")}</span>
                            <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                              pred.riskLevel === "CRITICAL" ? "bg-critical/10 text-critical border-critical/20" :
                              pred.riskLevel === "HIGH"     ? "bg-danger/10 text-danger border-danger/20" :
                              "bg-caution/10 text-caution border-caution/20"
                            }`}>{pred.riskLevel}</span>
                          </div>
                          <div className="text-[10px] font-mono text-text-muted">
                            {Math.round(pred.confidence * 100)}% confidence
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {intel.trendingCategories.length === 0 && intel.outbreaks.length === 0 && intel.predictions.length === 0 && (
                  <div className="col-span-3 text-text-muted text-sm text-center py-4">
                    Patterns are still accumulating — check back after more scans are processed.
                  </div>
                )}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs} hr ago`;
  return `${Math.floor(hrs / 24)} d ago`;
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function DashStatCard({
  icon,
  label,
  value,
  detail,
  accent,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  detail: string;
  accent: "shield" | "danger" | "caution" | "critical";
}) {
  const accentMap = {
    shield: "text-shield border-shield/20 bg-shield/5",
    danger: "text-danger border-danger/20 bg-danger/5",
    caution: "text-caution border-caution/20 bg-caution/5",
    critical: "text-critical border-critical/20 bg-critical/5",
  };

  return (
    <div className="glass-card p-5 hover:border-shield/20 transition-all duration-300">
      <div className={`inline-flex items-center justify-center w-10 h-10 rounded-lg border ${accentMap[accent]} mb-3`}>
        {icon}
      </div>
      <p className="text-text-muted text-xs font-mono uppercase tracking-wider mb-1">{label}</p>
      <p className="text-2xl font-bold font-mono text-text-primary">{value}</p>
      <p className="text-text-muted text-xs mt-1">{detail}</p>
    </div>
  );
}

function TypeBadge({ type }: { type: "url" | "text" | "screenshot" }) {
  const styles = {
    url: "bg-shield/10 text-shield border-shield/20",
    text: "bg-caution/10 text-caution border-caution/20",
    screenshot: "bg-safe/10 text-safe border-safe/20",
  };

  return (
    <span className={`inline-block px-1.5 py-0.5 text-[10px] font-mono uppercase rounded border ${styles[type]}`}>
      {type}
    </span>
  );
}

function ScoreBadge({ score }: { score: number }) {
  let color = "text-safe";
  if (score > 80) color = "text-critical";
  else if (score > 60) color = "text-danger";
  else if (score > 30) color = "text-caution";

  return <span className={`font-mono font-bold ${color}`}>{score}</span>;
}

function ThreatBadge({ level }: { level: ThreatLevel }) {
  const styles: Record<ThreatLevel, string> = {
    SAFE: "bg-safe/10 text-safe border-safe/20",
    LOW: "bg-safe/10 text-safe border-safe/20",
    MEDIUM: "bg-caution/10 text-caution border-caution/20",
    HIGH: "bg-danger/10 text-danger border-danger/20",
    CRITICAL: "bg-critical/10 text-critical border-critical/20",
  };

  return (
    <span className={`inline-block px-2 py-0.5 text-[10px] font-mono uppercase rounded border ${styles[level]}`}>
      {level}
    </span>
  );
}
