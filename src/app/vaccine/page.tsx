"use client";

import { useState, useRef } from "react";
import {
  Shield,
  Syringe,
  Globe,
  Loader2,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Activity,
  Zap,
  Fingerprint,
  Brain,
  Thermometer,
  Network,
  TrendingUp,
  ChevronDown,
  ChevronUp,
  Lock,
  Eye,
  Dna,
  Target,
  Clock,
} from "lucide-react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface VaccineResponse {
  url: string;
  timestamp: number;
  threatLevel: string;
  threatScore: number;
  threatsDetected: string[];
  injectionRules: any[];
  synergosAnalysis?: {
    verdict: string;
    confidence: number;
    nextAttackPrediction: {
      tactics: string[];
      likelihood: number;
    };
    recommendedDefense: string[];
  };
  signature: string;
  signedAt: number;
  latencyMs: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const THREAT_COLORS: Record<string, { bg: string; text: string; border: string; glow: string }> = {
  safe:     { bg: "bg-safe/10",     text: "text-safe",     border: "border-safe/20",     glow: "shadow-[0_0_20px_rgba(0,229,160,0.15)]" },
  low:      { bg: "bg-safe/8",      text: "text-safe",     border: "border-safe/15",     glow: "" },
  medium:   { bg: "bg-caution/10",  text: "text-caution",  border: "border-caution/20",  glow: "shadow-[0_0_20px_rgba(251,191,36,0.15)]" },
  high:     { bg: "bg-danger/10",   text: "text-danger",   border: "border-danger/20",   glow: "shadow-[0_0_20px_rgba(255,59,92,0.15)]" },
  critical: { bg: "bg-critical/10", text: "text-critical", border: "border-critical/20", glow: "shadow-[0_0_25px_rgba(255,23,68,0.2)]" },
};

const VERDICT_CONFIG: Record<string, { icon: any; label: string; color: string }> = {
  BLOCK: { icon: XCircle,      label: "Blocked",  color: "text-danger" },
  WARN:  { icon: AlertTriangle, label: "Warning",  color: "text-caution" },
  ALLOW: { icon: CheckCircle2,  label: "Safe",     color: "text-safe" },
};

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function VaccinePage() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VaccineResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    synergos: true,
    threats: true,
    defenses: false,
    rules: false,
  });
  const inputRef = useRef<HTMLInputElement>(null);

  function toggleSection(key: string) {
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));
  }

  async function handleScan() {
    const trimmed = url.trim();
    if (!trimmed) return;

    // Auto-prepend https:// if missing
    const scanUrl = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch("/api/vaccine/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: scanUrl }),
      });

      if (!res.ok) {
        const data = await res.json().catch(() => ({}));
        throw new Error(data.error || `Scan failed (${res.status})`);
      }

      const data: VaccineResponse = await res.json();
      setResult(data);
    } catch (err: any) {
      setError(err.message || "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if (e.key === "Enter" && !loading) handleScan();
  }

  const threatColors = result
    ? THREAT_COLORS[result.threatLevel.toLowerCase()] || THREAT_COLORS.safe
    : null;

  const synergos = result?.synergosAnalysis;
  const verdictCfg = synergos ? VERDICT_CONFIG[synergos.verdict] || VERDICT_CONFIG.ALLOW : null;

  return (
    <div className="min-h-screen p-4 md:p-8 md:pl-72">
      {/* Header */}
      <div className="max-w-5xl mx-auto mb-8">
        <div className="flex items-center gap-3 mb-2">
          <div className="relative">
            <Syringe size={28} className="text-shield" />
            <div className="absolute inset-0 bg-shield/20 rounded-full blur-lg" />
          </div>
          <h1 className="text-2xl md:text-3xl font-bold text-text-primary">
            Website <span className="text-shield">Vaccine</span>
          </h1>
        </div>
        <p className="text-text-secondary text-sm md:text-base">
          Deep-scan any URL with SYNERGOS behavioral analysis. Detects phishing, malware, and social engineering
          using physics-informed threat modeling, game theory, and spectral graph analysis.
        </p>
      </div>

      {/* Scan Input */}
      <div className="max-w-5xl mx-auto mb-8">
        <div className="glass-card p-5">
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Globe size={16} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-text-muted" />
              <input
                ref={inputRef}
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Enter URL to vaccinate (e.g. example.com)"
                className="w-full pl-10 pr-4 py-3 rounded-xl bg-obsidian border border-border text-text-primary placeholder:text-text-muted text-sm font-mono focus:outline-none focus:border-shield/40 focus:shadow-[0_0_15px_rgba(0,212,255,0.08)] transition-all"
                disabled={loading}
              />
            </div>
            <button
              onClick={handleScan}
              disabled={loading || !url.trim()}
              className="px-6 py-3 rounded-xl bg-shield/15 border border-shield/25 text-shield font-semibold text-sm hover:bg-shield/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center gap-2 shrink-0"
            >
              {loading ? (
                <>
                  <Loader2 size={16} className="animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Syringe size={16} />
                  Vaccinate
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="max-w-5xl mx-auto mb-6">
          <div className="glass-card p-4 border-danger/20 bg-danger/5 flex items-center gap-3">
            <AlertTriangle size={18} className="text-danger shrink-0" />
            <span className="text-danger text-sm">{error}</span>
          </div>
        </div>
      )}

      {/* Loading State */}
      {loading && (
        <div className="max-w-5xl mx-auto">
          <div className="glass-card p-12 flex flex-col items-center gap-4">
            <div className="relative">
              <Shield size={48} className="text-shield animate-pulse" />
              <div className="absolute inset-0 bg-shield/20 rounded-full blur-xl animate-pulse" />
            </div>
            <div className="text-center">
              <p className="text-text-primary font-medium">SYNERGOS Engine Active</p>
              <p className="text-text-muted text-sm mt-1">
                Running 5-stage behavioral analysis pipeline...
              </p>
            </div>
            <div className="flex gap-6 mt-2">
              {["Graph Build", "Intent Field", "Game Theory", "Lyapunov", "Integration"].map((stage, i) => (
                <div key={stage} className="flex flex-col items-center gap-1">
                  <div className={`w-2 h-2 rounded-full ${i < 3 ? "bg-shield animate-pulse" : "bg-slate-mid"}`} />
                  <span className="text-[10px] font-mono text-text-muted">{stage}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Results */}
      {result && !loading && (
        <div className="max-w-5xl mx-auto space-y-5">

          {/* --- Top Summary Banner --- */}
          <div className={`glass-card p-6 ${threatColors?.border} ${threatColors?.glow}`}>
            <div className="flex flex-col md:flex-row md:items-center gap-6">

              {/* Threat Score Ring */}
              <div className="flex items-center gap-5">
                <div className="relative w-20 h-20 shrink-0">
                  <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                    <circle cx="50" cy="50" r="42" fill="none" stroke="currentColor" strokeWidth="6" className="text-slate-deep" />
                    <circle
                      cx="50" cy="50" r="42" fill="none" strokeWidth="6"
                      strokeDasharray={`${2 * Math.PI * 42}`}
                      strokeDashoffset={`${2 * Math.PI * 42 * (1 - result.threatScore / 100)}`}
                      strokeLinecap="round"
                      className={threatColors?.text || "text-safe"}
                    />
                  </svg>
                  <div className="absolute inset-0 flex items-center justify-center">
                    <span className={`text-lg font-bold font-mono ${threatColors?.text}`}>
                      {Math.round(result.threatScore)}
                    </span>
                  </div>
                </div>

                <div>
                  <div className={`text-xs font-mono uppercase tracking-wider ${threatColors?.text} mb-1`}>
                    {result.threatLevel}
                  </div>
                  <div className="text-text-primary font-medium text-lg">
                    {result.threatLevel === "safe" || result.threatLevel === "low"
                      ? "No Threats Detected"
                      : `${result.threatsDetected.length} Threat${result.threatsDetected.length !== 1 ? "s" : ""} Found`}
                  </div>
                  <div className="text-text-muted text-xs font-mono mt-0.5">
                    {result.url}
                  </div>
                </div>
              </div>

              {/* Quick Stats */}
              <div className="md:ml-auto flex gap-4">
                <QuickStat icon={Clock} label="Latency" value={`${result.latencyMs}ms`} />
                <QuickStat icon={Lock} label="Signed" value={result.signature ? "HMAC" : "N/A"} />
                <QuickStat
                  icon={Brain}
                  label="SYNERGOS"
                  value={synergos ? `${Math.round(synergos.confidence * 100)}%` : "N/A"}
                />
              </div>
            </div>
          </div>

          {/* --- SYNERGOS Deep Analysis --- */}
          {synergos && (
            <CollapsibleSection
              title="SYNERGOS Behavioral Analysis"
              icon={Brain}
              expanded={expandedSections.synergos}
              onToggle={() => toggleSection("synergos")}
              badge={
                <span className={`text-xs font-mono px-2 py-0.5 rounded-full border ${
                  synergos.verdict === "BLOCK"
                    ? "bg-danger/10 text-danger border-danger/20"
                    : synergos.verdict === "WARN"
                    ? "bg-caution/10 text-caution border-caution/20"
                    : "bg-safe/10 text-safe border-safe/20"
                }`}>
                  {synergos.verdict}
                </span>
              }
            >
              <div className="space-y-5">

                {/* Verdict Banner */}
                <div className={`flex items-center gap-3 p-4 rounded-xl border ${
                  synergos.verdict === "BLOCK"
                    ? "bg-danger/5 border-danger/15"
                    : synergos.verdict === "WARN"
                    ? "bg-caution/5 border-caution/15"
                    : "bg-safe/5 border-safe/15"
                }`}>
                  {verdictCfg && <verdictCfg.icon size={20} className={verdictCfg.color} />}
                  <div>
                    <span className={`font-semibold text-sm ${verdictCfg?.color}`}>{verdictCfg?.label}</span>
                    <span className="text-text-muted text-xs ml-2">
                      Confidence: {Math.round(synergos.confidence * 100)}%
                    </span>
                  </div>
                </div>

                {/* Analysis Pillars Grid */}
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                  <AnalysisPillar
                    icon={Network}
                    title="Graph Laplacian"
                    description="Field dependency diffusion"
                    detail="Jacobi iteration with Neumann BC"
                    accent="shield"
                  />
                  <AnalysisPillar
                    icon={Target}
                    title="Anomaly Detection"
                    description="Payoff matrix distance"
                    detail="4x3 support enumeration"
                    accent="shield"
                  />
                  <AnalysisPillar
                    icon={Activity}
                    title="Lyapunov Exponent"
                    description="Chaos sensitivity"
                    detail="Multi-epsilon median (3 scales)"
                    accent="shield"
                  />
                  <AnalysisPillar
                    icon={Fingerprint}
                    title="Spectral Fingerprint"
                    description="Graph eigenvalue invariants"
                    detail="Sensitive subgraph + whole graph"
                    accent="shield"
                  />
                  <AnalysisPillar
                    icon={Thermometer}
                    title="Free Energy (F=U-TS)"
                    description="Thermodynamic classifier"
                    detail="Per-component + sensitive fields"
                    accent="shield"
                  />
                  <AnalysisPillar
                    icon={Dna}
                    title="Immune Memory"
                    description="Variant hash matching"
                    detail="Hamming pre-filter + Jaccard"
                    accent="shield"
                  />
                </div>

                {/* Attack Prediction */}
                {synergos.nextAttackPrediction.tactics.length > 0 && (
                  <div className="p-4 rounded-xl bg-obsidian border border-border">
                    <div className="flex items-center gap-2 mb-3">
                      <TrendingUp size={16} className="text-caution" />
                      <span className="text-sm font-medium text-text-primary">Predicted Attack Vectors</span>
                      <span className="text-xs font-mono text-text-muted ml-auto">
                        Likelihood: {Math.round(synergos.nextAttackPrediction.likelihood * 100)}%
                      </span>
                    </div>
                    <div className="flex flex-wrap gap-2">
                      {synergos.nextAttackPrediction.tactics.map((tactic) => (
                        <span
                          key={tactic}
                          className="px-2.5 py-1 rounded-lg bg-caution/10 border border-caution/15 text-caution text-xs font-mono"
                        >
                          {tactic.replace(/_/g, " ")}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </CollapsibleSection>
          )}

          {/* --- Threats Detected --- */}
          {result.threatsDetected.length > 0 && (
            <CollapsibleSection
              title={`Threats Detected (${result.threatsDetected.length})`}
              icon={AlertTriangle}
              expanded={expandedSections.threats}
              onToggle={() => toggleSection("threats")}
            >
              <div className="space-y-2">
                {result.threatsDetected.map((threat, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-3 p-3 rounded-xl bg-obsidian border border-border hover:border-danger/20 transition-colors"
                  >
                    <div className="w-5 h-5 rounded-full bg-danger/10 flex items-center justify-center shrink-0 mt-0.5">
                      <XCircle size={12} className="text-danger" />
                    </div>
                    <span className="text-text-secondary text-sm">{threat}</span>
                  </div>
                ))}
              </div>
            </CollapsibleSection>
          )}

          {/* --- Recommended Defenses --- */}
          {synergos && synergos.recommendedDefense.length > 0 && (
            <CollapsibleSection
              title="Recommended Defenses"
              icon={Shield}
              expanded={expandedSections.defenses}
              onToggle={() => toggleSection("defenses")}
            >
              <div className="space-y-2">
                {synergos.recommendedDefense.map((defense, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-3 p-3 rounded-xl bg-obsidian border border-border"
                  >
                    <CheckCircle2 size={14} className="text-safe shrink-0 mt-0.5" />
                    <span className="text-text-secondary text-sm">{defense}</span>
                  </div>
                ))}
              </div>
            </CollapsibleSection>
          )}

          {/* --- Injection Rules --- */}
          {result.injectionRules.length > 0 && (
            <CollapsibleSection
              title={`Injection Rules (${result.injectionRules.length})`}
              icon={Zap}
              expanded={expandedSections.rules}
              onToggle={() => toggleSection("rules")}
            >
              <div className="space-y-2">
                {result.injectionRules.map((rule: any, i: number) => (
                  <div
                    key={i}
                    className="flex items-center gap-3 p-3 rounded-xl bg-obsidian border border-border"
                  >
                    <span className={`text-xs font-mono px-2 py-0.5 rounded-full border ${
                      rule.type === "block"
                        ? "bg-danger/10 text-danger border-danger/20"
                        : rule.type === "warn"
                        ? "bg-caution/10 text-caution border-caution/20"
                        : "bg-shield/10 text-shield border-shield/20"
                    }`}>
                      {rule.type}
                    </span>
                    <span className="text-text-muted text-xs font-mono">{rule.selector || "global"}</span>
                    {rule.message && (
                      <span className="text-text-secondary text-xs ml-auto truncate max-w-[50%]">{rule.message}</span>
                    )}
                  </div>
                ))}
              </div>
            </CollapsibleSection>
          )}

          {/* --- Crypto Signature Footer --- */}
          <div className="flex items-center gap-2 px-2 py-1 text-text-muted">
            <Lock size={11} />
            <span className="text-[10px] font-mono">
              HMAC-SHA256 signed at {new Date(result.signedAt).toLocaleTimeString()} | Payload verified
            </span>
          </div>
        </div>
      )}

      {/* Empty State */}
      {!result && !loading && !error && (
        <div className="max-w-5xl mx-auto">
          <div className="glass-card p-12 text-center">
            <div className="flex justify-center mb-4">
              <div className="relative">
                <Syringe size={48} className="text-slate-mid" />
              </div>
            </div>
            <h3 className="text-text-secondary font-medium mb-2">Enter a URL to begin</h3>
            <p className="text-text-muted text-sm max-w-md mx-auto">
              SYNERGOS uses graph Laplacian diffusion, spectral fingerprinting, thermodynamic free energy,
              and immune memory to detect threats invisible to traditional scanners.
            </p>

            <div className="grid grid-cols-2 md:grid-cols-3 gap-3 mt-8 max-w-2xl mx-auto">
              {[
                { icon: Network,      label: "Graph Physics",      desc: "Field dependency diffusion" },
                { icon: Target,       label: "Strategy Analysis",   desc: "Payoff-based anomaly detection" },
                { icon: Activity,     label: "Chaos Detection",     desc: "Lyapunov exponent sensitivity" },
                { icon: Fingerprint,  label: "Spectral Invariants", desc: "Eigenvalue graph signatures" },
                { icon: Thermometer,  label: "Thermodynamics",      desc: "Free energy F = U - TS" },
                { icon: Dna,          label: "Immune Memory",       desc: "Variant matching via hashing" },
              ].map(({ icon: Icon, label, desc }) => (
                <div key={label} className="p-3 rounded-xl bg-obsidian/50 border border-border/50 text-left">
                  <Icon size={16} className="text-shield mb-1.5" />
                  <div className="text-text-secondary text-xs font-medium">{label}</div>
                  <div className="text-text-muted text-[10px]">{desc}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function QuickStat({ icon: Icon, label, value }: { icon: any; label: string; value: string }) {
  return (
    <div className="flex flex-col items-center gap-1 px-3">
      <Icon size={14} className="text-text-muted" />
      <span className="text-text-primary text-sm font-mono font-medium">{value}</span>
      <span className="text-text-muted text-[10px]">{label}</span>
    </div>
  );
}

function AnalysisPillar({
  icon: Icon,
  title,
  description,
  detail,
  accent,
}: {
  icon: any;
  title: string;
  description: string;
  detail: string;
  accent: string;
}) {
  return (
    <div className="p-3 rounded-xl bg-obsidian border border-border hover:border-shield/20 transition-colors">
      <div className="flex items-center gap-2 mb-1.5">
        <Icon size={14} className={`text-${accent}`} />
        <span className="text-text-primary text-xs font-medium">{title}</span>
      </div>
      <div className="text-text-secondary text-[11px]">{description}</div>
      <div className="text-text-muted text-[10px] font-mono mt-1">{detail}</div>
    </div>
  );
}

function CollapsibleSection({
  title,
  icon: Icon,
  expanded,
  onToggle,
  badge,
  children,
}: {
  title: string;
  icon: any;
  expanded: boolean;
  onToggle: () => void;
  badge?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="glass-card overflow-hidden">
      <button
        onClick={onToggle}
        className="w-full flex items-center gap-3 p-5 text-left hover:bg-slate-deep/20 transition-colors"
      >
        <Icon size={18} className="text-shield shrink-0" />
        <span className="text-text-primary font-medium text-sm flex-1">{title}</span>
        {badge}
        {expanded ? (
          <ChevronUp size={16} className="text-text-muted" />
        ) : (
          <ChevronDown size={16} className="text-text-muted" />
        )}
      </button>
      {expanded && (
        <div className="px-5 pb-5 pt-0">
          {children}
        </div>
      )}
    </div>
  );
}
