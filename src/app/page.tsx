"use client";

import { useState, useEffect } from "react";
import { ScanInput } from "@/components/ui/scan-input";
import { ScanResults } from "@/components/results/scan-results";
import type { VERIDICTResult } from "@/lib/algorithms/types";
import type { ThreatCategory } from "@/components/ui/threat-badge";
import type { EvidenceType } from "@/components/ui/evidence-card";
import Link from "next/link";
import { Shield, AlertTriangle, TrendingUp, Zap, Eye, Layers, Brain, Globe } from "lucide-react";

interface SiteStats {
  scansToday: number;
  threatsToday: number;
  topThreat: string;
  topThreatPct: number;
  avgScore: number;
}

const CATEGORY_MAP: Record<string, ThreatCategory> = {
  PHISHING: "phishing",
  ADVANCE_FEE: "prize",
  TECH_SUPPORT: "tech_support",
  ROMANCE: "romance",
  CRYPTO: "crypto",
  IRS_GOV: "phishing",
  PACKAGE_DELIVERY: "delivery",
  SOCIAL_MEDIA: "social_media",
  SUBSCRIPTION_TRAP: "subscription_trap",
  FAKE_CHARITY: "fake_charity",
  RENTAL_HOUSING: "rental_housing",
  STUDENT_LOAN: "student_loan",
  GENERIC: "unknown",
  MARKETPLACE_FRAUD: "marketplace_fraud",
  ELDER_SCAM: "elder_scam",
  TICKET_SCAM: "ticket_scam",
  INVESTMENT_FRAUD: "investment_fraud",
  EMPLOYMENT_SCAM: "employment_scam",
  BANK_OTP: "bank_otp",
};

const SEVERITY_MAP: Record<string, "low" | "medium" | "high" | "critical"> = {
  SAFE: "low",
  LOW: "low",
  MEDIUM: "medium",
  HIGH: "high",
  CRITICAL: "critical",
};

function mapEvidenceType(layer: string | undefined): EvidenceType {
  if (!layer) return "other";
  const l = layer.toLowerCase();
  if (l.includes("url") || l.includes("fisher")) return "url";
  if (l.includes("email")) return "email";
  if (l.includes("domain") || l.includes("conservation")) return "domain";
  if (l.includes("cascade") || l.includes("immune")) return "content";
  return "other";
}

export default function HomePage() {
  const [input, setInput] = useState("");
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<VERIDICTResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<SiteStats | null>(null);

  useEffect(() => {
    fetch("/api/stats")
      .then((r) => r.json())
      .then((data: SiteStats) => setStats(data))
      .catch(() => { /* keep stats null, section will be hidden */ });
  }, []);

  async function handleScan(scanData: { type: string; content: string; file?: File }) {
    setInput(scanData.content);
    setScanning(true);
    setError(null);

    try {
      let res: Response;

      if (scanData.type === "screenshot" && scanData.file) {
        const formData = new FormData();
        formData.append("image", scanData.file);
        res = await fetch("/api/scan/screenshot", {
          method: "POST",
          body: formData,
        });
      } else {
        res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ type: scanData.type, content: scanData.content }),
        });
      }

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.error || `Scan failed (${res.status})`);
      }

      const result: VERIDICTResult = await res.json();
      setResults(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "An unexpected error occurred");
    } finally {
      setScanning(false);
    }
  }


  return (
    <div className="space-y-12">
      {/* Hero Section */}
      <section className="text-center pt-8 md:pt-16 pb-4">
        <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-shield/20 bg-shield/5 text-shield text-sm font-mono mb-6">
          <Shield className="w-4 h-4" />
          <span>AI-Powered Scam Detection</span>
        </div>

        <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold leading-tight tracking-tight mb-4">
          Is This Legit or Am I
          <br />
          <span className="text-transparent bg-clip-text bg-gradient-to-r from-shield to-safe">
            About to Get Screwed?
          </span>
        </h1>

        <p className="text-text-secondary text-lg md:text-xl max-w-2xl mx-auto mb-10">
          Forward a suspicious text, email, or screenshot and get an instant
          scam confidence score with evidence.
        </p>

        {/* Scan Input */}
        <div className="max-w-3xl mx-auto" data-tour="scan-input">
          <ScanInput
            onScan={handleScan}
            isLoading={scanning}
          />
        </div>

        {/* Error Display */}
        {error && (
          <div className="max-w-3xl mx-auto mt-6">
            <div className="glass-card border-danger/30 p-4 flex items-center gap-3 text-left">
              <AlertTriangle className="w-5 h-5 text-danger shrink-0" />
              <p className="text-danger text-sm">{error}</p>
            </div>
          </div>
        )}
      </section>

      {/* Results */}
      {results && (
        <section className="max-w-4xl mx-auto">
          {scanning && (
            <div className="mb-4 flex items-center justify-center gap-2 rounded-xl border border-shield/20 bg-shield/5 px-4 py-3 text-sm text-shield font-mono">
              <span className="inline-block h-3.5 w-3.5 animate-spin rounded-full border-2 border-current border-t-transparent" />
              Re-scanning...
            </div>
          )}
          <ScanResults
            score={results.score}
            category={CATEGORY_MAP[results.category] || "unknown"}
            severity={SEVERITY_MAP[results.threatLevel] || "medium"}
            evidence={(results.evidence ?? []).map((e) => ({
              type: mapEvidenceType(e.layer),
              title: e.finding ?? "",
              description: e.detail ?? "",
              severity: e.severity === "low" ? "low" : e.severity === "medium" ? "medium" : e.severity === "high" ? "high" : e.severity === "critical" ? "critical" : "info",
            }))}
            layers={[
              { id: "fisher", name: "Fisher Cascade", icon: Eye, score: results.layerScores?.fisher ?? 0, summary: "Signal analysis with early stopping", findings: results.layerDetails?.fisher?.details ?? [] },
              { id: "conservation", name: "Conservation Laws", icon: Layers, score: results.layerScores?.conservation ?? 0, summary: "Structural violation detection", findings: results.layerDetails?.conservation?.details ?? [] },
              { id: "cascade", name: "Cascade Breaker", icon: Brain, score: results.layerScores?.cascadeBreaker ?? 0, summary: "Manipulation trigger analysis", findings: results.layerDetails?.cascadeBreaker?.details ?? [] },
              { id: "immune", name: "Immune Repertoire", icon: Globe, score: results.layerScores?.immune ?? 0, summary: "Pattern matching against known scams", findings: results.layerDetails?.immune?.details ?? [] },
            ]}
            scannedInput={input}
            similarKnownScam={results.similarKnownScam}
            confidenceInterval={results.confidenceInterval}
            financialRisk={results.financialRisk ? {
              riskScore: results.financialRisk.riskScore,
              riskType: results.financialRisk.riskType,
              estimatedLoss: results.financialRisk.estimatedLoss,
              urgencyScore: results.financialRisk.urgencyScore,
              sophisticationScore: results.financialRisk.sophisticationScore,
              recommendedActions: results.financialRisk.recommendedActions,
            } : undefined}
            urlDeepAnalysis={results.urlDeepAnalysis ? {
              overallRiskScore: results.urlDeepAnalysis.overallRiskScore,
              detectedBrands: results.urlDeepAnalysis.detectedBrands,
              homoglyphsDetected: results.urlDeepAnalysis.homoglyphsDetected,
              flags: results.urlDeepAnalysis.flags,
              breakdown: results.urlDeepAnalysis.breakdown,
            } : undefined}
            multilingualDetection={results.multilingualDetection ? {
              detected: results.multilingualDetection.detected,
              dominantLanguage: results.multilingualDetection.dominantLanguage,
              matchCount: results.multilingualDetection.matches?.length ?? 0,
              riskScore: results.multilingualDetection.riskScore,
              flags: results.multilingualDetection.flags ?? [],
            } : undefined}
            phoneAnalysis={results.phoneAnalysis ? {
              detected: results.phoneAnalysis.detected,
              highestRisk: results.phoneAnalysis.highestRisk,
              flags: results.phoneAnalysis.flags ?? [],
              phoneCount: results.phoneAnalysis.phones?.length ?? 0,
            } : undefined}
            linguisticDeception={results.linguisticDeception ? {
              score: results.linguisticDeception.score,
              tacticCount: results.linguisticDeception.deceptionTactics?.length ?? 0,
              manipulationScore: results.linguisticDeception.manipulationScore,
              flags: results.linguisticDeception.flags ?? [],
              details: results.linguisticDeception.details ?? [],
            } : undefined}
            // eslint-disable-next-line @typescript-eslint/no-explicit-any
            ipIntelligence={(results as any).ipIntelligence ?? undefined}
          />
        </section>
      )}

      {/* Real-time Threat Stats — only shown when data is available */}
      {stats && (
        <section className="max-w-4xl mx-auto pt-8">
          <h2 className="text-xl font-semibold text-text-primary mb-6 flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-shield" />
            Today&apos;s Threat Intelligence
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <StatCard
              icon={<Zap className="w-5 h-5" />}
              label="Scans Today"
              value={stats.scansToday.toLocaleString()}
              color="shield"
            />
            <StatCard
              icon={<AlertTriangle className="w-5 h-5" />}
              label="Threats Detected"
              value={stats.threatsToday.toLocaleString()}
              color="danger"
            />
            <StatCard
              icon={<Shield className="w-5 h-5" />}
              label="Top Threat"
              value={stats.topThreat}
              subtitle={stats.topThreatPct > 0 ? `${stats.topThreatPct}% of threats` : undefined}
              color="caution"
            />
            <StatCard
              icon={<TrendingUp className="w-5 h-5" />}
              label="Avg Score"
              value={stats.avgScore > 0 ? stats.avgScore.toFixed(1) : "—"}
              subtitle="out of 100"
              color="safe"
            />
          </div>
        </section>
      )}

      {/* Footer */}
      <footer className="mt-16 pt-8 border-t border-white/5 text-center">
        <p className="text-text-muted text-xs font-mono">
          © {new Date().getFullYear()} ScamShieldy &nbsp;·&nbsp;{" "}
          <Link href="/privacy" className="hover:text-text-secondary transition-colors">
            Privacy Policy
          </Link>
        </p>
      </footer>
    </div>
  );
}

function StatCard({
  icon,
  label,
  value,
  change,
  subtitle,
  color,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  change?: string;
  subtitle?: string;
  color: "shield" | "danger" | "caution" | "safe";
}) {
  const colorMap = {
    shield: "text-shield border-shield/20 bg-shield/5",
    danger: "text-danger border-danger/20 bg-danger/5",
    caution: "text-caution border-caution/20 bg-caution/5",
    safe: "text-safe border-safe/20 bg-safe/5",
  };

  return (
    <div className="glass-card p-5 group hover:border-shield/30 transition-all duration-300">
      <div className={`inline-flex items-center justify-center w-10 h-10 rounded-lg border ${colorMap[color]} mb-3`}>
        {icon}
      </div>
      <p className="text-text-muted text-xs font-mono uppercase tracking-wider mb-1">
        {label}
      </p>
      <p className="text-2xl font-bold font-mono text-text-primary">{value}</p>
      {change && (
        <p className="text-safe text-xs font-mono mt-1">{change} vs yesterday</p>
      )}
      {subtitle && (
        <p className="text-text-muted text-xs font-mono mt-1">{subtitle}</p>
      )}
    </div>
  );
}
