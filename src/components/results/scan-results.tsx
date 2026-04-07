"use client";

import { useState } from "react";
import {
  ChevronDown,
  Share2,
  Flag,
  CheckCircle,
  ShieldCheck,
  Layers,
  Eye,
  DollarSign,
  Link2,
  AlertCircle,
  Languages,
  Phone,
  Brain,
  Globe,
  Server,
  Wifi,
} from "lucide-react";
import clsx from "clsx";
import { ScoreRing } from "@/components/ui/score-ring";
import { ThreatBadge, type ThreatCategory } from "@/components/ui/threat-badge";
import { EvidenceCard, type EvidenceType } from "@/components/ui/evidence-card";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface Evidence {
  type: EvidenceType;
  title: string;
  description: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  details?: string;
}

interface LayerResult {
  id: string;
  name: string;
  icon: typeof Eye;
  score: number;
  summary: string;
  findings: string[];
}

interface FinancialRiskData {
  riskScore: number;
  riskType: string;
  estimatedLoss: { min: number; max: number; median: number };
  urgencyScore: number;
  sophisticationScore: number;
  recommendedActions: string[];
}

interface UrlDeepData {
  overallRiskScore: number;
  detectedBrands: { brand: string; distance: number }[];
  homoglyphsDetected: { original: string; lookalike: string }[];
  flags: string[];
  breakdown: {
    entropyScore: number;
    dgaScore: number;
    brandDistanceScore: number;
    homographScore: number;
    phishingKitScore?: number;
  };
}

interface ConfidenceIntervalData {
  lower: number;
  upper: number;
  confidence: number;
}

interface MultilingualData {
  detected: boolean;
  dominantLanguage: string | null;
  matchCount: number;
  riskScore: number;
  flags: string[];
}

interface PhoneData {
  detected: boolean;
  highestRisk: number;
  flags: string[];
  phoneCount: number;
}

interface LinguisticData {
  score: number;
  tacticCount: number;
  manipulationScore: number;
  flags: string[];
  details: string[];
}

type HostingCategory = "residential" | "cloud" | "vps" | "vpn_proxy" | "tor" | "unknown";

interface IpIntelligenceData {
  ip: string;
  country: string;
  countryCode: string;
  city: string;
  isp: string;
  org: string;
  asn: string;
  hostingCategory: HostingCategory;
  isDatacenter: boolean;
  isVpnOrProxy: boolean;
  countryRiskLevel: "low" | "medium" | "high" | "critical";
  flags: string[];
}

interface ScanResultsProps {
  score: number;
  category: ThreatCategory;
  severity: "low" | "medium" | "high" | "critical";
  evidence: Evidence[];
  layers: LayerResult[];
  scannedInput: string;
  similarKnownScam?: string | null;
  confidenceInterval?: ConfidenceIntervalData;
  financialRisk?: FinancialRiskData;
  urlDeepAnalysis?: UrlDeepData;
  multilingualDetection?: MultilingualData;
  phoneAnalysis?: PhoneData;
  linguisticDeception?: LinguisticData;
  ipIntelligence?: IpIntelligenceData;
  className?: string;
}

/* ------------------------------------------------------------------ */
/*  Layer accordion                                                    */
/* ------------------------------------------------------------------ */

function LayerAccordion({ layer }: { layer: LayerResult }) {
  const [open, setOpen] = useState(false);
  const Icon = layer.icon;

  const scoreColor =
    layer.score <= 30
      ? "text-safe"
      : layer.score <= 60
        ? "text-caution"
        : layer.score <= 80
          ? "text-danger"
          : "text-critical";

  return (
    <div className="border border-border/60 rounded-xl overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-3 p-4 hover:bg-slate-deep/30 transition-colors text-left"
      >
        <div className="p-2 rounded-lg bg-slate-deep/60 text-text-secondary">
          <Icon size={16} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-sm font-semibold text-text-primary">{layer.name}</div>
          <div className="text-xs text-text-muted truncate">{layer.summary}</div>
        </div>
        <span className={clsx("font-mono text-sm font-bold", scoreColor)}>
          {layer.score}
        </span>
        <ChevronDown
          size={16}
          className={clsx(
            "text-text-muted transition-transform duration-200 shrink-0",
            open && "rotate-180"
          )}
        />
      </button>

      <div
        className={clsx(
          "overflow-hidden transition-all duration-300 ease-in-out",
          open ? "max-h-[500px] opacity-100" : "max-h-0 opacity-0"
        )}
      >
        <div className="px-4 pb-4 space-y-2 border-t border-border/40">
          {layer.findings.map((finding, i) => (
            <div
              key={i}
              className="flex items-start gap-2 py-2 text-sm text-text-secondary"
            >
              <span className="shrink-0 mt-1.5 w-1.5 h-1.5 rounded-full bg-shield/60" />
              {finding}
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */
/*  Main results component                                             */
/* ------------------------------------------------------------------ */

export function ScanResults({
  score,
  category,
  severity,
  evidence,
  layers,
  scannedInput,
  similarKnownScam,
  confidenceInterval,
  financialRisk,
  urlDeepAnalysis,
  multilingualDetection,
  phoneAnalysis,
  linguisticDeception,
  ipIntelligence,
  className,
}: ScanResultsProps) {
  const [feedbackGiven, setFeedbackGiven] = useState<"fp" | "confirmed" | null>(null);

  const verdictText =
    score <= 30
      ? "This appears to be legitimate."
      : score <= 60
        ? "Exercise caution -- some red flags detected."
        : score <= 80
          ? "This is likely a scam. Do not engage."
          : "This is almost certainly a scam. Do not click, reply, or send money.";

  return (
    <div className={clsx("space-y-6", className)}>
      {/* ---- Top: Score + Category ---- */}
      <div className="glass-card p-6 md:p-8 flex flex-col items-center text-center" data-tour="score-ring">
        <ScoreRing score={score} label="Threat Score" size={180} />

        {confidenceInterval && (
          <div className="mt-2 text-xs font-mono text-text-muted">
            95% CI: {confidenceInterval.lower.toFixed(1)}–{confidenceInterval.upper.toFixed(1)}
          </div>
        )}

        <div className="mt-4 mb-2">
          <ThreatBadge category={category} severity={severity} />
        </div>

        <p className="max-w-md text-sm text-text-secondary leading-relaxed mt-2">
          {verdictText}
        </p>

        {/* Similar known scam callout */}
        {similarKnownScam && (
          <div className="mt-4 w-full max-w-lg flex items-start gap-2 p-3 rounded-lg bg-caution/10 border border-caution/20 text-left">
            <AlertCircle size={14} className="text-caution shrink-0 mt-0.5" />
            <p className="text-xs text-caution/90">
              Resembles known scam: <span className="font-semibold">{similarKnownScam}</span>
            </p>
          </div>
        )}

        {/* Scanned input preview */}
        <div className="mt-4 w-full max-w-lg p-3 rounded-lg bg-abyss/80 border border-border text-xs font-mono text-text-muted truncate">
          {scannedInput}
        </div>
      </div>

      {/* ---- Financial Risk Panel ---- */}

      {/* ---- URL Deep Analysis Panel ---- */}
      {urlDeepAnalysis && urlDeepAnalysis.overallRiskScore > 0.2 && (
        <div className="glass-card p-5">
          <div className="flex items-center gap-2 mb-4">
            <Link2 size={18} className="text-shield" />
            <h3 className="text-base font-semibold text-text-primary">URL Deep Analysis</h3>
            <span className={clsx(
              "ml-auto text-xs font-mono font-bold px-2 py-0.5 rounded-full",
              urlDeepAnalysis.overallRiskScore >= 0.75 ? "bg-danger/20 text-danger" :
              urlDeepAnalysis.overallRiskScore >= 0.45 ? "bg-caution/20 text-caution" :
              "bg-safe/20 text-safe"
            )}>
              {(urlDeepAnalysis.overallRiskScore * 100).toFixed(0)}% risk
            </span>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mb-3">
            {[
              { label: "Entropy", value: urlDeepAnalysis.breakdown.entropyScore },
              { label: "DGA", value: urlDeepAnalysis.breakdown.dgaScore },
              { label: "Brand Dist.", value: urlDeepAnalysis.breakdown.brandDistanceScore },
              { label: "Homograph", value: urlDeepAnalysis.breakdown.homographScore },
            ].map(({ label, value }) => (
              <div key={label} className="p-2 rounded-lg bg-abyss/60 border border-border/40 text-center">
                <div className="text-xs text-text-muted">{label}</div>
                <div className={clsx("text-sm font-mono font-bold mt-0.5",
                  value >= 0.7 ? "text-danger" : value >= 0.4 ? "text-caution" : "text-safe"
                )}>
                  {(value * 100).toFixed(0)}%
                </div>
              </div>
            ))}
          </div>
          {urlDeepAnalysis.detectedBrands.length > 0 && (
            <div className="text-xs text-caution mt-2">
              Brand impersonation: {urlDeepAnalysis.detectedBrands.map(b => b.brand).join(", ")}
            </div>
          )}
        </div>
      )}

      {/* ---- IP Intelligence Panel ---- */}
      {ipIntelligence && (
        <div className="glass-card p-5">
          <div className="flex items-center gap-2 mb-4">
            <Globe size={18} className="text-shield" />
            <h3 className="text-base font-semibold text-text-primary">IP Intelligence</h3>
            <span className={clsx(
              "ml-auto text-xs font-mono font-bold px-2 py-0.5 rounded-full",
              ipIntelligence.countryRiskLevel === "critical" ? "bg-danger/20 text-danger" :
              ipIntelligence.countryRiskLevel === "high"     ? "bg-danger/15 text-danger" :
              ipIntelligence.countryRiskLevel === "medium"   ? "bg-caution/20 text-caution" :
              "bg-safe/20 text-safe"
            )}>
              {ipIntelligence.countryRiskLevel.toUpperCase()} RISK
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-4">
            {/* IP Address */}
            <div className="p-3 rounded-lg bg-abyss/60 border border-border/40">
              <div className="text-xs text-text-muted mb-1">Server IP</div>
              <div className="text-sm font-mono font-semibold text-text-primary">{ipIntelligence.ip}</div>
            </div>
            {/* Country */}
            <div className="p-3 rounded-lg bg-abyss/60 border border-border/40">
              <div className="text-xs text-text-muted mb-1">Country</div>
              <div className="text-sm font-semibold text-text-primary">
                {ipIntelligence.country} {ipIntelligence.city ? `· ${ipIntelligence.city}` : ""}
              </div>
            </div>
            {/* Hosting type */}
            <div className="p-3 rounded-lg bg-abyss/60 border border-border/40">
              <div className="text-xs text-text-muted mb-1">Hosting Type</div>
              <div className={clsx("text-sm font-semibold capitalize flex items-center gap-1.5",
                ipIntelligence.hostingCategory === "tor"       ? "text-danger" :
                ipIntelligence.hostingCategory === "vpn_proxy" ? "text-danger" :
                ipIntelligence.hostingCategory === "vps"       ? "text-caution" :
                ipIntelligence.hostingCategory === "cloud"     ? "text-caution" :
                "text-safe"
              )}>
                {ipIntelligence.hostingCategory === "tor"       && <Wifi size={13} />}
                {ipIntelligence.hostingCategory === "vpn_proxy" && <Wifi size={13} />}
                {ipIntelligence.isDatacenter                    && <Server size={13} />}
                {ipIntelligence.hostingCategory.replace("_", " / ")}
              </div>
            </div>
          </div>

          {/* ASN + ISP */}
          <div className="p-3 rounded-lg bg-abyss/60 border border-border/40 mb-3">
            <div className="text-xs text-text-muted mb-1">Network</div>
            <div className="text-xs font-mono text-text-secondary">
              {ipIntelligence.asn}{ipIntelligence.isp && ` · ${ipIntelligence.isp}`}
            </div>
          </div>

          {/* Flags */}
          {ipIntelligence.flags.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {ipIntelligence.flags.map((flag, i) => (
                <span
                  key={i}
                  className="text-[10px] font-mono px-2 py-0.5 rounded-md border"
                  style={{
                    background: "rgba(239,68,68,0.08)",
                    borderColor: "rgba(239,68,68,0.2)",
                    color: "#ef4444",
                  }}
                >
                  {flag.replace(/_/g, " ")}
                </span>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ---- Linguistic Deception Panel ---- */}
      {linguisticDeception && linguisticDeception.score >= 20 && (
        <div className="glass-card p-5">
          <div className="flex items-center gap-2 mb-4">
            <Brain size={18} className="text-purple-400" />
            <h3 className="text-base font-semibold text-text-primary">Linguistic Deception Analysis</h3>
            <span className={clsx(
              "ml-auto text-xs font-mono font-bold px-2 py-0.5 rounded-full",
              linguisticDeception.score >= 70 ? "bg-danger/20 text-danger" :
              linguisticDeception.score >= 40 ? "bg-caution/20 text-caution" :
              "bg-safe/20 text-safe"
            )}>
              {linguisticDeception.score}/100
            </span>
          </div>
          <div className="grid grid-cols-2 gap-3 mb-3">
            <div className="p-3 rounded-lg bg-abyss/60 border border-border/40">
              <div className="text-xs text-text-muted mb-1">Manipulation Score</div>
              <div className={clsx("text-sm font-semibold",
                linguisticDeception.manipulationScore >= 0.7 ? "text-danger" :
                linguisticDeception.manipulationScore >= 0.4 ? "text-caution" : "text-safe"
              )}>
                {(linguisticDeception.manipulationScore * 100).toFixed(0)}%
              </div>
            </div>
            <div className="p-3 rounded-lg bg-abyss/60 border border-border/40">
              <div className="text-xs text-text-muted mb-1">Deception Tactics</div>
              <div className="text-sm font-semibold text-text-primary">{linguisticDeception.tacticCount} detected</div>
            </div>
          </div>
          {linguisticDeception.details.length > 0 && (
            <div className="space-y-1.5">
              {linguisticDeception.details.slice(0, 4).map((d, i) => (
                <div key={i} className="flex items-start gap-2 text-xs text-text-secondary">
                  <span className="shrink-0 mt-1.5 w-1.5 h-1.5 rounded-full bg-purple-400/60" />
                  {d}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ---- Multilingual Detection Panel ---- */}
      {multilingualDetection && multilingualDetection.detected && (
        <div className="glass-card p-5">
          <div className="flex items-center gap-2 mb-4">
            <Languages size={18} className="text-shield" />
            <h3 className="text-base font-semibold text-text-primary">Multilingual Scam Detection</h3>
            <span className={clsx(
              "ml-auto text-xs font-mono font-bold px-2 py-0.5 rounded-full",
              multilingualDetection.riskScore >= 0.7 ? "bg-danger/20 text-danger" :
              multilingualDetection.riskScore >= 0.4 ? "bg-caution/20 text-caution" :
              "bg-safe/20 text-safe"
            )}>
              {(multilingualDetection.riskScore * 100).toFixed(0)}% risk
            </span>
          </div>
          <div className="grid grid-cols-2 gap-3 mb-3">
            <div className="p-3 rounded-lg bg-abyss/60 border border-border/40">
              <div className="text-xs text-text-muted mb-1">Language Detected</div>
              <div className="text-sm font-semibold text-text-primary capitalize">
                {multilingualDetection.dominantLanguage ?? "Unknown"}
              </div>
            </div>
            <div className="p-3 rounded-lg bg-abyss/60 border border-border/40">
              <div className="text-xs text-text-muted mb-1">Pattern Matches</div>
              <div className="text-sm font-semibold text-text-primary">{multilingualDetection.matchCount}</div>
            </div>
          </div>
          {multilingualDetection.flags.length > 0 && (
            <div className="space-y-1.5">
              {multilingualDetection.flags.slice(0, 3).map((f, i) => (
                <div key={i} className="flex items-start gap-2 text-xs text-text-secondary">
                  <span className="shrink-0 mt-1.5 w-1.5 h-1.5 rounded-full bg-shield/60" />
                  {f}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ---- Phone Analysis Panel ---- */}
      {phoneAnalysis && phoneAnalysis.detected && phoneAnalysis.highestRisk >= 0.3 && (
        <div className="glass-card p-5">
          <div className="flex items-center gap-2 mb-4">
            <Phone size={18} className="text-caution" />
            <h3 className="text-base font-semibold text-text-primary">Phone Number Analysis</h3>
            <span className={clsx(
              "ml-auto text-xs font-mono font-bold px-2 py-0.5 rounded-full",
              phoneAnalysis.highestRisk >= 0.7 ? "bg-danger/20 text-danger" :
              phoneAnalysis.highestRisk >= 0.4 ? "bg-caution/20 text-caution" :
              "bg-safe/20 text-safe"
            )}>
              {(phoneAnalysis.highestRisk * 100).toFixed(0)}% risk
            </span>
          </div>
          <div className="mb-3 p-3 rounded-lg bg-abyss/60 border border-border/40">
            <div className="text-xs text-text-muted mb-1">Numbers Found</div>
            <div className="text-sm font-semibold text-text-primary">{phoneAnalysis.phoneCount} phone number{phoneAnalysis.phoneCount !== 1 ? "s" : ""} detected</div>
          </div>
          {phoneAnalysis.flags.length > 0 && (
            <div className="space-y-1.5">
              {phoneAnalysis.flags.slice(0, 3).map((f, i) => (
                <div key={i} className="flex items-start gap-2 text-xs text-text-secondary">
                  <span className="shrink-0 mt-1.5 w-1.5 h-1.5 rounded-full bg-caution/60" />
                  {f}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ---- Evidence section ---- */}
      <div data-tour="evidence-section">
        <div className="flex items-center gap-2 mb-4">
          <ShieldCheck size={18} className="text-shield" />
          <h3 className="text-base font-semibold text-text-primary">What we found</h3>
          <span className="ml-auto text-xs font-mono text-text-muted">
            {evidence.length} signal{evidence.length !== 1 ? "s" : ""}
          </span>
        </div>
        <div className="space-y-3">
          {evidence.map((ev, i) => (
            <EvidenceCard key={i} {...ev} />
          ))}
        </div>
      </div>

      {/* ---- Layer breakdown ---- */}
      <div>
        <div className="flex items-center gap-2 mb-4">
          <Layers size={18} className="text-shield" />
          <h3 className="text-base font-semibold text-text-primary">VERIDICT Layer Breakdown</h3>
        </div>
        <div className="space-y-2">
          {layers.map((layer) => (
            <LayerAccordion key={layer.id} layer={layer} />
          ))}
        </div>
      </div>

      {/* ---- Actions ---- */}
      <div className="glass-card p-5">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          {/* Community feedback */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-text-muted mr-1">Was this accurate?</span>

            {feedbackGiven === null ? (
              <>
                <button
                  onClick={async () => {
                    setFeedbackGiven("fp");
                    try {
                      await fetch("/api/feedback", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                          content: scannedInput,
                          contentType: scannedInput.startsWith("http") ? "url" : "text",
                          isScam: false,
                          category,
                        }),
                      });
                      console.log("[Feedback] False positive reported");
                    } catch (err) {
                      console.error("[Feedback] Error:", err);
                    }
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border text-xs font-medium text-text-secondary hover:text-caution hover:border-caution/30 transition-colors"
                >
                  <Flag size={12} />
                  False positive
                </button>
                <button
                  onClick={async () => {
                    setFeedbackGiven("confirmed");
                    try {
                      await fetch("/api/feedback", {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({
                          content: scannedInput,
                          contentType: scannedInput.startsWith("http") ? "url" : "text",
                          isScam: true,
                          category,
                        }),
                      });
                      console.log("[Feedback] Scam confirmed");
                    } catch (err) {
                      console.error("[Feedback] Error:", err);
                    }
                  }}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border text-xs font-medium text-text-secondary hover:text-safe hover:border-safe/30 transition-colors"
                >
                  <CheckCircle size={12} />
                  Confirm scam
                </button>
              </>
            ) : (
              <span className="text-xs font-mono text-safe">
                Thanks for your feedback!
              </span>
            )}
          </div>

          {/* Share */}
          <button
            onClick={async () => {
              const shareText = `ScamShieldy Analysis: Score ${score}/100 - ${verdictText}`;
              if (navigator.share) {
                try {
                  await navigator.share({ title: "ScamShieldy Results", text: shareText });
                } catch {
                  // User cancelled or share failed — fall back to clipboard
                  await navigator.clipboard.writeText(shareText);
                }
              } else {
                await navigator.clipboard.writeText(shareText);
              }
            }}
            className="flex items-center gap-2 px-4 py-2 rounded-xl border border-border text-sm text-text-secondary hover:text-shield hover:border-shield/30 transition-colors"
          >
            <Share2 size={14} />
            Share results
          </button>
        </div>
      </div>
    </div>
  );
}

