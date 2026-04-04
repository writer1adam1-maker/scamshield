"use client";

import { useState, useEffect, useRef } from "react";
import {
  Shield, Syringe, Globe, Loader2, AlertTriangle, CheckCircle2,
  XCircle, Activity, Zap, Fingerprint, Brain, Thermometer, Network,
  TrendingUp, ChevronDown, ChevronUp, Lock, Dna, Target, Clock,
  ShieldCheck, RefreshCw, Info, Phone, MessageSquare, Mail, QrCode,
} from "lucide-react";
import type { VaccineAnalyzeResponse } from "@/app/api/vaccine/analyze/route";

// ---------------------------------------------------------------------------
// Scan modes
// ---------------------------------------------------------------------------

type ScanMode = "website" | "phone" | "sms" | "email" | "qr";

const SCAN_MODES: Array<{
  id: ScanMode;
  label: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
  placeholder: string;
  desc: string;
}> = [
  { id: "website", icon: Globe,        label: "Website",  placeholder: "Enter URL (e.g. example.com)", desc: "Scan any site for malware, phishing forms, fake scripts" },
  { id: "phone",   icon: Phone,        label: "Phone",    placeholder: "Paste phone number(s) to check (e.g. +1-800-555-0100)", desc: "Check phone numbers for premium-rate fraud and scam call centers" },
  { id: "sms",     icon: MessageSquare, label: "SMS/Text", placeholder: "Paste the suspicious text message here…", desc: "Detect manipulation tactics in suspicious texts and DMs" },
  { id: "email",   icon: Mail,         label: "Email",    placeholder: "Paste email body or headers here…", desc: "Analyse emails for phishing language, fake authority, and deception" },
  { id: "qr",      icon: QrCode,       label: "QR Code",  placeholder: "Paste the URL decoded from the QR code…", desc: "Scan the URL hidden inside a QR code for malicious content" },
];

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface InjectionRule {
  id: string;
  type: "block" | "warn" | "sandbox" | "disable" | "monitor";
  selector?: string;
  attribute?: string;
  targetUrl?: string;
  scriptContent?: string;
  message?: string;
  expiresAt: number;
}

interface VaccineResponse {
  url: string;
  timestamp: number;
  threatLevel: string;
  threatScore: number;
  threatsDetected: string[];
  injectionRules: InjectionRule[];
  synergosAnalysis?: {
    verdict: "BLOCK" | "WARN" | "ALLOW";
    confidence: number;
    nextAttackPrediction: { tactics: string[]; likelihood: number };
    recommendedDefense: string[];
  };
  signature: string;
  signedAt: number;
  latencyMs: number;
}

interface BreachCard {
  id: string;
  title: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  category: string;
  ruleType: "block" | "warn" | "sandbox" | "disable" | "monitor";
  selector?: string;
  message?: string;
}

interface VaccineRecord {
  id: string;        // matches BreachCard.id
  url: string;
  appliedAt: string; // ISO
  expiresAt: string; // ISO (appliedAt + 1 hour)
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STORAGE_KEY = "scamshield:vaccines";
const VACCINE_TTL_MS = 60 * 60 * 1000; // 1 hour

const THREAT_COLORS: Record<string, { bg: string; text: string; border: string; glow: string }> = {
  safe:     { bg: "bg-safe/10",     text: "text-safe",     border: "border-safe/20",     glow: "shadow-[0_0_20px_rgba(0,229,160,0.15)]" },
  low:      { bg: "bg-safe/10",     text: "text-safe",     border: "border-safe/20",     glow: "" },
  medium:   { bg: "bg-caution/10",  text: "text-caution",  border: "border-caution/20",  glow: "shadow-[0_0_20px_rgba(251,191,36,0.15)]" },
  high:     { bg: "bg-danger/10",   text: "text-danger",   border: "border-danger/20",   glow: "shadow-[0_0_20px_rgba(255,59,92,0.15)]" },
  critical: { bg: "bg-critical/10", text: "text-critical", border: "border-critical/20", glow: "shadow-[0_0_25px_rgba(255,23,68,0.2)]" },
};

const SEVERITY_COLORS: Record<string, string> = {
  low:      "bg-safe/10 text-safe border-safe/20",
  medium:   "bg-caution/10 text-caution border-caution/20",
  high:     "bg-danger/10 text-danger border-danger/20",
  critical: "bg-critical/10 text-critical border-critical/20",
};

const SEVERITY_LEFT: Record<string, string> = {
  low:      "border-l-safe",
  medium:   "border-l-caution",
  high:     "border-l-danger",
  critical: "border-l-critical",
};

// Maps rule type → default severity
const RULE_SEVERITY: Record<string, BreachCard["severity"]> = {
  block:   "critical",
  disable: "high",
  sandbox: "medium",
  warn:    "medium",
  monitor: "low",
};

// Maps id prefix / keywords → human-readable category + title
const TITLE_MAP: Array<{ keywords: string[]; title: string; category: string }> = [
  { keywords: ["phishing", "credential"],      title: "Credential Harvesting Form",       category: "Phishing"          },
  { keywords: ["payment", "card"],             title: "Fake Payment Form Detected",        category: "Financial Fraud"   },
  { keywords: ["entropy", "obfuscat"],         title: "Obfuscated Script Detected",        category: "Malicious Code"    },
  { keywords: ["cryptomin", "miner"],          title: "Cryptominer Script Found",          category: "Malware"           },
  { keywords: ["keylog"],                      title: "Keylogger Behaviour Detected",      category: "Malware"           },
  { keywords: ["ransomware"],                  title: "Ransomware Pattern Detected",       category: "Malware"           },
  { keywords: ["malware", "exploit"],          title: "Malware Signature Found",           category: "Malware"           },
  { keywords: ["iframe"],                      title: "Hidden iFrame Injection",           category: "Script Injection"  },
  { keywords: ["redirect"],                    title: "Suspicious Redirect Chain",         category: "Redirect Attack"   },
  { keywords: ["xss"],                         title: "XSS Payload Detected",              category: "Script Injection"  },
  { keywords: ["urgency", "fake_urgency"],     title: "Fake Urgency / Pressure Tactic",   category: "Social Engineering"},
  { keywords: ["trust", "badge"],              title: "Fake Trust Badge Found",            category: "Deception"         },
  { keywords: ["spoof", "brand"],              title: "Spoofed Brand Identity",            category: "Phishing"          },
  { keywords: ["review"],                      title: "Fake Reviews Detected",             category: "Deception"         },
  { keywords: ["support", "chat"],             title: "Fake Support Chat Widget",          category: "Social Engineering"},
  { keywords: ["clipboard"],                   title: "Clipboard Hijacking Attempt",       category: "Malware"           },
  { keywords: ["popup"],                       title: "Popup Spam Behaviour",              category: "Deception"         },
  { keywords: ["external", "domain", "form"],  title: "Form Submits to External Domain",  category: "Phishing"          },
];

function mapToBreachCard(description: string, rule: InjectionRule, index: number): BreachCard {
  const haystack = `${description} ${rule.id} ${rule.selector || ""} ${rule.message || ""}`.toLowerCase();

  let title = "Suspicious Behaviour Detected";
  let category = "Unknown";
  for (const entry of TITLE_MAP) {
    if (entry.keywords.some((kw) => haystack.includes(kw))) {
      title = entry.title;
      category = entry.category;
      break;
    }
  }

  const severity = RULE_SEVERITY[rule.type] ?? "medium";

  return {
    id: rule.id || `breach-${index}`,
    title,
    description,
    severity,
    category,
    ruleType: rule.type,
    selector: rule.selector,
    message: rule.message,
  };
}

function mapResponseToBreachCards(result: VaccineResponse): BreachCard[] {
  const len = Math.max(result.threatsDetected.length, result.injectionRules.length);
  const cards: BreachCard[] = [];
  for (let i = 0; i < len; i++) {
    const desc = result.threatsDetected[i] || "No description available";
    const rule = result.injectionRules[i] || { id: `rule-${i}`, type: "monitor" as const, expiresAt: 0 };
    cards.push(mapToBreachCard(desc, rule, i));
  }
  // Deduplicate by title (keep first)
  const seen = new Set<string>();
  return cards.filter((c) => { if (seen.has(c.title)) return false; seen.add(c.title); return true; });
}

// ---------------------------------------------------------------------------
// localStorage helpers
// ---------------------------------------------------------------------------

function loadVaccines(): VaccineRecord[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const all: VaccineRecord[] = JSON.parse(raw);
    // Garbage-collect truly expired records (older than 2h for logging purposes)
    const cutoff = Date.now() - 2 * VACCINE_TTL_MS;
    return all.filter((v) => new Date(v.expiresAt).getTime() > cutoff);
  } catch { return []; }
}

function saveVaccines(records: VaccineRecord[]): void {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(records)); } catch { /* ignore */ }
}

function applyVaccine(card: BreachCard, url: string, existing: VaccineRecord[]): VaccineRecord[] {
  const now = new Date();
  const record: VaccineRecord = {
    id: card.id,
    url,
    appliedAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + VACCINE_TTL_MS).toISOString(),
  };
  // Replace existing record with same id
  const filtered = existing.filter((v) => v.id !== card.id);
  return [...filtered, record];
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function VaccinePage() {
  const [mode, setMode] = useState<ScanMode>("website");
  const [url, setUrl] = useState("");
  const [textInput, setTextInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VaccineResponse | null>(null);
  const [analyzeResult, setAnalyzeResult] = useState<VaccineAnalyzeResponse | null>(null);
  const [breachCards, setBreachCards] = useState<BreachCard[]>([]);
  const [vaccines, setVaccines] = useState<VaccineRecord[] | null>(null); // null = not yet loaded
  const [error, setError] = useState<string | null>(null);
  const [showSynergos, setShowSynergos] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Load vaccines from localStorage on mount
  useEffect(() => {
    setVaccines(loadVaccines());
  }, []);

  async function handleScan() {
    setLoading(true);
    setError(null);
    setResult(null);
    setAnalyzeResult(null);
    setBreachCards([]);

    try {
      if (mode === "website" || mode === "qr") {
        const trimmed = url.trim();
        if (!trimmed) { setLoading(false); return; }
        const scanUrl = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
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
        setBreachCards(mapResponseToBreachCards(data));
      } else {
        // phone / sms / email — use the analyze endpoint
        const trimmed = textInput.trim();
        if (!trimmed) { setLoading(false); return; }
        const apiMode = mode; // "phone" | "sms" | "email"
        const res = await fetch("/api/vaccine/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mode: apiMode, input: trimmed }),
        });
        if (!res.ok) {
          const data = await res.json().catch(() => ({}));
          throw new Error(data.error || `Analysis failed (${res.status})`);
        }
        const data: VaccineAnalyzeResponse = await res.json();
        setAnalyzeResult(data);
        // Map VaccineBreachPoint → BreachCard so we can reuse the same UI
        setBreachCards(data.breachPoints.map((bp) => ({
          id: bp.id,
          title: bp.title,
          description: bp.description,
          severity: bp.severity,
          category: bp.category,
          ruleType: bp.ruleType,
          message: bp.message,
        })));
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally {
      setLoading(false);
    }
  }

  function handleVaccinate(card: BreachCard) {
    if (!result) return;
    const updated = applyVaccine(card, result.url, vaccines || []);
    setVaccines(updated);
    saveVaccines(updated);
  }

  function handleRevaccinate(card: BreachCard) {
    handleVaccinate(card);
  }

  const activeThreatLevel = result?.threatLevel.toLowerCase() ?? analyzeResult?.threatLevel ?? null;
  const threatColors = activeThreatLevel
    ? THREAT_COLORS[activeThreatLevel] || THREAT_COLORS.safe
    : null;
  const activeThreatScore = result?.threatScore ?? analyzeResult?.threatScore ?? 0;
  const activeUrl = result?.url ?? (analyzeResult ? `${analyzeResult.mode.toUpperCase()} scan` : "");

  const vaccinesReady = vaccines !== null;

  const currentMode = SCAN_MODES.find((m) => m.id === mode)!;
  const canScanNow = mode === "website" || mode === "qr" ? url.trim().length > 0 : textInput.trim().length > 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="relative">
            <Syringe size={26} className="text-shield" />
            <div className="absolute inset-0 bg-shield/20 rounded-full blur-lg" />
          </div>
          <h1 className="text-2xl font-bold text-text-primary">
            <span className="text-shield">Vaccine</span> Scanner
          </h1>
        </div>
        <p className="text-text-secondary text-sm">
          Scan websites, phone numbers, texts, and emails for scam threats. Vaccinate each breach for 1-hour protection.
        </p>
      </div>

      {/* Notice — non-intrusive */}
      <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-shield/5 border border-shield/15 text-xs text-text-muted">
        <Info size={12} className="text-shield shrink-0 mt-0.5" />
        Vaccines are client-side protection records stored on your device. We never modify or attack external sites.
      </div>

      {/* Scan Mode Tabs */}
      <div className="flex gap-1 p-1 rounded-xl bg-abyss/80 border border-border overflow-x-auto" data-tour="vaccine-modes">
        {SCAN_MODES.map((m) => {
          const Icon = m.icon;
          return (
            <button
              key={m.id}
              onClick={() => { setMode(m.id); setResult(null); setAnalyzeResult(null); setBreachCards([]); setError(null); }}
              className={`flex items-center gap-1.5 px-3 py-2 rounded-lg text-xs font-medium transition-all whitespace-nowrap flex-1 justify-center ${
                mode === m.id
                  ? "bg-shield/10 text-shield border border-shield/20"
                  : "text-text-muted hover:text-text-secondary"
              }`}
            >
              <Icon size={13} />
              <span className="hidden xs:inline sm:inline">{m.label}</span>
            </button>
          );
        })}
      </div>

      {/* Mode description */}
      <p className="text-xs text-text-muted -mt-2">{currentMode.desc}</p>

      {/* Scan Input */}
      <div className="glass-card p-5" data-tour="vaccine-input">
        <div className="flex flex-col sm:flex-row gap-3">
          {(mode === "website" || mode === "qr") ? (
            <div className="relative flex-1">
              {mode === "website" ? (
                <Globe size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-text-muted" />
              ) : (
                <QrCode size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-text-muted" />
              )}
              <input
                ref={inputRef}
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && !loading && handleScan()}
                placeholder={currentMode.placeholder}
                className="w-full pl-10 pr-4 py-3 rounded-xl bg-obsidian border border-border text-text-primary placeholder:text-text-muted text-sm font-mono focus:outline-none focus:border-shield/40 transition-all"
                disabled={loading}
              />
            </div>
          ) : (
            <textarea
              value={textInput}
              onChange={(e) => setTextInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && e.ctrlKey && !loading && handleScan()}
              placeholder={currentMode.placeholder}
              rows={4}
              className="flex-1 px-4 py-3 rounded-xl bg-obsidian border border-border text-text-primary placeholder:text-text-muted text-sm font-mono focus:outline-none focus:border-shield/40 transition-all resize-y min-h-[80px]"
              disabled={loading}
            />
          )}
          <button
            onClick={handleScan}
            disabled={loading || !canScanNow}
            data-tour="vaccine-scan-button"
            className="w-full sm:w-auto px-5 py-3 rounded-xl bg-shield/15 border border-shield/25 text-shield font-semibold text-sm hover:bg-shield/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2 shrink-0 sm:self-start"
          >
            {loading
              ? <><Loader2 size={15} className="animate-spin" />Scanning…</>
              : <><Syringe size={15} />Scan</>}
          </button>
        </div>
        {(mode === "sms" || mode === "email" || mode === "phone") && (
          <p className="text-[10px] text-text-muted mt-2">Press Ctrl+Enter to scan</p>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="glass-card p-4 border-danger/20 bg-danger/5 flex items-center gap-3">
          <AlertTriangle size={16} className="text-danger shrink-0" />
          <span className="text-danger text-sm">{error}</span>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="glass-card p-10 flex flex-col items-center gap-4">
          <div className="relative">
            <Shield size={44} className="text-shield animate-pulse" />
            <div className="absolute inset-0 bg-shield/20 rounded-full blur-xl animate-pulse" />
          </div>
          <div className="text-center">
            <p className="text-text-primary font-medium">SYNERGOS Engine Active</p>
            <p className="text-text-muted text-sm mt-1">Running 5-stage behavioral analysis…</p>
          </div>
          <div className="flex flex-wrap justify-center gap-4 mt-1">
            {["Graph Build", "Intent Field", "Game Theory", "Lyapunov", "Integration"].map((stage, i) => (
              <div key={stage} className="flex flex-col items-center gap-1">
                <div className={`w-2 h-2 rounded-full ${i < 3 ? "bg-shield animate-pulse" : "bg-slate-mid"}`} />
                <span className="text-[9px] font-mono text-text-muted">{stage}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Results */}
      {(result || analyzeResult) && !loading && (
        <div className="space-y-4">

          {/* Summary Banner */}
          <div className={`glass-card p-5 ${threatColors?.border} ${threatColors?.glow}`}>
            <div className="flex items-center gap-4 flex-wrap">
              {/* Score Ring */}
              <div className="relative w-14 h-14 shrink-0">
                <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                  <circle cx="50" cy="50" r="42" fill="none" stroke="currentColor" strokeWidth="7" className="text-slate-deep" />
                  <circle
                    cx="50" cy="50" r="42" fill="none" strokeWidth="7"
                    strokeDasharray={`${2 * Math.PI * 42}`}
                    strokeDashoffset={`${2 * Math.PI * 42 * (1 - activeThreatScore / 100)}`}
                    strokeLinecap="round"
                    className={threatColors?.text || "text-safe"}
                  />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className={`text-sm font-bold font-mono ${threatColors?.text}`}>{Math.round(activeThreatScore)}</span>
                </div>
              </div>

              <div className="flex-1 min-w-0">
                <div className={`text-xs font-mono uppercase tracking-widest ${threatColors?.text} mb-0.5`}>
                  {activeThreatLevel} threat
                </div>
                <div className="text-text-primary font-semibold text-sm">
                  {breachCards.length === 0
                    ? analyzeResult?.summary ?? "No breach points found"
                    : `${breachCards.length} breach point${breachCards.length !== 1 ? "s" : ""} detected`}
                </div>
                <div className="text-text-muted text-xs font-mono mt-0.5 truncate">{activeUrl}</div>
              </div>

              <div className="flex gap-3 shrink-0">
                {result && <QuickStat icon={Clock} label="Latency" value={`${result.latencyMs}ms`} />}
                {result && <QuickStat icon={Lock} label="Signed" value="HMAC" />}
                {analyzeResult && <QuickStat icon={Clock} label="Time" value={`${analyzeResult.processingTimeMs}ms`} />}
              </div>
            </div>
          </div>

          {/* Breach Cards — the main section */}
          {breachCards.length === 0 ? (
            <div className="glass-card p-8 text-center">
              <CheckCircle2 size={36} className="text-safe mx-auto mb-3" />
              <p className="text-text-primary font-medium">No breach points detected</p>
              <p className="text-text-muted text-sm mt-1">This site passed all security checks.</p>
            </div>
          ) : (
            <div className="space-y-3" data-tour="breach-cards">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-text-primary">Breach Points</h2>
                {vaccinesReady && (
                  <span className="text-xs text-text-muted">
                    {vaccines!.filter((v) => breachCards.some((c) => c.id === v.id) && new Date(v.expiresAt).getTime() > Date.now()).length}
                    /{breachCards.length} vaccinated
                  </span>
                )}
              </div>

              {breachCards.map((card) => {
                const vaccine = vaccinesReady
                  ? vaccines!.find((v) => v.id === card.id) ?? null
                  : null;
                return (
                  <BreachCardComponent
                    key={card.id}
                    card={card}
                    vaccine={vaccine}
                    onVaccinate={() => handleVaccinate(card)}
                    onRevaccinate={() => handleRevaccinate(card)}
                  />
                );
              })}
            </div>
          )}

          {/* SYNERGOS — collapsed by default (website scans only) */}
          {result?.synergosAnalysis && (
            <div className="glass-card overflow-hidden">
              <button
                onClick={() => setShowSynergos((v) => !v)}
                className="w-full flex items-center gap-3 p-4 text-left hover:bg-slate-deep/20 transition-colors"
              >
                <Brain size={16} className="text-shield shrink-0" />
                <span className="text-text-primary text-sm font-medium flex-1">SYNERGOS Behavioral Analysis</span>
                <span className={`text-xs font-mono px-2 py-0.5 rounded-full border ${
                  result.synergosAnalysis.verdict === "BLOCK" ? "bg-danger/10 text-danger border-danger/20"
                  : result.synergosAnalysis.verdict === "WARN"  ? "bg-caution/10 text-caution border-caution/20"
                  : "bg-safe/10 text-safe border-safe/20"
                }`}>
                  {result.synergosAnalysis.verdict} · {Math.round(result.synergosAnalysis.confidence * 100)}%
                </span>
                {showSynergos ? <ChevronUp size={15} className="text-text-muted" /> : <ChevronDown size={15} className="text-text-muted" />}
              </button>

              {showSynergos && result?.synergosAnalysis && (
                <div className="px-5 pb-5 space-y-4">
                  {/* Defense list */}
                  {result.synergosAnalysis.recommendedDefense.length > 0 && (
                    <div className="space-y-1.5">
                      <p className="text-xs font-medium text-text-muted uppercase tracking-wider">Recommended Defenses</p>
                      {result.synergosAnalysis.recommendedDefense.map((d, i) => (
                        <div key={i} className="flex items-start gap-2 text-xs text-text-secondary">
                          <CheckCircle2 size={12} className="text-safe shrink-0 mt-0.5" />
                          {d}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Attack prediction */}
                  {result.synergosAnalysis.nextAttackPrediction.tactics.length > 0 && (
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <TrendingUp size={13} className="text-caution" />
                        <span className="text-xs font-medium text-text-muted uppercase tracking-wider">Predicted Attack Vectors</span>
                        <span className="text-xs font-mono text-text-muted ml-auto">
                          {Math.round(result.synergosAnalysis.nextAttackPrediction.likelihood * 100)}% likelihood
                        </span>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        {result.synergosAnalysis.nextAttackPrediction.tactics.map((t) => (
                          <span key={t} className="px-2 py-0.5 rounded-lg bg-caution/10 border border-caution/15 text-caution text-xs font-mono">
                            {t.replace(/_/g, " ")}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Analysis pillars mini-grid */}
                  <div className="grid grid-cols-3 gap-2 pt-1">
                    {[
                      { icon: Network,     label: "Graph Laplacian" },
                      { icon: Target,      label: "Anomaly Detection" },
                      { icon: Activity,    label: "Lyapunov" },
                      { icon: Fingerprint, label: "Spectral" },
                      { icon: Thermometer, label: "Free Energy" },
                      { icon: Dna,         label: "Immune Memory" },
                    ].map(({ icon: Icon, label }) => (
                      <div key={label} className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-obsidian border border-border">
                        <Icon size={11} className="text-shield shrink-0" />
                        <span className="text-[10px] text-text-muted">{label}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Signature footer */}
          <div className="flex items-center gap-1.5 px-1 text-text-muted">
            <Lock size={10} />
            <span className="text-[10px] font-mono">
              {result
                ? `HMAC-SHA256 signed · ${new Date(result.signedAt).toLocaleTimeString()} · payload verified`
                : `${currentMode.label} scan · ${new Date().toLocaleTimeString()} · local analysis`}
            </span>
          </div>
        </div>
      )}

      {/* Empty state */}
      {!result && !analyzeResult && !loading && !error && (
        <div className="glass-card p-8 text-center">
          <Syringe size={40} className="text-slate-mid mx-auto mb-4" />
          <h3 className="text-text-secondary font-medium mb-2">
            {currentMode.id === "website" && "Enter a URL to scan for breach points"}
            {currentMode.id === "qr"      && "Paste the URL from your QR code to scan"}
            {currentMode.id === "phone"   && "Paste a phone number to check for fraud risk"}
            {currentMode.id === "sms"     && "Paste a suspicious text message to analyze"}
            {currentMode.id === "email"   && "Paste an email body or headers to analyze"}
          </h3>
          <p className="text-text-muted text-sm max-w-md mx-auto mb-6">{currentMode.desc}</p>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 max-w-xl mx-auto">
            {(currentMode.id === "website" || currentMode.id === "qr") ? [
              { icon: Network,     label: "Graph Physics",     desc: "Field dependency diffusion" },
              { icon: Target,      label: "Anomaly Detection", desc: "Payoff-based detection" },
              { icon: Activity,    label: "Chaos Analysis",    desc: "Lyapunov sensitivity" },
              { icon: Fingerprint, label: "Spectral IDs",      desc: "Eigenvalue signatures" },
              { icon: Thermometer, label: "Thermodynamics",    desc: "Free energy F = U − TS" },
              { icon: Dna,         label: "Immune Memory",     desc: "Variant matching" },
            ].map(({ icon: Icon, label, desc }) => (
              <div key={label} className="p-3 rounded-xl bg-obsidian/50 border border-border/50 text-left">
                <Icon size={14} className="text-shield mb-1.5" />
                <div className="text-text-secondary text-xs font-medium">{label}</div>
                <div className="text-text-muted text-[10px]">{desc}</div>
              </div>
            )) : [
              { icon: Brain,        label: "Deception Tactics",   desc: "Manipulation pattern matching" },
              { icon: AlertTriangle,label: "Authority Faking",    desc: "Fake official language detection" },
              { icon: Zap,          label: "Urgency Signals",     desc: "False time-pressure detection" },
              { icon: Phone,        label: "Phone Risk Scoring",  desc: "Premium-rate & scam area codes" },
              { icon: Activity,     label: "Emotional Exploit",   desc: "Fear, greed, empathy targeting" },
              { icon: Lock,         label: "Isolation Tactics",   desc: "Secrecy demand detection" },
            ].map(({ icon: Icon, label, desc }) => (
              <div key={label} className="p-3 rounded-xl bg-obsidian/50 border border-border/50 text-left">
                <Icon size={14} className="text-shield mb-1.5" />
                <div className="text-text-secondary text-xs font-medium">{label}</div>
                <div className="text-text-muted text-[10px]">{desc}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// BreachCard component
// ---------------------------------------------------------------------------

function BreachCardComponent({
  card,
  vaccine,
  onVaccinate,
  onRevaccinate,
}: {
  card: BreachCard;
  vaccine: VaccineRecord | null;
  onVaccinate: () => void;
  onRevaccinate: () => void;
}) {
  const [showDetail, setShowDetail] = useState(false);
  const isExpired = vaccine ? new Date(vaccine.expiresAt).getTime() <= Date.now() : false;
  const isActive = vaccine !== null && !isExpired;

  return (
    <div className={`glass-card border-l-4 ${SEVERITY_LEFT[card.severity]} overflow-hidden transition-all ${
      isActive ? "opacity-80" : ""
    }`}>
      <div className="p-4">
        <div className="flex items-start gap-3">
          {/* Severity icon */}
          <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5 ${
            isActive ? "bg-safe/10" : SEVERITY_COLORS[card.severity].split(" ")[0]
          }`}>
            {isActive
              ? <ShieldCheck size={14} className="text-safe" />
              : <XCircle size={14} className={`text-${card.severity === "critical" ? "critical" : card.severity === "high" ? "danger" : card.severity === "medium" ? "caution" : "safe"}`} />
            }
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1">
              <span className="text-sm font-semibold text-text-primary">{card.title}</span>
              <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${SEVERITY_COLORS[card.severity]}`}>
                {card.severity}
              </span>
              <span className="text-[10px] font-mono text-text-muted px-1.5 py-0.5 rounded border border-border bg-obsidian/40">
                {card.category}
              </span>
              <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${
                card.ruleType === "block" ? "bg-danger/10 text-danger border-danger/20"
                : card.ruleType === "warn" ? "bg-caution/10 text-caution border-caution/20"
                : "bg-shield/10 text-shield border-shield/20"
              }`}>
                {card.ruleType}
              </span>
            </div>
            <p className="text-xs text-text-secondary leading-relaxed">{card.description}</p>

            {/* Detail toggle */}
            {(card.selector || card.message) && (
              <button
                onClick={() => setShowDetail((v) => !v)}
                className="flex items-center gap-1 mt-1.5 text-[10px] text-text-muted hover:text-text-secondary transition-colors"
              >
                {showDetail ? <ChevronUp size={10} /> : <ChevronDown size={10} />}
                {showDetail ? "Less detail" : "More detail"}
              </button>
            )}
            {showDetail && (card.selector || card.message) && (
              <div className="mt-2 px-2 py-1.5 rounded bg-obsidian border border-border/50 text-[10px] font-mono text-text-muted space-y-0.5">
                {card.selector && <div><span className="text-shield">selector:</span> {card.selector}</div>}
                {card.message && <div><span className="text-shield">message:</span> {card.message}</div>}
              </div>
            )}
          </div>

          {/* Right: Vaccinate button or status */}
          <div className="shrink-0 ml-2">
            {isActive ? (
              <VaccineStatus expiresAt={vaccine!.expiresAt} onExpire={() => {/* re-render handled by timer */}} />
            ) : isExpired && vaccine ? (
              <button
                onClick={onRevaccinate}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-shield/30 bg-shield/5 text-shield text-xs font-semibold hover:bg-shield/10 transition-colors"
              >
                <RefreshCw size={11} />
                Re-vaccinate
              </button>
            ) : (
              <button
                onClick={onVaccinate}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-shield/30 bg-shield/10 text-shield text-xs font-semibold hover:bg-shield/20 transition-colors"
              >
                <Syringe size={11} />
                Vaccinate
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// VaccineStatus — countdown timer inside vaccinated card
// ---------------------------------------------------------------------------

function VaccineStatus({ expiresAt, onExpire }: { expiresAt: string; onExpire: () => void }) {
  const [remaining, setRemaining] = useState(() => new Date(expiresAt).getTime() - Date.now());

  useEffect(() => {
    if (remaining <= 0) { onExpire(); return; }
    const id = setInterval(() => {
      const r = new Date(expiresAt).getTime() - Date.now();
      setRemaining(r);
      if (r <= 0) { clearInterval(id); onExpire(); }
    }, 1000);
    return () => clearInterval(id);
  }, [expiresAt, onExpire, remaining]);

  if (remaining <= 0) return null;

  const mins = Math.floor(remaining / 60000);
  const secs = Math.floor((remaining % 60000) / 1000);

  return (
    <div className="flex flex-col items-center gap-1 px-3 py-1.5 rounded-lg bg-safe/5 border border-safe/20">
      <div className="flex items-center gap-1">
        <ShieldCheck size={12} className="text-safe" />
        <span className="text-xs font-semibold text-safe">Protected</span>
      </div>
      <div className="flex items-center gap-1 text-[10px] font-mono text-safe/70">
        <Clock size={9} />
        {mins}m {String(secs).padStart(2, "0")}s
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function QuickStat({ icon: Icon, label, value }: { icon: React.ComponentType<{ size?: number; className?: string }>; label: string; value: string }) {
  return (
    <div className="flex flex-col items-center gap-0.5">
      <Icon size={12} className="text-text-muted" />
      <span className="text-text-primary text-xs font-mono font-medium">{value}</span>
      <span className="text-text-muted text-[9px]">{label}</span>
    </div>
  );
}

