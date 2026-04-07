"use client";

import { useState, useEffect, useRef } from "react";
import {
  Shield, Syringe, Globe, Loader2, AlertTriangle, CheckCircle2,
  XCircle, ChevronDown, ChevronUp, Lock, Dna, Clock,
  ShieldCheck, Info, Copy, Check, ExternalLink,
  Network, Target,
  Activity, Fingerprint, Thermometer, Brain,
  Bookmark, Send,
} from "lucide-react";
import { dnaSegmentColor } from "@/lib/vaccine/threat-dna";
import { tierColor } from "@/lib/vaccine/immunity-model";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface InjectionRule {
  id: string;
  type: "block" | "warn" | "sandbox" | "disable" | "monitor";
  selector?: string;
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

interface ProtectResponse {
  script: string;
  modules: string[];
  moduleCount: number;
  url: string;
}

interface DNAResult {
  hex: string;
  dimensions: Array<{ name: string; intensity: number; label: string }>;
  dominantStrand: string;
  mutationClass: string;
  mutationLabel: string;
}

interface ImmunityResult {
  strength: number;
  peakStrength: number;
  tier: string;
  tierLabel: string;
  boosterDueAt: number;
  exposureCount: number;
  decayRateLabel: string;
  antibodies: Array<{ dimension: string; strength: number; targetLabel: string }>;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const THREAT_COLORS: Record<string, { text: string; border: string; glow: string }> = {
  safe:     { text: "text-safe",     border: "border-safe/20",     glow: "shadow-[0_0_20px_rgba(0,229,160,0.15)]" },
  low:      { text: "text-safe",     border: "border-safe/20",     glow: "" },
  medium:   { text: "text-caution",  border: "border-caution/20",  glow: "shadow-[0_0_20px_rgba(251,191,36,0.15)]" },
  high:     { text: "text-danger",   border: "border-danger/20",   glow: "shadow-[0_0_20px_rgba(255,59,92,0.15)]" },
  critical: { text: "text-critical", border: "border-critical/20", glow: "shadow-[0_0_25px_rgba(255,23,68,0.2)]" },
};

const SEVERITY_LEFT: Record<string, string> = {
  low: "border-l-safe", medium: "border-l-caution", high: "border-l-danger", critical: "border-l-critical",
};

const SEVERITY_BADGE: Record<string, string> = {
  low: "bg-safe/10 text-safe border-safe/20",
  medium: "bg-caution/10 text-caution border-caution/20",
  high: "bg-danger/10 text-danger border-danger/20",
  critical: "bg-critical/10 text-critical border-critical/20",
};

const RULE_SEVERITY: Record<string, BreachCard["severity"]> = {
  block: "critical", disable: "high", sandbox: "medium", warn: "medium", monitor: "low",
};

const TITLE_MAP: Array<{ keywords: string[]; title: string; category: string }> = [
  { keywords: ["phishing", "credential"],      title: "Credential Harvesting Form",       category: "Phishing"          },
  { keywords: ["payment", "card"],             title: "Fake Payment Form Detected",        category: "Financial Fraud"   },
  { keywords: ["entropy", "obfuscat"],         title: "Obfuscated Script Detected",        category: "Malicious Code"    },
  { keywords: ["cryptomin", "miner"],          title: "Cryptominer Script Found",          category: "Malware"           },
  { keywords: ["keylog"],                      title: "Keylogger Detected",                category: "Malware"           },
  { keywords: ["ransomware"],                  title: "Ransomware Pattern Detected",       category: "Malware"           },
  { keywords: ["malware", "exploit"],          title: "Malware Signature Found",           category: "Malware"           },
  { keywords: ["iframe"],                      title: "Hidden iFrame Injection",           category: "Script Injection"  },
  { keywords: ["redirect"],                    title: "Suspicious Redirect Chain",         category: "Redirect Attack"   },
  { keywords: ["xss"],                         title: "XSS Payload Detected",              category: "Script Injection"  },
  { keywords: ["urgency", "fake_urgency"],     title: "Fake Urgency Tactic",               category: "Social Engineering"},
  { keywords: ["trust", "badge"],              title: "Fake Trust Badge",                   category: "Deception"         },
  { keywords: ["spoof", "brand"],              title: "Spoofed Brand Identity",            category: "Phishing"          },
  { keywords: ["clipboard"],                   title: "Clipboard Hijacking",               category: "Malware"           },
  { keywords: ["popup"],                       title: "Popup Spam",                         category: "Deception"         },
  { keywords: ["external", "domain", "form"],  title: "Form Submits to External Domain",  category: "Phishing"          },
];

// Available protection modules that users can toggle
const ALL_MODULES = [
  { id: "block_external_forms",    name: "Block External Forms",    desc: "Stop forms sending data to foreign servers", default: true },
  { id: "block_credential_harvest", name: "Protect Credentials",     desc: "Block password/card data exfiltration", default: true },
  { id: "disable_clipboard_hijack", name: "Clipboard Shield",        desc: "Prevent scripts from changing your clipboard", default: true },
  { id: "remove_malicious_iframes", name: "Remove Hidden iFrames",   desc: "Remove invisible cross-origin iframes", default: true },
  { id: "block_popup_spam",         name: "Block Popup Spam",        desc: "Limit aggressive popups and exit traps", default: true },
  { id: "remove_fake_urgency",      name: "Kill Fake Urgency",       desc: "Disable countdown timers and pressure tactics", default: false },
  { id: "disable_malicious_scripts", name: "Block Eval Injection",   desc: "Stop obfuscated eval() code execution", default: true },
  { id: "monitor_network",          name: "Network Monitor",         desc: "Track which external servers the page contacts", default: true },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function mapToBreachCard(desc: string, rule: InjectionRule, i: number): BreachCard {
  const hay = `${desc} ${rule.id} ${rule.selector ?? ""} ${rule.message ?? ""}`.toLowerCase();
  let title = "Suspicious Behaviour Detected", category = "Unknown";
  for (const e of TITLE_MAP) { if (e.keywords.some(k => hay.includes(k))) { title = e.title; category = e.category; break; } }
  return { id: rule.id || `breach-${i}`, title, description: desc, severity: RULE_SEVERITY[rule.type] ?? "medium", category, ruleType: rule.type, selector: rule.selector, message: rule.message };
}

function mapResponseToBreachCards(r: VaccineResponse): BreachCard[] {
  const len = Math.max(r.threatsDetected.length, r.injectionRules.length);
  const cards: BreachCard[] = [];
  for (let i = 0; i < len; i++) {
    cards.push(mapToBreachCard(r.threatsDetected[i] ?? "Threat detected", r.injectionRules[i] ?? { id: `r-${i}`, type: "monitor" as const, expiresAt: 0 }, i));
  }
  const seen = new Set<string>();
  return cards.filter(c => { if (seen.has(c.title)) return false; seen.add(c.title); return true; });
}

function buildBookmarklet(url: string): string {
  const encoded = encodeURIComponent(url);
  return `javascript:void(fetch('${window.location.origin}/api/vaccine/protect',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url:location.href,threats:[],rules:[]})}).then(r=>r.json()).then(d=>{var s=document.createElement('script');s.textContent=d.script;document.head.appendChild(s)}).catch(e=>alert('ScamShieldy: '+e.message)))`;
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function VaccinePage() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<VaccineResponse | null>(null);
  const [breachCards, setBreachCards] = useState<BreachCard[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [showSynergos, setShowSynergos] = useState(false);
  const [enabledModules, setEnabledModules] = useState<Set<string>>(
    () => new Set(ALL_MODULES.filter(m => m.default).map(m => m.id))
  );
  const [scriptModal, setScriptModal] = useState<{ script: string; modules: string[]; url: string; rules: InjectionRule[]; copied: boolean; sent: boolean } | null>(null);
  const [showModules, setShowModules] = useState(false);
  const [showBookmarklet, setShowBookmarklet] = useState(false);
  const [extensionDetected, setExtensionDetected] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Detect if ScamShieldy extension is installed via ping/pong
  useEffect(() => {
    const handler = (e: MessageEvent) => {
      if (e.data?.type === 'SCAMSHIELDY_EXTENSION_PRESENT' || e.data?.type === 'SCAMSHIELDY_PONG') {
        setExtensionDetected(true);
      }
    };
    window.addEventListener('message', handler);
    // Ping the extension — content script will respond with PONG
    window.postMessage({ type: 'SCAMSHIELDY_PING' }, window.location.origin);
    // Retry after 800ms in case content script wasn't ready yet
    const t = setTimeout(() => window.postMessage({ type: 'SCAMSHIELDY_PING' }, window.location.origin), 800);
    return () => { window.removeEventListener('message', handler); clearTimeout(t); };
  }, []);

  async function handleScan() {
    const trimmed = url.trim();
    if (!trimmed) return;
    setLoading(true); setError(null); setResult(null); setBreachCards([]);
    try {
      const scanUrl = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
      const res = await fetch("/api/vaccine/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: scanUrl }),
      });
      if (!res.ok) { const d = await res.json().catch(() => ({})); throw new Error(d.error || `Scan failed (${res.status})`); }
      const data: VaccineResponse = await res.json();
      setResult(data);
      setBreachCards(mapResponseToBreachCards(data));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Scan failed");
    } finally { setLoading(false); }
  }

  async function handleVaccinate() {
    if (!result) return;
    try {
      const res = await fetch("/api/vaccine/protect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: result.url,
          threats: result.threatsDetected,
          rules: result.injectionRules,
          modules: [...enabledModules],
        }),
      });
      if (res.ok) {
        const data: ProtectResponse = await res.json();
        setScriptModal({ script: data.script, modules: data.modules, url: result.url, rules: result.injectionRules, copied: false, sent: false });
      }
    } catch { /* ignore */ }
  }

  const tl = result?.threatLevel.toLowerCase() ?? null;
  const tc = tl ? (THREAT_COLORS[tl] ?? THREAT_COLORS.safe) : null;

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
            <span className="text-shield">Scam</span> Vaccine
          </h1>
        </div>
        <p className="text-text-secondary text-sm">
          Scan any website and generate a real-time protection script that neutralizes threats — phishing forms,
          credential stealers, malware injections, clipboard hijackers — so you can visit the site safely.
        </p>
        <div className={`inline-flex items-center gap-1.5 mt-2 px-2.5 py-1 rounded-full text-[11px] font-mono border ${
          extensionDetected
            ? "bg-safe/10 border-safe/25 text-safe"
            : "bg-white/3 border-border text-text-muted"
        }`}>
          <div className={`w-1.5 h-1.5 rounded-full ${extensionDetected ? "bg-safe animate-pulse" : "bg-text-muted"}`} />
          {extensionDetected ? "Extension connected" : "Extension not detected"}
        </div>
      </div>

      {/* How it works — compact */}
      <div className="glass-card p-4 flex flex-wrap gap-x-6 gap-y-2 text-xs text-text-muted items-center">
        <Info size={13} className="text-shield shrink-0" />
        <span><strong className="text-text-secondary">1.</strong> Scan — detect threats</span>
        <span className="text-white/10">→</span>
        <span><strong className="text-text-secondary">2.</strong> Choose protection modules</span>
        <span className="text-white/10">→</span>
        <span><strong className="text-text-secondary">3.</strong> Vaccinate — generate protection script</span>
        <span className="text-white/10">→</span>
        <span><strong className="text-text-secondary">4.</strong> Send to extension — auto-applies when you visit the site</span>
      </div>

      {/* Scan Input */}
      <div className="glass-card p-5">
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Globe size={15} className="absolute left-3.5 top-1/2 -translate-y-1/2 text-text-muted" />
            <input
              ref={inputRef}
              type="text"
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === "Enter" && !loading && handleScan()}
              placeholder="Enter URL to vaccinate (e.g. suspicious-site.com)"
              className="w-full pl-10 pr-4 py-3 rounded-xl bg-obsidian border border-border text-text-primary placeholder:text-text-muted text-sm font-mono focus:outline-none focus:border-shield/40 transition-all"
              disabled={loading}
            />
          </div>
          <button
            onClick={handleScan}
            disabled={loading || !url.trim()}
            className="w-full sm:w-auto px-6 py-3 rounded-xl bg-shield/15 border border-shield/25 text-shield font-semibold text-sm hover:bg-shield/20 disabled:opacity-40 disabled:cursor-not-allowed transition-all flex items-center justify-center gap-2 shrink-0"
          >
            {loading ? <><Loader2 size={15} className="animate-spin" />Scanning…</> : <><Shield size={15} />Scan for Threats</>}
          </button>
        </div>
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
          <p className="text-text-primary font-medium">Analyzing URL for threats…</p>
          <p className="text-text-muted text-xs">VERIDICT engine — 13,000+ pattern matching</p>
          <div className="flex flex-wrap justify-center gap-4 mt-1">
            {["Patterns", "Fisher Cascade", "URL Intel", "Deception", "Classify"].map((s, i) => (
              <div key={s} className="flex flex-col items-center gap-1">
                <div className={`w-2 h-2 rounded-full ${i < 3 ? "bg-shield animate-pulse" : "bg-slate-mid"}`} />
                <span className="text-[9px] font-mono text-text-muted">{s}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Results */}
      {result && !loading && (
        <div className="space-y-4">

          {/* Summary */}
          <div className={`glass-card p-5 ${tc?.border} ${tc?.glow}`}>
            <div className="flex items-center gap-4 flex-wrap">
              <div className="relative w-14 h-14 shrink-0">
                <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                  <circle cx="50" cy="50" r="42" fill="none" stroke="currentColor" strokeWidth="7" className="text-slate-deep" />
                  <circle cx="50" cy="50" r="42" fill="none" strokeWidth="7"
                    strokeDasharray={`${2 * Math.PI * 42}`}
                    strokeDashoffset={`${2 * Math.PI * 42 * (1 - result.threatScore / 100)}`}
                    strokeLinecap="round" className={tc?.text ?? "text-safe"} />
                </svg>
                <div className="absolute inset-0 flex items-center justify-center">
                  <span className={`text-sm font-bold font-mono ${tc?.text}`}>{Math.round(result.threatScore)}</span>
                </div>
              </div>
              <div className="flex-1 min-w-0">
                <div className={`text-xs font-mono uppercase tracking-widest ${tc?.text} mb-0.5`}>{tl} threat</div>
                <div className="text-text-primary font-semibold text-sm">
                  {breachCards.length === 0 ? "No threats found — site appears safe" : `${breachCards.length} threat${breachCards.length !== 1 ? "s" : ""} detected — vaccine ready`}
                </div>
                <div className="text-text-muted text-xs font-mono mt-0.5 truncate">{result.url}</div>
              </div>
              <div className="flex gap-3 shrink-0">
                <MiniStat icon={Clock} label="Latency" value={`${result.latencyMs}ms`} />
                <MiniStat icon={Lock} label="Signed" value="HMAC" />
              </div>
            </div>
          </div>

          {/* Breach Cards */}
          {breachCards.length > 0 && (
            <div className="space-y-3">
              <h2 className="text-sm font-semibold text-text-primary">Threats Detected</h2>
              {breachCards.map(card => (
                <div key={card.id} className={`glass-card border-l-4 ${SEVERITY_LEFT[card.severity]} p-4`}>
                  <div className="flex items-start gap-3">
                    <div className={`w-7 h-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5 ${SEVERITY_BADGE[card.severity].split(" ")[0]}`}>
                      <XCircle size={14} className={card.severity === "critical" ? "text-critical" : card.severity === "high" ? "text-danger" : card.severity === "medium" ? "text-caution" : "text-safe"} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <span className="text-sm font-semibold text-text-primary">{card.title}</span>
                        <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${SEVERITY_BADGE[card.severity]}`}>{card.severity}</span>
                        <span className="text-[10px] font-mono text-text-muted px-1.5 py-0.5 rounded border border-border bg-obsidian/40">{card.category}</span>
                      </div>
                      <p className="text-xs text-text-secondary leading-relaxed">{card.description}</p>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Module Picker + Vaccinate Button */}
          {breachCards.length > 0 && (
            <div className="glass-card p-5 space-y-4 border border-shield/20">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-semibold text-text-primary flex items-center gap-2">
                  <Syringe size={14} className="text-shield" /> Build Protection Script
                </h2>
                <button onClick={() => setShowModules(v => !v)} className="text-xs text-shield hover:underline flex items-center gap-1">
                  {showModules ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                  {showModules ? "Hide" : "Choose"} modules
                </button>
              </div>

              {showModules && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {ALL_MODULES.map(m => (
                    <label key={m.id} className={`flex items-start gap-2.5 p-3 rounded-lg border cursor-pointer transition-all ${
                      enabledModules.has(m.id) ? "bg-shield/5 border-shield/25" : "bg-obsidian border-border hover:border-white/10"
                    }`}>
                      <input
                        type="checkbox"
                        checked={enabledModules.has(m.id)}
                        onChange={() => setEnabledModules(prev => {
                          const next = new Set(prev);
                          next.has(m.id) ? next.delete(m.id) : next.add(m.id);
                          return next;
                        })}
                        className="mt-0.5 accent-shield"
                      />
                      <div>
                        <div className="text-xs font-semibold text-text-primary">{m.name}</div>
                        <div className="text-[10px] text-text-muted">{m.desc}</div>
                      </div>
                    </label>
                  ))}
                </div>
              )}

              <p className="text-xs text-text-muted">
                {enabledModules.size} of {ALL_MODULES.length} protection modules selected.
                The script will intercept, block, and neutralize the threats found above.
              </p>

              <button
                onClick={handleVaccinate}
                className="w-full flex items-center justify-center gap-2 py-3 rounded-xl bg-shield hover:bg-shield/90 text-white font-semibold text-sm transition-colors"
              >
                <Syringe size={16} /> Generate Vaccine ({enabledModules.size} modules)
              </button>
            </div>
          )}

          {/* SYNERGOS (collapsed) */}
          {result.synergosAnalysis && (
            <div className="glass-card overflow-hidden">
              <button onClick={() => setShowSynergos(v => !v)}
                className="w-full flex items-center gap-3 p-4 text-left hover:bg-slate-deep/20 transition-colors">
                <Brain size={16} className="text-shield shrink-0" />
                <span className="text-text-primary text-sm font-medium flex-1">SYNERGOS Behavioral Analysis</span>
                <span className={`text-xs font-mono px-2 py-0.5 rounded-full border ${
                  result.synergosAnalysis.verdict === "BLOCK" ? "bg-danger/10 text-danger border-danger/20"
                  : result.synergosAnalysis.verdict === "WARN" ? "bg-caution/10 text-caution border-caution/20"
                  : "bg-safe/10 text-safe border-safe/20"
                }`}>{result.synergosAnalysis.verdict} · {Math.round(result.synergosAnalysis.confidence * 100)}%</span>
                {showSynergos ? <ChevronUp size={15} className="text-text-muted" /> : <ChevronDown size={15} className="text-text-muted" />}
              </button>
              {showSynergos && (
                <div className="px-5 pb-5 space-y-3">
                  {result.synergosAnalysis.recommendedDefense.length > 0 && (
                    <div className="space-y-1.5">
                      <p className="text-xs font-medium text-text-muted uppercase tracking-wider">Recommended Defenses</p>
                      {result.synergosAnalysis.recommendedDefense.map((d, i) => (
                        <div key={i} className="flex items-start gap-2 text-xs text-text-secondary"><CheckCircle2 size={12} className="text-safe shrink-0 mt-0.5" />{d}</div>
                      ))}
                    </div>
                  )}
                  {result.synergosAnalysis.nextAttackPrediction.tactics.length > 0 && (
                    <div>
                      <p className="text-xs font-medium text-text-muted uppercase tracking-wider mb-2">Predicted Attack Vectors — {Math.round(result.synergosAnalysis.nextAttackPrediction.likelihood * 100)}% likelihood</p>
                      <div className="flex flex-wrap gap-2">
                        {result.synergosAnalysis.nextAttackPrediction.tactics.map(t => (
                          <span key={t} className="px-2 py-0.5 rounded-lg bg-caution/10 border border-caution/15 text-caution text-xs font-mono">{t.replace(/_/g, " ")}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  <div className="grid grid-cols-3 gap-2 pt-1">
                    {[
                      { icon: Network, label: "Graph Laplacian" }, { icon: Target, label: "Anomaly Detection" },
                      { icon: Activity, label: "Lyapunov" }, { icon: Fingerprint, label: "Spectral" },
                      { icon: Thermometer, label: "Free Energy" }, { icon: Dna, label: "Immune Memory" },
                    ].map(({ icon: Icon, label }) => (
                      <div key={label} className="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-obsidian border border-border">
                        <Icon size={11} className="text-shield shrink-0" /><span className="text-[10px] text-text-muted">{label}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Bookmarklet */}
          <div className="glass-card p-4">
            <button onClick={() => setShowBookmarklet(v => !v)} className="w-full flex items-center gap-2 text-left">
              <Bookmark size={14} className="text-shield" />
              <span className="text-sm font-medium text-text-primary flex-1">One-Click Bookmarklet</span>
              {showBookmarklet ? <ChevronUp size={13} className="text-text-muted" /> : <ChevronDown size={13} className="text-text-muted" />}
            </button>
            {showBookmarklet && (
              <div className="mt-3 space-y-3">
                <p className="text-xs text-text-secondary">Drag the button below to your bookmarks bar. Then click it on any suspicious page to instantly apply ScamShieldy&apos;s vaccine.</p>
                <div className="flex items-center gap-3">
                  <a
                    href={buildBookmarklet(result.url)}
                    className="px-4 py-2 rounded-lg bg-shield text-white font-semibold text-xs cursor-grab active:cursor-grabbing no-underline"
                    onClick={e => e.preventDefault()}
                    title="Drag this to your bookmarks bar"
                  >
                    🛡️ ScamShieldy Vaccine
                  </a>
                  <span className="text-[10px] text-text-muted">← Drag to bookmarks bar</span>
                </div>
              </div>
            )}
          </div>

          {/* Signature */}
          <div className="flex items-center gap-1.5 px-1 text-text-muted">
            <Lock size={10} />
            <span className="text-[10px] font-mono">
              HMAC-SHA256 signed · {new Date(result.signedAt).toLocaleTimeString()} · payload verified
            </span>
          </div>
        </div>
      )}

      {/* Empty state */}
      {!result && !loading && !error && (
        <div className="glass-card p-8 text-center">
          <Shield size={40} className="text-slate-mid mx-auto mb-4" />
          <h3 className="text-text-secondary font-medium mb-2">Enter a URL to generate a protection vaccine</h3>
          <p className="text-text-muted text-sm max-w-md mx-auto mb-6">
            We scrape the website, detect phishing forms, malware scripts, credential stealers, and fake urgency elements — then build a JavaScript vaccine that neutralizes them when you visit.
          </p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 max-w-2xl mx-auto">
            {[
              { icon: Shield,       label: "Blocks phishing forms" },
              { icon: Lock,         label: "Protects credentials" },
              { icon: XCircle,      label: "Removes hidden iframes" },
              { icon: AlertTriangle, label: "Kills fake urgency" },
            ].map(({ icon: Icon, label }) => (
              <div key={label} className="p-3 rounded-xl bg-obsidian/50 border border-border/50 text-left">
                <Icon size={14} className="text-shield mb-1.5" />
                <div className="text-text-muted text-[10px]">{label}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Script Modal */}
      {scriptModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-void/80 backdrop-blur-sm">
          <div className="glass-card w-full max-w-2xl max-h-[90vh] flex flex-col border border-shield/30">
            <div className="flex items-center gap-3 p-4 border-b border-white/5">
              <div className="w-8 h-8 rounded-lg bg-shield/10 border border-shield/20 flex items-center justify-center" style={{flexShrink: 0}}>
                <ShieldCheck size={16} className="text-shield" />
              </div>
              <div style={{flex: 1, minWidth: 0, overflow: 'hidden'}}>
                <h2 className="text-sm font-semibold text-text-primary" style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>Vaccine Ready — {scriptModal.modules.length} modules active</h2>
                <p className="text-xs text-text-muted font-mono" style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{scriptModal.url}</p>
              </div>
              <button
                onClick={() => setScriptModal(null)}
                style={{flexShrink: 0, width: 32, height: 32, display:'flex', alignItems:'center', justifyContent:'center', borderRadius: 8, background: 'rgba(255,255,255,0.06)', cursor:'pointer', border:'none', color:'#8892a4', fontSize: 16}}
                onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.12)')}
                onMouseLeave={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.06)')}
              >✕</button>
            </div>

            <div className="px-5 pt-4 pb-2">
              <div className="flex flex-wrap gap-1.5">
                {scriptModal.modules.map(m => (
                  <span key={m} className="text-[10px] font-mono px-2 py-0.5 rounded-lg bg-shield/10 border border-shield/20 text-shield">{m}</span>
                ))}
              </div>
            </div>

            <div className="p-5 pt-0 space-y-3">
              {/* Primary: Send to Extension */}
              <button
                onClick={() => {
                  if (!scriptModal) return;
                  window.postMessage({
                    type: 'SCAMSHIELDY_VACCINE_INJECT',
                    url: scriptModal.url,
                    rules: scriptModal.rules,
                  }, window.location.origin);
                  setScriptModal(s => s ? { ...s, sent: true } : null);
                }}
                disabled={scriptModal.sent || !extensionDetected}
                className={`w-full flex items-center justify-center gap-2 py-3 rounded-xl font-semibold text-sm transition-all ${
                  scriptModal.sent
                    ? "bg-safe/15 border border-safe/30 text-safe cursor-default"
                    : extensionDetected
                    ? "bg-shield hover:bg-shield/90 text-white"
                    : "bg-obsidian border border-border text-text-muted cursor-not-allowed opacity-50"
                }`}
              >
                {scriptModal.sent
                  ? <><Check size={16} /> Vaccine sent — visit the site to activate</>
                  : extensionDetected
                  ? <><Send size={16} /> Send to Extension</>
                  : <><Send size={16} /> Extension not detected — install it first</>
                }
              </button>
              {!extensionDetected && !scriptModal.sent && (
                <p className="text-[11px] text-text-muted text-center">
                  Install the <a href="/download" className="text-shield underline">ScamShieldy Extension</a> to use one-click injection. Or use copy script below.
                </p>
              )}

              {scriptModal.sent && (
                <p className="text-[11px] text-text-muted text-center">
                  Protection will auto-apply the next time you visit <span className="font-mono text-shield">{new URL(scriptModal.url).hostname}</span>
                </p>
              )}

              {/* Secondary row */}
              <div className="flex gap-2">
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(scriptModal.script).then(() => {
                      setScriptModal(s => s ? { ...s, copied: true } : null);
                      setTimeout(() => setScriptModal(s => s ? { ...s, copied: false } : null), 2500);
                    });
                  }}
                  className="flex-1 flex items-center justify-center gap-1.5 py-2 rounded-xl bg-obsidian border border-border text-text-muted text-xs hover:border-shield/30 hover:text-shield transition-colors"
                >
                  {scriptModal.copied ? <><Check size={13} />Copied</> : <><Copy size={13} />Copy script (no extension)</>}
                </button>
                <a href={scriptModal.url} target="_blank" rel="noopener noreferrer"
                  className="flex items-center justify-center gap-1.5 px-3 py-2 rounded-xl bg-obsidian border border-border text-text-muted text-xs hover:border-shield/30 hover:text-shield transition-colors">
                  <ExternalLink size={13} />Open site
                </a>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Small components
// ---------------------------------------------------------------------------

function MiniStat({ icon: Icon, label, value }: { icon: React.ComponentType<{ size?: number; className?: string }>; label: string; value: string }) {
  return (
    <div className="flex flex-col items-center gap-0.5">
      <Icon size={12} className="text-text-muted" />
      <span className="text-text-primary text-xs font-mono font-medium">{value}</span>
      <span className="text-text-muted text-[9px]">{label}</span>
    </div>
  );
}
