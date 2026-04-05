"use client";

import { useState, useCallback, useRef } from "react";
import {
  Upload,
  FileText,
  Search,
  CheckCircle,
  AlertTriangle,
  Loader2,
  Copy,
  Download,
  Shield,
  Sparkles,
  ClipboardPaste,
  RefreshCw,
  ExternalLink,
  Database,
  TrendingUp,
  Rss,
} from "lucide-react";

// ---------------------------------------------------------------------------
// Types (mirrors the server-side ExtractedPattern)
// ---------------------------------------------------------------------------

interface ExtractedPattern {
  text: string;
  category: string;
  frequency: number;
  specificityScore: number;
  suggestedWeight: number;
  suggestedSeverity: "low" | "medium" | "high" | "critical";
  sourceExamples: string[];
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SEVERITY_COLORS: Record<string, string> = {
  low: "bg-border/50 text-text-muted border-border",
  medium: "bg-caution/10 text-caution border-caution/20",
  high: "bg-danger/10 text-danger border-danger/20",
  critical: "bg-critical/10 text-critical border-critical/20",
};

const CATEGORY_COLORS: Record<string, string> = {
  URGENCY: "bg-orange-400/10 text-orange-400 border-orange-400/20",
  FINANCIAL: "bg-green-400/10 text-green-400 border-green-400/20",
  ROMANCE: "bg-pink-400/10 text-pink-400 border-pink-400/20",
  PHISHING: "bg-red-400/10 text-red-400 border-red-400/20",
  CRYPTO_INVESTMENT: "bg-yellow-400/10 text-yellow-400 border-yellow-400/20",
  GOVERNMENT_IMPERSONATION: "bg-blue-400/10 text-blue-400 border-blue-400/20",
  TECH_SUPPORT: "bg-purple-400/10 text-purple-400 border-purple-400/20",
  PACKAGE_DELIVERY: "bg-amber-400/10 text-amber-400 border-amber-400/20",
  LOTTERY_PRIZE: "bg-emerald-400/10 text-emerald-400 border-emerald-400/20",
  EMPLOYMENT: "bg-cyan-400/10 text-cyan-400 border-cyan-400/20",
  // Malware / web threat categories
  MALWARE_DISTRIBUTION: "bg-red-600/10 text-red-500 border-red-600/20",
  DRIVE_BY_DOWNLOAD: "bg-red-500/10 text-red-400 border-red-500/20",
  RANSOMWARE_DELIVERY: "bg-rose-500/10 text-rose-400 border-rose-500/20",
  EXPLOIT_KIT: "bg-violet-500/10 text-violet-400 border-violet-500/20",
  SPYWARE_STALKERWARE: "bg-fuchsia-500/10 text-fuchsia-400 border-fuchsia-500/20",
  FAKE_ANTIVIRUS: "bg-indigo-400/10 text-indigo-400 border-indigo-400/20",
  MALVERTISING: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  CREDENTIAL_STEALER: "bg-red-400/10 text-red-400 border-red-400/20",
  BOTNET_C2: "bg-slate-400/10 text-slate-400 border-slate-400/20",
  URL_OBFUSCATION: "bg-zinc-400/10 text-zinc-400 border-zinc-400/20",
  DOMAIN_SQUATTING: "bg-stone-400/10 text-stone-400 border-stone-400/20",
  SEO_POISONING: "bg-lime-400/10 text-lime-400 border-lime-400/20",
  SOCIAL_ENGINEERING: "bg-teal-400/10 text-teal-400 border-teal-400/20",
  BRAND_IMPERSONATION: "bg-sky-400/10 text-sky-400 border-sky-400/20",
  GENERIC: "bg-border/50 text-text-muted border-border",
};

// ---------------------------------------------------------------------------
// Free threat intel data sources admins can download from
// ---------------------------------------------------------------------------

const DATA_SOURCES = [
  {
    name: "URLhaus (abuse.ch)",
    url: "https://urlhaus.abuse.ch/downloads/",
    description: "Active malware distribution URLs. Updated multiple times daily. Download full CSV/TXT lists.",
    formats: ["CSV", "TXT"],
    updateFreq: "Live / hourly",
    category: "Malware URLs",
    highlight: true,
  },
  {
    name: "PhishTank",
    url: "https://phishtank.org/developer_info.php",
    description: "Verified phishing URLs submitted by the community. Free API + CSV download.",
    formats: ["CSV", "JSON"],
    updateFreq: "Hourly",
    category: "Phishing",
    highlight: true,
  },
  {
    name: "OpenPhish",
    url: "https://openphish.com/feed.txt",
    description: "Community phishing feed — plain text list of active phishing URLs.",
    formats: ["TXT"],
    updateFreq: "Every 12h",
    category: "Phishing",
    highlight: false,
  },
  {
    name: "MalwareBazaar (abuse.ch)",
    url: "https://bazaar.abuse.ch/export/",
    description: "Malware samples database. Download recent IOCs as CSV with tags, signatures, and threat names.",
    formats: ["CSV", "JSON"],
    updateFreq: "Daily",
    category: "Malware IOCs",
    highlight: true,
  },
  {
    name: "Feodo Tracker (abuse.ch)",
    url: "https://feodotracker.abuse.ch/downloads/",
    description: "C2 botnet tracker for Emotet, TrickBot, QBot, etc. Blocklists in multiple formats.",
    formats: ["CSV", "TXT"],
    updateFreq: "Daily",
    category: "Botnet C2",
    highlight: false,
  },
  {
    name: "SSLBL (abuse.ch)",
    url: "https://sslbl.abuse.ch/blacklist/",
    description: "Malicious SSL certificates and JA3 fingerprints used by malware C2 infrastructure.",
    formats: ["CSV", "TXT"],
    updateFreq: "Daily",
    category: "SSL/TLS IOCs",
    highlight: false,
  },
  {
    name: "PhishStats",
    url: "https://phishstats.info/",
    description: "Real-time phishing intelligence. Free CSV download of recent phishing sites with scores.",
    formats: ["CSV"],
    updateFreq: "Every 15 min",
    category: "Phishing",
    highlight: false,
  },
  {
    name: "Spamhaus Domain Blocklist",
    url: "https://www.spamhaus.org/blocklists/domain-blocklist/",
    description: "Domain-based threat intelligence. Free access for non-commercial use. High quality.",
    formats: ["TXT"],
    updateFreq: "Continuous",
    category: "Spam/Malware Domains",
    highlight: true,
  },
  {
    name: "Emerging Threats (Proofpoint)",
    url: "https://rules.emergingthreats.net/blockrules/",
    description: "IDS/IPS rules and blocklists for emerging threats. Free community ruleset available.",
    formats: ["TXT", "Rules"],
    updateFreq: "Daily",
    category: "Network Threats",
    highlight: false,
  },
  {
    name: "CISA Known Exploited Vulnerabilities",
    url: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    description: "US government catalog of actively exploited CVEs. CSV download available. Great for exploit kit patterns.",
    formats: ["CSV", "JSON"],
    updateFreq: "Weekly",
    category: "Exploit Kits",
    highlight: false,
  },
  {
    name: "Google Safe Browsing API",
    url: "https://developers.google.com/safe-browsing/v4/lists",
    description: "Phishing, malware, and unwanted software lists from Google. Free API with generous quota.",
    formats: ["API"],
    updateFreq: "Every 30 min",
    category: "Phishing/Malware",
    highlight: true,
  },
  {
    name: "MalShare",
    url: "https://malshare.com/daily/",
    description: "Daily malware repository. Download hash lists and malware samples. Free API available.",
    formats: ["TXT", "JSON"],
    updateFreq: "Daily",
    category: "Malware Samples",
    highlight: false,
  },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function AdminPatternsPage() {
  // File upload state
  const [dragOver, setDragOver] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [uploadSuccess, setUploadSuccess] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Extracted patterns state
  const [extractedPatterns, setExtractedPatterns] = useState<ExtractedPattern[]>([]);
  const [selectedPatterns, setSelectedPatterns] = useState<Set<number>>(new Set());
  const [approving, setApproving] = useState(false);
  const [approveResult, setApproveResult] = useState<string | null>(null);

  // Saved patterns state
  const [savedPatterns, setSavedPatterns] = useState<ExtractedPattern[]>([]);
  const [loadingSaved, setLoadingSaved] = useState(false);

  // Live feed sync state
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState<string | null>(null);
  const [syncError, setSyncError] = useState<string | null>(null);

  // LLM prompt state
  const [copiedPrompt, setCopiedPrompt] = useState(false);
  const [llmOutput, setLlmOutput] = useState("");
  const [llmParsing, setLlmParsing] = useState(false);
  const [llmError, setLlmError] = useState<string | null>(null);

  // --- File Upload ---

  const handleFile = useCallback(async (file: File) => {
    setUploadError(null);
    setUploadSuccess(null);
    setExtractedPatterns([]);
    setSelectedPatterns(new Set());
    setApproveResult(null);

    const ext = file.name.split(".").pop()?.toLowerCase();
    if (!ext || !["pdf", "csv", "txt"].includes(ext)) {
      setUploadError("Unsupported file type. Accepted: PDF, CSV, TXT.");
      return;
    }

    if (file.size > 10 * 1024 * 1024) {
      setUploadError("File too large. Maximum: 10 MB.");
      return;
    }

    setUploading(true);
    try {
      const formData = new FormData();
      formData.append("file", file);

      const res = await fetch("/api/admin/patterns", {
        method: "POST",
        body: formData,
      });

      const data = await res.json();
      if (!res.ok) {
        setUploadError(data.error || "Upload failed.");
        return;
      }

      setExtractedPatterns(data.patterns || []);
      setUploadSuccess(
        `Extracted ${data.patterns?.length ?? 0} patterns from ${data.chunksExtracted} text chunks in "${data.filename}".`
      );
    } catch {
      setUploadError("Network error. Please try again.");
    } finally {
      setUploading(false);
    }
  }, []);

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  const onFileInput = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  // --- Pattern selection ---

  const togglePattern = (idx: number) => {
    setSelectedPatterns((prev) => {
      const next = new Set(prev);
      if (next.has(idx)) next.delete(idx);
      else next.add(idx);
      return next;
    });
  };

  const toggleAll = () => {
    if (selectedPatterns.size === extractedPatterns.length) {
      setSelectedPatterns(new Set());
    } else {
      setSelectedPatterns(new Set(extractedPatterns.map((_, i) => i)));
    }
  };

  // --- Approve selected ---

  const approveSelected = async () => {
    const toApprove = extractedPatterns.filter((_, i) => selectedPatterns.has(i));
    if (toApprove.length === 0) return;

    setApproving(true);
    setApproveResult(null);
    try {
      const res = await fetch("/api/admin/patterns", {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ patterns: toApprove }),
      });
      const data = await res.json();
      if (!res.ok) {
        setApproveResult(`Error: ${data.error}`);
        return;
      }
      const parts = [`✅ Added ${data.added} new patterns`];
      if (data.upgraded > 0) parts.push(`⬆️ ${data.upgraded} upgraded`);
      if (data.duplicatesSkipped > 0) parts.push(`${data.duplicatesSkipped} duplicates skipped`);
      parts.push(`Total: ${data.total}`);
      setApproveResult(parts.join(" · "));
      // Remove approved patterns from the list
      setExtractedPatterns((prev) => prev.filter((_, i) => !selectedPatterns.has(i)));
      setSelectedPatterns(new Set());
    } catch {
      setApproveResult("Network error. Please try again.");
    } finally {
      setApproving(false);
    }
  };

  // --- Load saved patterns ---

  const loadSavedPatterns = async () => {
    setLoadingSaved(true);
    try {
      const res = await fetch("/api/admin/patterns");
      if (res.ok) {
        const data = await res.json();
        setSavedPatterns(data.patterns || []);
      }
    } catch {
      // ignore
    }
    setLoadingSaved(false);
  };

  // --- LLM output import ---

  const importLlmOutput = async () => {
    if (!llmOutput.trim()) return;
    setLlmError(null);
    setLlmParsing(true);

    try {
      const res = await fetch("/api/admin/patterns", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ llmOutput }),
      });
      const data = await res.json();
      if (!res.ok) {
        setLlmError(data.error || "Failed to parse LLM output.");
        return;
      }

      setExtractedPatterns(data.patterns || []);
      setSelectedPatterns(new Set());
      setUploadSuccess(`Parsed ${data.patterns?.length ?? 0} patterns from LLM output.`);
      setUploadError(null);
      setLlmOutput("");
    } catch {
      setLlmError("Network error. Please try again.");
    } finally {
      setLlmParsing(false);
    }
  };

  // --- Sync from live threat intel feeds ---

  const syncFromFeeds = async () => {
    setSyncing(true);
    setSyncResult(null);
    setSyncError(null);
    try {
      const res = await fetch("/api/admin/patterns/sync", { method: "POST" });
      const data = await res.json();
      if (!res.ok || !data.success) {
        setSyncError(data.error || "Sync failed.");
        return;
      }
      const parts = [
        `Processed ${data.urlsProcessed} URLs from URLhaus (${data.sources?.urlhaus ?? 0}) + OpenPhish (${data.sources?.openphish ?? 0})`,
        `→ ${data.patternsExtracted} extracted`,
        `✅ ${data.added} added`,
      ];
      if (data.upgraded > 0) parts.push(`⬆️ ${data.upgraded} upgraded`);
      if (data.duplicatesSkipped > 0) parts.push(`${data.duplicatesSkipped} skipped`);
      parts.push(`Total: ${data.total}`);
      setSyncResult(parts.join(" · "));
    } catch {
      setSyncError("Network error. Check that threat intel feeds are reachable.");
    } finally {
      setSyncing(false);
    }
  };

  // --- Copy prompt ---

  const copyPrompt = async () => {
    try {
      const res = await fetch("/api/admin/patterns/prompt");
      if (res.ok) {
        const data = await res.json();
        await navigator.clipboard.writeText(data.prompt);
      } else {
        // Fallback: use a minimal version
        await navigator.clipboard.writeText(
          "Could not load prompt from API. Visit the admin patterns page for the full prompt template."
        );
      }
    } catch {
      // Fallback: copy directly from constant
      await navigator.clipboard.writeText(
        "Error loading prompt. Please refresh and try again."
      );
    }
    setCopiedPrompt(true);
    setTimeout(() => setCopiedPrompt(false), 2000);
  };

  // -------------------------------------------------------------------------
  // Render
  // -------------------------------------------------------------------------

  return (
    <div className="max-w-7xl mx-auto px-4 py-8 space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-shield/10 border border-shield/20 flex items-center justify-center">
            <Sparkles className="w-5 h-5 text-shield" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-text-primary">Pattern Ingestion</h1>
            <p className="text-sm text-text-muted">Upload fraud data to extract and approve new scam patterns</p>
          </div>
        </div>
        <button
          onClick={syncFromFeeds}
          disabled={syncing}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-shield/10 border border-shield/30 text-shield text-sm font-semibold hover:bg-shield/20 transition-colors disabled:opacity-50"
        >
          {syncing ? <Loader2 size={14} className="animate-spin" /> : <Rss size={14} />}
          {syncing ? "Syncing…" : "Sync from Live Feeds"}
        </button>
      </div>

      {/* Sync result / error */}
      {syncResult && (
        <div className="flex items-start gap-2 p-3 rounded-lg bg-safe/10 border border-safe/20 text-safe text-xs">
          <CheckCircle size={13} className="shrink-0 mt-0.5" />
          {syncResult}
        </div>
      )}
      {syncError && (
        <div className="flex items-start gap-2 p-3 rounded-lg bg-danger/10 border border-danger/20 text-danger text-xs">
          <AlertTriangle size={13} className="shrink-0 mt-0.5" />
          {syncError}
        </div>
      )}

      {/* File Upload Area */}
      <section className="glass-card p-6 space-y-4">
        <div className="flex items-center gap-2 mb-2">
          <Upload className="w-5 h-5 text-shield" />
          <h2 className="text-lg font-semibold text-text-primary">Upload Fraud Data</h2>
        </div>

        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
          onClick={() => fileInputRef.current?.click()}
          className={`relative flex flex-col items-center justify-center gap-3 p-10 rounded-xl border-2 border-dashed cursor-pointer transition-all ${
            dragOver
              ? "border-shield bg-shield/5"
              : "border-border hover:border-shield/30 hover:bg-white/[0.02]"
          }`}
        >
          {uploading ? (
            <Loader2 className="w-8 h-8 animate-spin text-shield" />
          ) : (
            <FileText className="w-8 h-8 text-text-muted" />
          )}
          <div className="text-center">
            <p className="text-sm text-text-primary font-medium">
              {uploading ? "Processing file..." : "Drop a file here or click to browse"}
            </p>
            <p className="text-xs text-text-muted mt-1">
              Accepts PDF, CSV, or TXT files (max 10 MB)
            </p>
          </div>
          <input
            ref={fileInputRef}
            type="file"
            accept=".pdf,.csv,.txt"
            onChange={onFileInput}
            className="hidden"
          />
        </div>

        {uploadError && (
          <div className="flex items-center gap-2 p-3 rounded-lg bg-danger/10 border border-danger/20 text-danger text-sm">
            <AlertTriangle size={14} />
            {uploadError}
          </div>
        )}

        {uploadSuccess && (
          <div className="flex items-center gap-2 p-3 rounded-lg bg-safe/10 border border-safe/20 text-safe text-sm">
            <CheckCircle size={14} />
            {uploadSuccess}
          </div>
        )}
      </section>

      {/* Extracted Patterns Table */}
      {extractedPatterns.length > 0 && (
        <section className="glass-card overflow-hidden">
          <div className="flex items-center justify-between p-4 border-b border-border">
            <div className="flex items-center gap-2">
              <Search size={16} className="text-shield" />
              <h2 className="text-lg font-semibold text-text-primary">
                Extracted Patterns ({extractedPatterns.length})
              </h2>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={toggleAll}
                className="px-3 py-1.5 rounded-lg border border-border text-xs text-text-secondary hover:text-text-primary transition-colors"
              >
                {selectedPatterns.size === extractedPatterns.length ? "Deselect All" : "Select All"}
              </button>
              <button
                onClick={approveSelected}
                disabled={selectedPatterns.size === 0 || approving}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-shield text-void font-semibold text-xs hover:bg-shield/90 transition-colors disabled:opacity-50"
              >
                {approving ? <Loader2 size={12} className="animate-spin" /> : <CheckCircle size={12} />}
                Approve Selected ({selectedPatterns.size})
              </button>
            </div>
          </div>

          {approveResult && (
            <div className="px-4 pt-3">
              <div className={`flex items-center gap-2 p-2 rounded-lg text-sm ${
                approveResult.startsWith("Error")
                  ? "bg-danger/10 border border-danger/20 text-danger"
                  : "bg-safe/10 border border-safe/20 text-safe"
              }`}>
                {approveResult.startsWith("Error") ? <AlertTriangle size={13} /> : <CheckCircle size={13} />}
                {approveResult}
              </div>
            </div>
          )}

          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left">
                  <th className="px-4 py-3 w-8">
                    <input
                      type="checkbox"
                      checked={selectedPatterns.size === extractedPatterns.length && extractedPatterns.length > 0}
                      onChange={toggleAll}
                      className="rounded border-border"
                    />
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-text-muted">Pattern</th>
                  <th className="px-4 py-3 text-xs font-medium text-text-muted">Category</th>
                  <th className="px-4 py-3 text-xs font-medium text-text-muted">Frequency</th>
                  <th className="px-4 py-3 text-xs font-medium text-text-muted">Severity</th>
                  <th className="px-4 py-3 text-xs font-medium text-text-muted">Weight</th>
                  <th className="px-4 py-3 text-xs font-medium text-text-muted">Specificity</th>
                </tr>
              </thead>
              <tbody>
                {extractedPatterns.map((p, i) => (
                  <tr
                    key={i}
                    onClick={() => togglePattern(i)}
                    className={`border-b border-border/50 cursor-pointer transition-colors ${
                      selectedPatterns.has(i) ? "bg-shield/5" : "hover:bg-white/[0.02]"
                    }`}
                  >
                    <td className="px-4 py-3">
                      <input
                        type="checkbox"
                        checked={selectedPatterns.has(i)}
                        onChange={() => togglePattern(i)}
                        onClick={(e) => e.stopPropagation()}
                        className="rounded border-border"
                      />
                    </td>
                    <td className="px-4 py-3">
                      <div>
                        <span className="text-text-primary font-mono text-xs">{p.text}</span>
                        {p.sourceExamples.length > 0 && (
                          <p className="text-[10px] text-text-muted mt-1 truncate max-w-xs" title={p.sourceExamples[0]}>
                            e.g. &quot;{p.sourceExamples[0]}&quot;
                          </p>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border ${CATEGORY_COLORS[p.category] || CATEGORY_COLORS.GENERIC}`}>
                        {p.category}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-text-primary font-mono">{p.frequency}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border ${SEVERITY_COLORS[p.suggestedSeverity]}`}>
                        {p.suggestedSeverity}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-text-primary font-mono">{p.suggestedWeight}</td>
                    <td className="px-4 py-3 text-text-primary font-mono">{p.specificityScore.toFixed(3)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* LLM Prompt Template Section */}
      <section className="glass-card p-6 space-y-4">
        <div className="flex items-center gap-2 mb-2">
          <Sparkles className="w-5 h-5 text-shield" />
          <h2 className="text-lg font-semibold text-text-primary">LLM Pattern Extraction</h2>
        </div>

        <p className="text-sm text-text-muted">
          Copy the prompt below, paste it into any LLM (ChatGPT, Claude, etc.) along with your fraud text,
          then paste the JSON output back here to import.
        </p>

        {/* Copy prompt button */}
        <div className="flex items-center gap-3">
          <button
            onClick={copyPrompt}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-shield/10 border border-shield/20 text-shield text-sm font-semibold hover:bg-shield/15 transition-colors"
          >
            {copiedPrompt ? <CheckCircle size={14} /> : <Copy size={14} />}
            {copiedPrompt ? "Copied!" : "Copy LLM Prompt"}
          </button>
          <span className="text-xs text-text-muted">
            Paste this into any LLM with your fraud text appended at the end
          </span>
        </div>

        {/* LLM output paste area */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <ClipboardPaste size={14} className="text-text-muted" />
            <label className="text-sm font-medium text-text-primary">Paste LLM JSON Output</label>
          </div>
          <textarea
            value={llmOutput}
            onChange={(e) => setLlmOutput(e.target.value)}
            placeholder='Paste the JSON array output from the LLM here...\n[\n  { "text": "verify your account", "category": "PHISHING", ... }\n]'
            rows={6}
            className="w-full px-4 py-3 bg-abyss/60 border border-border rounded-lg text-sm text-text-primary font-mono placeholder:text-text-muted/50 outline-none focus:border-shield/40 transition-colors resize-y"
          />
          <div className="flex items-center gap-3">
            <button
              onClick={importLlmOutput}
              disabled={!llmOutput.trim() || llmParsing}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-shield text-void font-semibold text-sm hover:bg-shield/90 transition-colors disabled:opacity-50"
            >
              {llmParsing ? <Loader2 size={14} className="animate-spin" /> : <Download size={14} />}
              Import Patterns
            </button>
            {llmError && (
              <span className="text-xs text-danger flex items-center gap-1">
                <AlertTriangle size={12} />
                {llmError}
              </span>
            )}
          </div>
        </div>
      </section>

      {/* Saved Patterns Section */}
      <section className="glass-card p-6 space-y-4">
        <div className="flex items-center justify-between mb-2">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-shield" />
            <h2 className="text-lg font-semibold text-text-primary">Saved Custom Patterns</h2>
          </div>
          <button
            onClick={loadSavedPatterns}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-border text-xs text-text-secondary hover:text-text-primary transition-colors"
          >
            {loadingSaved ? <Loader2 size={13} className="animate-spin" /> : <RefreshCw size={13} />}
            Load Patterns
          </button>
        </div>

        {savedPatterns.length === 0 ? (
          <p className="text-sm text-text-muted">
            No saved patterns yet. Extract patterns from a file or LLM output and approve them.
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left">
                  <th className="px-4 py-3 text-xs font-medium text-text-muted">Pattern</th>
                  <th className="px-4 py-3 text-xs font-medium text-text-muted">Category</th>
                  <th className="px-4 py-3 text-xs font-medium text-text-muted">Severity</th>
                  <th className="px-4 py-3 text-xs font-medium text-text-muted">Weight</th>
                </tr>
              </thead>
              <tbody>
                {savedPatterns.map((p, i) => (
                  <tr key={i} className="border-b border-border/50 hover:bg-white/[0.02] transition-colors">
                    <td className="px-4 py-3 text-text-primary font-mono text-xs">{p.text}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border ${CATEGORY_COLORS[p.category] || CATEGORY_COLORS.GENERIC}`}>
                        {p.category}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium border ${SEVERITY_COLORS[p.suggestedSeverity]}`}>
                        {p.suggestedSeverity}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-text-primary font-mono">{p.suggestedWeight}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {savedPatterns.length > 0 && (
          <p className="text-xs text-text-muted">
            {savedPatterns.length} pattern{savedPatterns.length !== 1 ? "s" : ""} saved
          </p>
        )}
      </section>

      {/* Free Data Sources Section */}
      <section className="glass-card p-6 space-y-4">
        <div className="flex items-center gap-2 mb-1">
          <Database className="w-5 h-5 text-shield" />
          <h2 className="text-lg font-semibold text-text-primary">Free Threat Intel Sources</h2>
        </div>
        <p className="text-sm text-text-muted">
          Download free, regularly-updated threat data from these sites. Open the file in a text editor,
          copy the content, then use the LLM prompt above to extract patterns and import them.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {DATA_SOURCES.map((src) => (
            <a
              key={src.name}
              href={src.url}
              target="_blank"
              rel="noopener noreferrer"
              className={`group flex flex-col gap-2 p-4 rounded-xl border transition-all hover:border-shield/40 hover:bg-shield/5 ${
                src.highlight
                  ? "border-shield/20 bg-shield/5"
                  : "border-border/40 bg-abyss/40"
              }`}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2">
                  <TrendingUp size={13} className={src.highlight ? "text-shield" : "text-text-muted"} />
                  <span className="text-sm font-semibold text-text-primary group-hover:text-shield transition-colors">
                    {src.name}
                  </span>
                  {src.highlight && (
                    <span className="text-[9px] font-bold uppercase tracking-wide bg-shield/20 text-shield px-1.5 py-0.5 rounded-full">
                      Recommended
                    </span>
                  )}
                </div>
                <ExternalLink size={12} className="text-text-muted group-hover:text-shield transition-colors shrink-0 mt-0.5" />
              </div>

              <p className="text-xs text-text-muted leading-relaxed">{src.description}</p>

              <div className="flex items-center gap-3 mt-1">
                <span className="text-[10px] text-text-muted">
                  <span className="text-text-secondary font-medium">Category:</span> {src.category}
                </span>
                <span className="text-[10px] text-text-muted">
                  <span className="text-text-secondary font-medium">Updated:</span> {src.updateFreq}
                </span>
                <div className="flex gap-1 ml-auto">
                  {src.formats.map((f) => (
                    <span key={f} className="text-[9px] font-mono bg-abyss/80 border border-border/60 text-text-muted px-1.5 py-0.5 rounded">
                      {f}
                    </span>
                  ))}
                </div>
              </div>
            </a>
          ))}
        </div>

        <p className="text-xs text-text-muted pt-1 border-t border-border/30">
          💡 <strong className="text-text-secondary">Workflow tip:</strong> Download a CSV/TXT → copy all text → paste into LLM with the prompt above → import JSON output → approve patterns.
          These sources update frequently — check back weekly for new threat data.
        </p>
      </section>
    </div>
  );
}
