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
  Trash2,
  Shield,
  Sparkles,
  ClipboardPaste,
  RefreshCw,
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
  GENERIC: "bg-border/50 text-text-muted border-border",
};

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
      setApproveResult(
        `Added ${data.added} patterns (${data.duplicatesSkipped} duplicates skipped). Total: ${data.total}.`
      );
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
      </div>

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
    </div>
  );
}
