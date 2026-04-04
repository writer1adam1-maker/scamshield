"use client";

import { useState, useEffect } from "react";
import {
  Mail, Shield, CheckCircle2, AlertTriangle, Loader2, RefreshCw,
  LogOut, Zap, TrendingUp, Clock, ShieldAlert,
} from "lucide-react";
import clsx from "clsx";
import Link from "next/link";

interface GmailStatus {
  connected: boolean;
  googleEmail?: string;
  connectedAt?: string;
  lastPolledAt?: string;
  emailsScannedTotal?: number;
  threatsFoundTotal?: number;
}

interface ScanResult {
  id: string;
  gmail_message_id: string;
  sender_domain: string | null;
  subject_preview: string | null;
  received_at: string | null;
  score: number;
  threat_level: string;
  category: string;
  scanned_at: string;
}

const LEVEL_COLORS: Record<string, string> = {
  SAFE:     "text-safe border-safe/20 bg-safe/5",
  LOW:      "text-safe border-safe/20 bg-safe/5",
  MEDIUM:   "text-warning border-warning/20 bg-warning/5",
  HIGH:     "text-danger border-danger/20 bg-danger/5",
  CRITICAL: "text-danger border-danger/20 bg-danger/10",
};

export default function GmailShieldPage() {
  const [status, setStatus] = useState<GmailStatus | null>(null);
  const [results, setResults] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [resultsLoading, setResultsLoading] = useState(false);
  const [disconnecting, setDisconnecting] = useState(false);
  const [showThreatsOnly, setShowThreatsOnly] = useState(false);
  const [urlError, setUrlError] = useState<string | null>(null);

  useEffect(() => {
    // Check for URL params (from OAuth callback)
    const params = new URLSearchParams(window.location.search);
    if (params.get("connected")) {
      // Clean URL
      window.history.replaceState({}, "", "/dashboard/gmail");
    }
    if (params.get("error")) {
      setUrlError(params.get("error"));
      window.history.replaceState({}, "", "/dashboard/gmail");
    }

    loadStatus();
  }, []);

  useEffect(() => {
    if (status?.connected) loadResults();
  }, [status, showThreatsOnly]);

  async function loadStatus() {
    setLoading(true);
    try {
      const res = await fetch("/api/gmail/status");
      if (res.ok) setStatus(await res.json());
    } catch { /* ignore */ }
    setLoading(false);
  }

  async function loadResults() {
    setResultsLoading(true);
    try {
      const url = `/api/gmail/scan-results?limit=30${showThreatsOnly ? "&threats=1" : ""}`;
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setResults(data.results ?? []);
      }
    } catch { /* ignore */ }
    setResultsLoading(false);
  }

  async function handleDisconnect() {
    if (!confirm("Disconnect Gmail? This will remove your connection and delete all scanned email records.")) return;
    setDisconnecting(true);
    try {
      await fetch("/api/gmail/disconnect", { method: "POST" });
      setStatus({ connected: false });
      setResults([]);
    } catch { /* ignore */ }
    setDisconnecting(false);
  }

  if (loading) {
    return (
      <div className="flex items-center gap-3 text-text-muted p-8">
        <Loader2 size={18} className="animate-spin" />
        Loading Gmail Shield…
      </div>
    );
  }

  return (
    <div className="space-y-6 max-w-3xl">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-text-primary flex items-center gap-2">
          <Mail className="w-6 h-6 text-shield" />
          Gmail Shield
        </h1>
        <p className="text-text-secondary text-sm mt-1">
          Scan your Gmail inbox for phishing and scam emails automatically
        </p>
      </div>

      {urlError && (
        <div className="flex items-center gap-2 p-3 rounded-xl bg-danger/10 border border-danger/20 text-danger text-sm">
          <AlertTriangle size={14} />
          Connection failed: {urlError.replace(/_/g, " ")}
        </div>
      )}

      {/* Connection card */}
      <section className="glass-card p-6">
        {status?.connected ? (
          <div className="space-y-4">
            {/* Connected status */}
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-full bg-safe/10 border border-safe/20 flex items-center justify-center">
                <CheckCircle2 size={18} className="text-safe" />
              </div>
              <div>
                <p className="font-semibold text-text-primary text-sm">Connected</p>
                <p className="text-xs text-text-muted font-mono">{status.googleEmail}</p>
              </div>
              <button
                onClick={handleDisconnect}
                disabled={disconnecting}
                className="ml-auto flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border text-xs text-text-muted hover:text-danger hover:border-danger/30 transition-colors disabled:opacity-50"
              >
                {disconnecting ? <Loader2 size={11} className="animate-spin" /> : <LogOut size={11} />}
                Disconnect
              </button>
            </div>

            {/* Stats */}
            <div className="grid grid-cols-3 gap-3">
              <div className="p-3 rounded-xl bg-abyss/60 border border-border/40 text-center">
                <div className="text-xl font-bold font-mono text-shield">{status.emailsScannedTotal ?? 0}</div>
                <div className="text-[10px] text-text-muted mt-0.5">Emails Scanned</div>
              </div>
              <div className="p-3 rounded-xl bg-abyss/60 border border-border/40 text-center">
                <div className="text-xl font-bold font-mono text-danger">{status.threatsFoundTotal ?? 0}</div>
                <div className="text-[10px] text-text-muted mt-0.5">Threats Found</div>
              </div>
              <div className="p-3 rounded-xl bg-abyss/60 border border-border/40 text-center">
                <div className="text-xs font-mono text-text-secondary mt-1">
                  {status.lastPolledAt
                    ? new Date(status.lastPolledAt).toLocaleTimeString()
                    : "Not yet"}
                </div>
                <div className="text-[10px] text-text-muted mt-0.5">Last Checked</div>
              </div>
            </div>

            <p className="text-[10px] text-text-muted flex items-center gap-1.5">
              <Clock size={10} />
              Inbox is scanned automatically once daily. Email content is never stored — only threat scores.
            </p>
          </div>
        ) : (
          /* Not connected */
          <div className="space-y-4">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-10 h-10 rounded-full bg-abyss/80 border border-border flex items-center justify-center">
                <Mail size={18} className="text-text-muted" />
              </div>
              <div>
                <p className="font-semibold text-text-primary text-sm">Gmail not connected</p>
                <p className="text-xs text-text-muted">Connect to scan your inbox for scam emails</p>
              </div>
            </div>

            {/* How it works */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
              {[
                { icon: Shield, title: "Zero-body scanning", desc: "Only subject + sender analyzed. Email body never read." },
                { icon: Zap, title: "Auto every 15 min", desc: "Background inbox scan catches new phishing attempts." },
                { icon: TrendingUp, title: "Full history", desc: "See all past scans with threat scores & categories." },
              ].map(({ icon: Icon, title, desc }) => (
                <div key={title} className="p-3 rounded-xl bg-abyss/40 border border-border/40">
                  <Icon size={16} className="text-shield mb-2" />
                  <p className="text-xs font-medium text-text-primary mb-1">{title}</p>
                  <p className="text-[10px] text-text-muted">{desc}</p>
                </div>
              ))}
            </div>

            <Link
              href="/api/gmail/authorize"
              className="flex items-center justify-center gap-2 w-full py-3 rounded-xl bg-shield/10 border border-shield/20 text-shield font-semibold text-sm hover:bg-shield/15 transition-all shield-glow"
            >
              <Mail size={16} />
              Connect Gmail Account
            </Link>

            <p className="text-[10px] text-text-muted text-center">
              Uses Gmail read-only metadata scope. ScamShield never reads or stores email content.
            </p>
          </div>
        )}
      </section>

      {/* Scan results */}
      {status?.connected && (
        <section className="glass-card p-6 space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-base font-semibold text-text-primary flex items-center gap-2">
              <ShieldAlert size={16} className="text-shield" />
              Recent Email Scans
            </h2>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setShowThreatsOnly(!showThreatsOnly)}
                className={clsx(
                  "text-xs px-3 py-1.5 rounded-lg border transition-colors",
                  showThreatsOnly
                    ? "bg-danger/10 border-danger/20 text-danger"
                    : "border-border text-text-muted hover:text-text-secondary"
                )}
              >
                {showThreatsOnly ? "Threats only" : "All emails"}
              </button>
              <button
                onClick={loadResults}
                disabled={resultsLoading}
                className="p-1.5 text-text-muted hover:text-shield transition-colors rounded-lg"
                title="Refresh"
              >
                <RefreshCw size={14} className={resultsLoading ? "animate-spin" : ""} />
              </button>
            </div>
          </div>

          {resultsLoading ? (
            <div className="flex items-center gap-2 text-text-muted text-sm py-4">
              <Loader2 size={14} className="animate-spin" /> Loading…
            </div>
          ) : results.length === 0 ? (
            <div className="text-center py-8 text-text-muted text-sm">
              <Mail size={32} className="mx-auto mb-3 opacity-20" />
              <p>No scans yet. Gmail Shield will scan your inbox automatically.</p>
            </div>
          ) : (
            <div className="space-y-2">
              {results.map((r) => (
                <div
                  key={r.id}
                  className={clsx(
                    "flex items-start gap-3 p-3 rounded-xl border text-sm",
                    LEVEL_COLORS[r.threat_level] ?? "text-text-secondary border-border bg-abyss/40"
                  )}
                >
                  <div className="shrink-0 mt-0.5">
                    {r.threat_level === "HIGH" || r.threat_level === "CRITICAL" ? (
                      <AlertTriangle size={14} />
                    ) : (
                      <CheckCircle2 size={14} />
                    )}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="font-medium text-xs truncate">
                      {r.subject_preview || "(No subject)"}
                    </div>
                    <div className="text-[10px] opacity-70 mt-0.5">
                      {r.sender_domain || "unknown"} · {r.category.replace(/_/g, " ")} · Score {r.score}
                    </div>
                  </div>
                  <div className="shrink-0 text-[10px] font-mono opacity-60">
                    {new Date(r.scanned_at).toLocaleDateString()}
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
