"use client";

import { useState, useRef } from "react";
import {
  MessageSquare,
  AlertTriangle,
  Shield,
  Upload,
  Loader2,
  ChevronDown,
  ChevronUp,
  AlertCircle,
  CheckCircle2,
} from "lucide-react";
import type { ConversationArcResult, PhaseResult } from "@/lib/algorithms/conversation-arc";
import { GroomingPhase } from "@/lib/algorithms/conversation-arc";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const PHASE_ORDER: GroomingPhase[] = [
  GroomingPhase.RAPPORT_BUILDING,
  GroomingPhase.TRUST_DEVELOPMENT,
  GroomingPhase.ISOLATION,
  GroomingPhase.INVESTMENT_HOOK,
  GroomingPhase.PRESSURE_ESCALATION,
  GroomingPhase.COLLECTION,
];

const PHASE_COLORS: Record<GroomingPhase, string> = {
  [GroomingPhase.RAPPORT_BUILDING]:    '#22c55e',
  [GroomingPhase.TRUST_DEVELOPMENT]:   '#14b8a6',
  [GroomingPhase.ISOLATION]:           '#f59e0b',
  [GroomingPhase.INVESTMENT_HOOK]:     '#f97316',
  [GroomingPhase.PRESSURE_ESCALATION]: '#ef4444',
  [GroomingPhase.COLLECTION]:          '#dc2626',
};

const SAMPLE_FORMATS = `WhatsApp export:
[01/15/2024, 9:30 AM] Alex: Hey! How are you doing today?
[01/15/2024, 9:32 AM] You: I'm good, thanks! Who is this?
[01/15/2024, 9:33 AM] Alex: I think we might have met before. You seem so familiar to me...

Telegram format:
Alex [Jan 15, 2024 9:30 AM]: Hey! How are you doing today?
You [Jan 15, 2024 9:32 AM]: I'm good, thanks!

Generic format (any "Name: message" per line):
Alex: Hey! How are you doing today?
You: I'm good thanks. Do I know you?
Alex: No but I feel like I've known you forever...`;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function threatColor(level: string): string {
  const map: Record<string, string> = {
    CRITICAL: '#dc2626',
    HIGH:     '#ef4444',
    MEDIUM:   '#f59e0b',
    LOW:      '#22c55e',
    SAFE:     '#00e5a0',
  };
  return map[level] ?? '#00e5a0';
}

function arcTypeBorderColor(arcType: string): string {
  const map: Record<string, string> = {
    PIG_BUTCHERING:    'rgba(220,38,38,0.35)',
    ROMANCE_SCAM:      'rgba(239,68,68,0.3)',
    INVESTMENT_FRAUD:  'rgba(249,115,22,0.3)',
    ADVANCE_FEE:       'rgba(251,191,36,0.3)',
    GENERIC_GROOMING:  'rgba(245,158,11,0.25)',
    BENIGN:            'rgba(0,229,160,0.2)',
  };
  return map[arcType] ?? 'rgba(42,42,68,1)';
}

// ---------------------------------------------------------------------------
// Sub-components
// ---------------------------------------------------------------------------

function PhaseCard({
  phase,
  expanded,
  onToggle,
}: {
  phase: PhaseResult;
  expanded: boolean;
  onToggle: () => void;
}) {
  return (
    <div
      className="glass-card p-4 cursor-pointer transition-all duration-200"
      style={{
        borderColor: phase.present ? phase.color + '30' : undefined,
        opacity: phase.present ? 1 : 0.55,
      }}
      onClick={onToggle}
    >
      <div className="flex items-start justify-between gap-3 mb-2">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5">
            {phase.present ? (
              <AlertTriangle size={13} style={{ color: phase.color, flexShrink: 0 }} />
            ) : (
              <CheckCircle2 size={13} className="text-text-muted" style={{ flexShrink: 0 }} />
            )}
            <span className="text-sm font-semibold text-text-primary">{phase.label}</span>
            {phase.present && (
              <span
                className="text-[10px] font-mono px-1.5 py-0.5 rounded"
                style={{
                  background: phase.color + '15',
                  color: phase.color,
                  border: `1px solid ${phase.color}30`,
                }}
              >
                DETECTED
              </span>
            )}
          </div>
          <p className="text-xs text-text-muted leading-relaxed">{phase.description}</p>
        </div>
        <div className="shrink-0 text-right">
          <div
            className="text-xl font-mono font-black leading-none"
            style={{ color: phase.present ? phase.color : '#5a5a7a' }}
          >
            {phase.score}
          </div>
          <div className="text-[10px] font-mono text-text-muted">/100</div>
        </div>
      </div>

      {/* Score bar */}
      <div className="w-full h-1.5 rounded-full overflow-hidden mb-2" style={{ background: '#12121c' }}>
        <div
          className="h-full rounded-full transition-all duration-500"
          style={{ width: `${phase.score}%`, background: phase.color }}
        />
      </div>

      {/* Expanded evidence */}
      {expanded && phase.topFindings.length > 0 && (
        <div className="mt-3 space-y-1.5 border-t pt-2" style={{ borderColor: phase.color + '20' }}>
          {phase.topFindings.map((finding, i) => (
            <div key={i} className="flex items-start gap-2">
              <div
                className="w-1.5 h-1.5 rounded-full shrink-0 mt-1.5"
                style={{ background: phase.color }}
              />
              <span className="text-[11px] font-mono text-text-secondary leading-relaxed">{finding}</span>
            </div>
          ))}
        </div>
      )}

      {phase.present && (
        <div
          className="flex items-center gap-1 mt-2 text-[11px] font-mono"
          style={{ color: phase.color + '80' }}
        >
          {expanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
          {expanded ? 'Hide' : 'Show'} evidence ({phase.signals.length} signal{phase.signals.length !== 1 ? 's' : ''})
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function ConversationPage() {
  const [text, setText] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ConversationArcResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showFormats, setShowFormats] = useState(false);
  const [expandedPhase, setExpandedPhase] = useState<GroomingPhase | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  async function handleAnalyze() {
    if (!text.trim()) {
      setError('Please paste a conversation before analyzing.');
      return;
    }
    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch('/api/analyze-conversation', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ conversation: text }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `Server error ${res.status}`);
      setResult(data as ConversationArcResult);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Analysis failed. Please try again.');
    } finally {
      setLoading(false);
    }
  }

  function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = ev => {
      const content = (ev.target?.result as string) || '';
      if (content) setText(content);
    };
    reader.readAsText(file);
    e.target.value = '';
  }

  function togglePhase(phase: GroomingPhase) {
    setExpandedPhase(prev => (prev === phase ? null : phase));
  }

  const orderedPhases: PhaseResult[] = result
    ? PHASE_ORDER.map(p => result.phases.find(ph => ph.phase === p)).filter(Boolean) as PhaseResult[]
    : [];

  const tColor = result ? threatColor(result.threatLevel) : '#00d4ff';

  return (
    <div>
      {/* ── Page header ── */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-2">
          <div
            className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
            style={{ background: 'rgba(0,212,255,0.08)', border: '1px solid rgba(0,212,255,0.2)' }}
          >
            <MessageSquare size={20} className="text-shield" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-text-primary">Conversation Arc Analyzer</h1>
            <p className="text-[11px] font-mono text-text-muted tracking-widest uppercase">
              VERIDICT · Grooming Phase Detection · v1.0
            </p>
          </div>
        </div>
        <p className="text-sm text-text-secondary leading-relaxed max-w-2xl">
          Paste any conversation export to detect pig-butchering, romance scam, and social engineering
          grooming phases. Identifies 6 manipulation phases across WhatsApp, Telegram, SMS, and generic formats.
        </p>
      </div>

      {/* ── Input card ── */}
      <div className="glass-card p-5 mb-5">
        {/* Format hint toggle */}
        <button
          onClick={() => setShowFormats(f => !f)}
          className="flex items-center gap-1.5 text-[11px] font-mono text-text-muted hover:text-shield transition-colors mb-3"
        >
          {showFormats ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
          Supported formats (WhatsApp / Telegram / Generic)
        </button>

        {showFormats && (
          <pre
            className="text-[11px] font-mono text-text-muted rounded-xl p-3 mb-4 overflow-x-auto leading-relaxed"
            style={{ background: 'rgba(18,18,28,0.8)', border: '1px solid rgba(42,42,68,0.6)' }}
          >
            {SAMPLE_FORMATS}
          </pre>
        )}

        <div className="mb-3">
          <label className="block text-[10px] font-mono text-text-muted uppercase tracking-widest mb-2">
            Paste conversation export
          </label>
          <textarea
            value={text}
            onChange={e => setText(e.target.value)}
            placeholder={`[01/15/2024, 9:30 AM] Alex: Hey! I feel like I've known you forever...`}
            rows={10}
            className="w-full rounded-xl text-text-primary text-xs font-mono p-3 resize-y outline-none transition-all placeholder:text-text-muted"
            style={{
              background: 'rgba(18,18,28,0.7)',
              border: `1px solid ${text ? 'rgba(0,212,255,0.25)' : 'rgba(42,42,68,1)'}`,
            }}
          />
          <div className="flex items-center justify-between mt-1">
            <span className="text-[10px] font-mono text-text-muted">{text.length.toLocaleString()} chars</span>
            {text.trim() && (() => {
              const words = text.trim().split(/\s+/).filter(Boolean).length;
              const scans = Math.min(10, Math.max(1, Math.floor(words / 1000)));
              return (
                <span className="text-[10px] font-mono text-caution">
                  ~{words.toLocaleString()} words · costs {scans} scan{scans > 1 ? "s" : ""}
                </span>
              );
            })()}
            {!text.trim() && <span className="text-[10px] font-mono text-text-muted">max 100,000 chars</span>}
          </div>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => fileRef.current?.click()}
            className="flex items-center gap-2 px-4 py-2 text-sm border rounded-xl text-text-muted hover:text-text-secondary transition-colors"
            style={{ borderColor: 'rgba(42,42,68,1)' }}
          >
            <Upload size={14} />
            Upload .txt
          </button>
          <input
            ref={fileRef}
            type="file"
            accept=".txt,.csv,.log"
            className="hidden"
            onChange={handleFile}
          />
          <button
            onClick={handleAnalyze}
            disabled={loading || !text.trim()}
            className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl font-bold text-sm transition-opacity disabled:opacity-40 disabled:cursor-not-allowed"
            style={{ background: '#00d4ff', color: '#0a0a0f' }}
          >
            {loading ? (
              <><Loader2 size={14} className="animate-spin" /> Analyzing arc…</>
            ) : (
              <><MessageSquare size={14} /> Analyze Conversation</>
            )}
          </button>
        </div>
      </div>

      {/* ── Error ── */}
      {error && (
        <div
          className="flex items-center gap-3 p-4 rounded-xl mb-5 text-sm"
          style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}
        >
          <AlertCircle size={16} className="text-danger shrink-0" />
          <span style={{ color: '#ef4444' }}>{error}</span>
        </div>
      )}

      {/* ── Results ── */}
      {result && (
        <div className="space-y-5">

          {/* Arc banner */}
          <div
            className="glass-card p-5 flex items-start gap-5"
            style={{ borderColor: arcTypeBorderColor(result.arcType) }}
          >
            {/* Risk gauge */}
            <div className="shrink-0 text-center">
              <div
                className="w-[72px] h-[72px] rounded-full flex items-center justify-center border-2 font-mono font-black text-2xl"
                style={{
                  color: tColor,
                  borderColor: tColor + '55',
                  background: tColor + '10',
                }}
              >
                {result.overallRisk}
              </div>
              <div className="text-[11px] font-mono mt-1 font-semibold" style={{ color: tColor }}>
                {result.threatLevel}
              </div>
            </div>

            {/* Arc details */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1 flex-wrap">
                <span
                  className="text-[11px] font-mono font-semibold px-2 py-0.5 rounded-md"
                  style={{
                    background: tColor + '12',
                    border: `1px solid ${tColor}30`,
                    color: tColor,
                  }}
                >
                  {result.arcType.replace(/_/g, ' ')}
                </span>
              </div>
              <h2 className="text-base font-bold text-text-primary mb-1">{result.arcLabel}</h2>
              <p className="text-xs text-text-secondary leading-relaxed">{result.arcDescription}</p>
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-3 text-[11px] font-mono text-text-muted">
                <span>{result.messageCount.toLocaleString()} messages</span>
                {result.senderCount > 0 && (
                  <span>{result.senderCount} sender{result.senderCount !== 1 ? 's' : ''}</span>
                )}
                <span>{result.phases.filter(p => p.present).length}/6 phases detected</span>
                <span>{result.processingTimeMs}ms</span>
              </div>
            </div>
          </div>

          {/* Timeline */}
          <div className="glass-card p-5">
            <div className="text-[10px] font-mono text-text-muted uppercase tracking-widest mb-3">
              Conversation Timeline — Dominant Phase per Segment
            </div>
            <div className="flex gap-0.5 rounded-lg overflow-hidden h-7 mb-3">
              {result.timeline.map(seg => (
                <div
                  key={seg.segmentIndex}
                  className="flex-1 transition-all"
                  title={
                    seg.dominantPhase
                      ? seg.dominantPhase.replace(/_/g, ' ')
                      : 'No signals detected'
                  }
                  style={{
                    background: seg.dominantPhase
                      ? PHASE_COLORS[seg.dominantPhase as GroomingPhase] + 'BB'
                      : '#1a1a2e',
                  }}
                />
              ))}
            </div>
            {/* Phase legend */}
            <div className="flex flex-wrap gap-x-4 gap-y-1.5">
              {PHASE_ORDER.map(phase => {
                const pr = result.phases.find(p => p.phase === phase);
                return (
                  <div key={phase} className="flex items-center gap-1.5">
                    <div
                      className="w-2.5 h-2.5 rounded-sm shrink-0"
                      style={{ background: PHASE_COLORS[phase] }}
                    />
                    <span
                      className="text-[11px] font-mono"
                      style={{ color: pr?.present ? PHASE_COLORS[phase] : '#5a5a7a' }}
                    >
                      {pr?.label ?? phase.replace(/_/g, ' ')}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Phase detection grid */}
          <div>
            <div className="text-[10px] font-mono text-text-muted uppercase tracking-widest mb-3">
              Phase Detection — Click any card to expand evidence
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {orderedPhases.map(phase => (
                <PhaseCard
                  key={phase.phase}
                  phase={phase}
                  expanded={expandedPhase === phase.phase}
                  onToggle={() => togglePhase(phase.phase)}
                />
              ))}
            </div>
          </div>

          {/* Critical findings */}
          {result.criticalFindings.length > 0 && (
            <div
              className="glass-card p-5"
              style={{ borderColor: 'rgba(239,68,68,0.25)' }}
            >
              <div className="flex items-center gap-2 mb-3">
                <AlertTriangle size={14} style={{ color: '#ef4444' }} />
                <span className="text-[10px] font-mono text-text-muted uppercase tracking-widest">
                  Critical Findings
                </span>
              </div>
              <ul className="space-y-2">
                {result.criticalFindings.map((f, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-text-secondary">
                    <div className="w-1.5 h-1.5 rounded-full shrink-0 mt-1.5" style={{ background: '#ef4444' }} />
                    {f}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Recommended actions */}
          {result.recommendedActions.length > 0 && (
            <div
              className="glass-card p-5"
              style={{ borderColor: 'rgba(0,212,255,0.15)' }}
            >
              <div className="flex items-center gap-2 mb-3">
                <Shield size={14} className="text-shield" />
                <span className="text-[10px] font-mono text-text-muted uppercase tracking-widest">
                  Recommended Actions
                </span>
              </div>
              <ul className="space-y-2">
                {result.recommendedActions.map((a, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-text-secondary">
                    <div className="w-1.5 h-1.5 rounded-full bg-shield shrink-0 mt-1.5" />
                    {a}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Safe result */}
          {result.arcType === 'BENIGN' && (
            <div
              className="glass-card p-5 flex items-center gap-4"
              style={{ borderColor: 'rgba(0,229,160,0.2)' }}
            >
              <Shield size={24} className="text-safe shrink-0" />
              <div>
                <div className="text-sm font-semibold text-safe mb-0.5">No Grooming Patterns Detected</div>
                <p className="text-xs text-text-muted leading-relaxed">
                  This conversation does not contain significant manipulation signals. If you still have
                  concerns, discuss with a trusted friend, family member, or professional counselor.
                </p>
              </div>
            </div>
          )}

        </div>
      )}
    </div>
  );
}
