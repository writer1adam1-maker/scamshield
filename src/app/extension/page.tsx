"use client";

import { Puzzle, Shield, Zap, Eye, MousePointer, Settings, CheckCircle2, AlertTriangle } from "lucide-react";
import Link from "next/link";

const FEATURES = [
  {
    icon: Eye,
    title: "Live dot badges on every link",
    desc: "Green = safe · Yellow = medium · Red = high/critical. See risk at a glance before clicking.",
  },
  {
    icon: MousePointer,
    title: "Click intercept for high-risk links",
    desc: "Clicking a high or critical link shows a warning page — protecting you at the decision moment.",
  },
  {
    icon: Zap,
    title: "Batched background scanning",
    desc: "Links are scanned in batches as you scroll. Results are cached for 30 minutes per domain.",
  },
  {
    icon: Shield,
    title: "Right-click context menu",
    desc: "\"Scan with ScamShield\" on any link, selected text, or page.",
  },
  {
    icon: Settings,
    title: "API key authentication",
    desc: "Connect your ScamShield account for higher rate limits and scan history tracking.",
  },
];

const INSTALL_STEPS = [
  {
    step: "1",
    title: "Download the extension",
    desc: "Download the ZIP file below and unzip it to a folder on your computer.",
  },
  {
    step: "2",
    title: "Load in Chrome",
    desc: "Open chrome://extensions → Enable Developer Mode → Load unpacked → Select the unzipped folder.",
  },
  {
    step: "3",
    title: "Add your API key (optional)",
    desc: "Click the extension icon → ⚙ Settings → Create an API key in your ScamShield account and paste it.",
  },
  {
    step: "4",
    title: "Browse safely",
    desc: "Every page you visit will now have live threat dots on all external links.",
  },
];

export default function ExtensionPage() {
  return (
    <div className="space-y-8 max-w-2xl">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-text-primary flex items-center gap-2">
          <Puzzle className="w-6 h-6 text-shield" />
          Browser Extension
        </h1>
        <p className="text-text-secondary text-sm mt-1">
          Real-time link scanning in your browser — every link gets a live threat score before you click
        </p>
      </div>

      {/* Hero card */}
      <section className="glass-card p-6 space-y-4 border-shield/15">
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 rounded-2xl bg-shield/10 border border-shield/20 flex items-center justify-center text-3xl">
            🛡️
          </div>
          <div>
            <h2 className="text-lg font-bold text-text-primary">ScamShield v2.0</h2>
            <p className="text-xs text-text-muted">Chrome & Firefox · Manifest V3</p>
          </div>
          <a
            href="/scamshield-extension.zip"
            download
            className="ml-auto flex items-center gap-2 px-4 py-2.5 rounded-xl bg-shield text-void font-bold text-sm hover:bg-shield-dim transition-colors shield-glow"
          >
            ↓ Download
          </a>
        </div>

        <div className="flex items-center gap-4 text-xs text-text-muted">
          <span className="flex items-center gap-1"><CheckCircle2 size={10} className="text-safe" /> Free to use</span>
          <span className="flex items-center gap-1"><CheckCircle2 size={10} className="text-safe" /> No account required</span>
          <span className="flex items-center gap-1"><CheckCircle2 size={10} className="text-safe" /> Open source ready</span>
        </div>
      </section>

      {/* Features */}
      <section className="glass-card p-6 space-y-4">
        <h2 className="text-base font-semibold text-text-primary">What it does</h2>
        <div className="space-y-3">
          {FEATURES.map(({ icon: Icon, title, desc }) => (
            <div key={title} className="flex items-start gap-3">
              <div className="w-7 h-7 rounded-lg bg-shield/10 border border-shield/20 flex items-center justify-center shrink-0 mt-0.5">
                <Icon size={14} className="text-shield" />
              </div>
              <div>
                <p className="text-sm font-medium text-text-primary">{title}</p>
                <p className="text-xs text-text-muted mt-0.5">{desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Install steps */}
      <section className="glass-card p-6 space-y-4">
        <h2 className="text-base font-semibold text-text-primary">How to install</h2>
        <div className="space-y-4">
          {INSTALL_STEPS.map(({ step, title, desc }) => (
            <div key={step} className="flex items-start gap-4">
              <div className="w-7 h-7 rounded-full bg-shield/10 border border-shield/20 flex items-center justify-center shrink-0 font-bold text-shield text-xs">
                {step}
              </div>
              <div>
                <p className="text-sm font-medium text-text-primary">{title}</p>
                <p className="text-xs text-text-muted mt-0.5">{desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* API key CTA */}
      <section className="glass-card p-6 flex items-center gap-4">
        <AlertTriangle size={18} className="text-warning shrink-0" />
        <div className="flex-1">
          <p className="text-sm font-medium text-text-primary">Get an API key for unlimited scanning</p>
          <p className="text-xs text-text-muted">Without a key the extension uses anonymous mode (rate limited). Add a key in extension settings to authenticate scans with your account.</p>
        </div>
        <Link
          href="/settings"
          className="shrink-0 px-3 py-2 rounded-xl bg-shield/10 border border-shield/20 text-shield text-xs font-semibold hover:bg-shield/15 transition-colors whitespace-nowrap"
        >
          Get Key →
        </Link>
      </section>
    </div>
  );
}
