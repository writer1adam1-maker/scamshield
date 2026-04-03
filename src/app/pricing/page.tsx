"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import {
  Shield,
  Zap,
  Check,
  X,
  ChevronDown,
  ChevronUp,
  Star,
  Lock,
} from "lucide-react";

// ---------------------------------------------------------------------------
// Plan data
// ---------------------------------------------------------------------------

interface PlanFeature {
  name: string;
  free: boolean | string;
  pro: boolean | string;
}

const FEATURES: PlanFeature[] = [
  { name: "Scam detection scans", free: "15 per day", pro: "Unlimited" },
  { name: "VERIDICT 4-layer analysis", free: true, pro: true },
  { name: "SYNERGOS behavioral analysis", free: true, pro: true },
  { name: "Threat score & evidence", free: true, pro: true },
  { name: "Website Vaccine (phishing protection)", free: true, pro: true },
  { name: "Scam pattern database", free: true, pro: true },
  { name: "Full scan history & dashboard", free: false, pro: true },
  { name: "API access (REST)", free: false, pro: true },
  { name: "Bulk scan (up to 50)", free: false, pro: true },
  { name: "Priority analysis speed", free: false, pro: true },
  { name: "Priority support", free: false, pro: true },
];

interface FaqItem {
  question: string;
  answer: string;
}

const FAQ: FaqItem[] = [
  {
    question: "How does ScamShieldy detect scams?",
    answer:
      "ScamShieldy uses the VERIDICT algorithm, a 4-layer analysis engine that combines Fisher Information scoring, Conservation Law violation detection, Cascade Breaking analysis, and an Immune Repertoire pattern matcher. Together these layers analyze URLs, text patterns, domain age, SSL certificates, and known scam signatures to produce a threat confidence score from 0-100.",
  },
  {
    question: "Is my data safe?",
    answer:
      "Yes. We do not store the content you scan beyond the current session (free tier) or your encrypted scan history (Pro). We never share your data with third parties. All API communications are encrypted via TLS 1.3.",
  },
  {
    question: "What counts as a 'scan'?",
    answer:
      "Each submission (URL, text message, email, or screenshot) counts as one scan. Editing and re-submitting the same content counts as a new scan.",
  },
  {
    question: "Can I cancel Pro anytime?",
    answer:
      "Absolutely. Pro is a monthly subscription with no contract. Cancel anytime from your account settings and you'll retain access until the end of your billing period.",
  },
  {
    question: "How accurate is the detection?",
    answer:
      "ScamShieldy's VERIDICT engine achieves a high detection rate for known scam patterns. However, no system is 100% accurate. Always use your own judgment alongside our analysis. We continuously update our pattern database to improve accuracy.",
  },
  {
    question: "Do you support screenshot analysis?",
    answer:
      "Yes. Upload a screenshot of a suspicious message and our system will extract text and analyze it. For best results in the current version, paste the text directly. Full OCR integration is coming soon.",
  },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function PricingPage() {
  const router = useRouter();
  const [expandedFaq, setExpandedFaq] = useState<number | null>(null);
  const [annual, setAnnual] = useState(false);
  const [upgrading, setUpgrading] = useState(false);

  const proPrice = annual ? "$2.99" : "$3.99";
  const proPeriod = annual ? "/mo (billed yearly)" : "/mo";

  async function handleUpgrade() {
    setUpgrading(true);
    try {
      const res = await fetch("/api/stripe/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const data = await res.json();
      if (data.url) {
        window.location.href = data.url;
      }
    } catch {
      // Checkout failed silently — user stays on pricing page
    } finally {
      setUpgrading(false);
    }
  }

  return (
    <div className="space-y-12">
      {/* Header */}
      <div className="text-center pt-8">
        <h1 className="text-3xl md:text-4xl font-bold text-text-primary mb-3">
          Simple, Transparent Pricing
        </h1>
        <p className="text-text-secondary text-lg max-w-xl mx-auto">
          Start free. Upgrade when you need unlimited protection.
        </p>

        {/* Annual toggle */}
        <div className="flex items-center justify-center gap-3 mt-6">
          <span className={`text-sm ${!annual ? "text-text-primary" : "text-text-muted"}`}>
            Monthly
          </span>
          <button
            onClick={() => setAnnual(!annual)}
            role="switch"
            aria-checked={annual}
            aria-label="Toggle annual billing"
            className={`relative w-12 h-6 rounded-full transition-colors ${
              annual ? "bg-shield" : "bg-slate-mid"
            }`}
          >
            <div
              className={`absolute top-0.5 w-5 h-5 rounded-full bg-white transition-transform ${
                annual ? "translate-x-6" : "translate-x-0.5"
              }`}
            />
          </button>
          <span className={`text-sm ${annual ? "text-text-primary" : "text-text-muted"}`}>
            Annual
            <span className="ml-1 text-safe text-xs font-mono">SAVE 25%</span>
          </span>
        </div>
      </div>

      {/* Pricing Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 max-w-3xl mx-auto">
        {/* Free Tier */}
        <div className="glass-card p-6 flex flex-col">
          <div className="mb-6">
            <div className="flex items-center gap-2 mb-2">
              <Shield className="w-5 h-5 text-text-secondary" />
              <h2 className="text-lg font-semibold text-text-primary">Free</h2>
            </div>
            <div className="flex items-baseline gap-1">
              <span className="text-4xl font-bold font-mono text-text-primary">$0</span>
              <span className="text-text-muted text-sm">/forever</span>
            </div>
            <p className="text-text-secondary text-sm mt-2">
              15 scans per day. Perfect for checking the occasional suspicious message.
            </p>
          </div>

          <ul className="space-y-3 flex-1 mb-6">
            {FEATURES.filter((f) => f.free).map((f) => (
              <li key={f.name} className="flex items-center gap-2 text-sm text-text-secondary">
                <Check className="w-4 h-4 text-safe shrink-0" />
                <span>
                  {f.name}
                  {typeof f.free === "string" && (
                    <span className="text-text-muted ml-1">({f.free})</span>
                  )}
                </span>
              </li>
            ))}
            {FEATURES.filter((f) => !f.free).map((f) => (
              <li key={f.name} className="flex items-center gap-2 text-sm text-text-muted">
                <X className="w-4 h-4 shrink-0" />
                <span>{f.name}</span>
              </li>
            ))}
          </ul>

          <button
            onClick={() => router.push("/")}
            className="w-full py-3 px-4 rounded-lg border border-border text-text-primary font-semibold text-sm hover:border-shield/30 hover:bg-shield/5 transition-all duration-300"
          >
            Get Started Free
          </button>
        </div>

        {/* Pro Tier */}
        <div className="glass-card p-6 flex flex-col border-shield/30 relative overflow-hidden">
          {/* Glow effect */}
          <div className="absolute -top-20 -right-20 w-40 h-40 bg-shield/10 rounded-full blur-3xl" />
          <div className="absolute -bottom-20 -left-20 w-40 h-40 bg-shield/5 rounded-full blur-3xl" />

          {/* Popular badge */}
          <div className="absolute top-4 right-4 flex items-center gap-1 px-2 py-1 rounded-full bg-shield/10 border border-shield/20 text-shield text-xs font-mono">
            <Star className="w-3 h-3" />
            POPULAR
          </div>

          <div className="mb-6 relative">
            <div className="flex items-center gap-2 mb-2">
              <Zap className="w-5 h-5 text-shield" />
              <h2 className="text-lg font-semibold text-text-primary">Pro</h2>
            </div>
            <div className="flex items-baseline gap-1">
              <span className="text-4xl font-bold font-mono text-text-primary">{proPrice}</span>
              <span className="text-text-muted text-sm">{proPeriod}</span>
            </div>
            <p className="text-text-secondary text-sm mt-2">
              Unlimited scans with full analysis power. For anyone who takes online safety seriously.
            </p>
          </div>

          <ul className="space-y-3 flex-1 mb-6 relative">
            {FEATURES.map((f) => (
              <li key={f.name} className="flex items-center gap-2 text-sm text-text-secondary">
                <Check className="w-4 h-4 text-shield shrink-0" />
                <span>
                  {f.name}
                  {typeof f.pro === "string" && (
                    <span className="text-shield ml-1">({f.pro})</span>
                  )}
                </span>
              </li>
            ))}
          </ul>

          <button
            onClick={handleUpgrade}
            disabled={upgrading}
            className="w-full py-3 px-4 rounded-lg bg-shield text-void font-semibold text-sm shield-glow hover:bg-shield-dim transition-all duration-300 flex items-center justify-center gap-2 disabled:opacity-50"
          >
            <Lock className="w-4 h-4" />
            {upgrading ? "Redirecting..." : "Upgrade to Pro"}
          </button>
        </div>
      </div>

      {/* Feature Comparison Table */}
      <div className="max-w-3xl mx-auto">
        <h2 className="text-xl font-semibold text-text-primary mb-4 text-center">
          Feature Comparison
        </h2>
        <div className="glass-card overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border">
                <th className="text-left px-5 py-3 text-text-muted font-mono text-xs uppercase tracking-wider">
                  Feature
                </th>
                <th className="text-center px-5 py-3 text-text-muted font-mono text-xs uppercase tracking-wider w-[100px]">
                  Free
                </th>
                <th className="text-center px-5 py-3 text-shield font-mono text-xs uppercase tracking-wider w-[100px]">
                  Pro
                </th>
              </tr>
            </thead>
            <tbody>
              {FEATURES.map((f, i) => (
                <tr
                  key={f.name}
                  className={`border-b border-border/50 ${i % 2 === 0 ? "" : "bg-slate-deep/30"}`}
                >
                  <td className="px-5 py-3 text-text-secondary">{f.name}</td>
                  <td className="px-5 py-3 text-center">
                    {typeof f.free === "string" ? (
                      <span className="text-text-muted text-xs font-mono">{f.free}</span>
                    ) : f.free ? (
                      <Check className="w-4 h-4 text-safe mx-auto" />
                    ) : (
                      <X className="w-4 h-4 text-text-muted mx-auto" />
                    )}
                  </td>
                  <td className="px-5 py-3 text-center">
                    {typeof f.pro === "string" ? (
                      <span className="text-shield text-xs font-mono">{f.pro}</span>
                    ) : f.pro ? (
                      <Check className="w-4 h-4 text-shield mx-auto" />
                    ) : (
                      <X className="w-4 h-4 text-text-muted mx-auto" />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* FAQ Section */}
      <div className="max-w-2xl mx-auto pb-12">
        <h2 className="text-xl font-semibold text-text-primary mb-6 text-center">
          Frequently Asked Questions
        </h2>

        <div className="space-y-2">
          {FAQ.map((item, i) => {
            const isOpen = expandedFaq === i;

            return (
              <div key={i} className="glass-card overflow-hidden">
                <button
                  onClick={() => setExpandedFaq(isOpen ? null : i)}
                  className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-slate-deep/50 transition-colors"
                >
                  <span className="text-text-primary text-sm font-medium pr-4">
                    {item.question}
                  </span>
                  {isOpen ? (
                    <ChevronUp className="w-4 h-4 text-text-muted shrink-0" />
                  ) : (
                    <ChevronDown className="w-4 h-4 text-text-muted shrink-0" />
                  )}
                </button>

                {isOpen && (
                  <div className="px-5 pb-4 border-t border-border/50 pt-3">
                    <p className="text-text-secondary text-sm leading-relaxed">
                      {item.answer}
                    </p>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
