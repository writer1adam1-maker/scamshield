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
  Crown,
  Building2,
  Users,
} from "lucide-react";

const PLANS = [
  {
    id: "free",
    name: "Free",
    icon: Shield,
    monthlyPrice: 0,
    annualPrice: 0,
    scansLabel: "50 scans/month · +1/day",
    description: "For occasional scam checking. No card needed.",
    highlight: null,
    color: "text-text-secondary",
    features: [
      "50 scans/month",
      "+1 scan/day replenishment",
      "URL, text & screenshot scanning",
      "VERIDICT threat analysis",
      "Scam pattern database",
      "Referral bonuses",
    ],
    notIncluded: ["Scan history", "API access", "Bulk scanning", "Priority speed"],
  },
  {
    id: "starter",
    name: "Starter",
    icon: Zap,
    monthlyPrice: 4.99,
    annualPrice: 3.99,
    scansLabel: "300 scans/month · +10/day",
    description: "For individuals who check links regularly.",
    highlight: null,
    color: "text-shield",
    features: [
      "300 scans/month",
      "+10 scans/day replenishment",
      "Full scan history & dashboard",
      "VERIDICT + WHOIS/SSL analysis",
      "IP intelligence checks",
      "Referral bonuses",
    ],
    notIncluded: ["API access", "Bulk scanning"],
  },
  {
    id: "plus",
    name: "Plus",
    icon: Star,
    monthlyPrice: 8.99,
    annualPrice: 7.49,
    scansLabel: "1,000 scans/month · +35/day",
    description: "For power users and small teams.",
    highlight: "MOST POPULAR",
    color: "text-yellow-400",
    features: [
      "1,000 scans/month",
      "+35 scans/day replenishment",
      "Full scan history & dashboard",
      "All analysis engines",
      "Bulk scan (up to 20)",
      "Priority analysis speed",
      "Referral bonuses",
    ],
    notIncluded: ["API access"],
  },
  {
    id: "pro",
    name: "Pro",
    icon: Crown,
    monthlyPrice: 14.99,
    annualPrice: 11.99,
    scansLabel: "2,500 scans/month · +85/day",
    description: "For developers and security-conscious teams.",
    highlight: null,
    color: "text-purple-400",
    features: [
      "2,500 scans/month",
      "+85 scans/day replenishment",
      "Full scan history & dashboard",
      "All analysis engines",
      "Bulk scan (up to 50)",
      "REST API access",
      "Priority speed & support",
      "Referral bonuses",
    ],
    notIncluded: [] as string[],
  },
  {
    id: "business",
    name: "Business",
    icon: Building2,
    monthlyPrice: 49,
    annualPrice: 39,
    scansLabel: "Unlimited scans",
    description: "For agencies and businesses with high volume.",
    highlight: null,
    color: "text-green-400",
    features: [
      "Unlimited scans",
      "No daily limits",
      "All analysis engines",
      "Bulk scan (unlimited)",
      "Full REST API access",
      "Priority support + SLA",
      "Team seats (up to 10)",
      "Referral bonuses",
    ],
    notIncluded: [] as string[],
  },
] as const;

const FAQ = [
  {
    question: "How does daily replenishment work?",
    answer: "Each day at midnight UTC, your allowance tops up by the daily amount — but stops at your monthly cap. On Starter, you get +10/day up to 300 total. Monthly caps reset on the 1st of each month. Referral bonus scans stack on top and never expire.",
  },
  {
    question: "What happens to referral bonus scans?",
    answer: "Referral bonus scans go into a separate bonus pool that sits on top of your monthly cap. They don't expire when your month resets — they stay until you use them.",
  },
  {
    question: "What counts as a scan?",
    answer: "Each submission (URL, text, email body, or screenshot) counts as one scan. Re-submitting counts as a new scan.",
  },
  {
    question: "Can I cancel anytime?",
    answer: "Yes. All paid plans are monthly or annual with no lock-in. Cancel from Settings and keep access until your billing period ends.",
  },
  {
    question: "Is the API production-ready?",
    answer: "Yes. The REST API is available on Pro and Business plans with rate limit headers, API key auth, and JSON responses. Generate your key from Settings.",
  },
  {
    question: "How accurate is the detection?",
    answer: "VERIDICT runs 4 analysis layers: Fisher Information scoring, WHOIS/SSL checks, IP intelligence, and behavioral pattern matching. We continuously improve with community reports.",
  },
];

export default function PricingPage() {
  const router = useRouter();
  const [expandedFaq, setExpandedFaq] = useState<number | null>(null);
  const [annual, setAnnual] = useState(false);
  const [upgrading, setUpgrading] = useState<string | null>(null);

  async function handleUpgrade(planId: string) {
    if (planId === "free") { router.push("/"); return; }
    setUpgrading(planId);
    try {
      const res = await fetch("/api/stripe/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ plan: planId, annual }),
      });
      const data = await res.json();
      if (data.url) {
        window.location.href = data.url;
      } else if (res.status === 401) {
        router.push("/login?next=/pricing");
      }
    } catch {
      // silent
    } finally {
      setUpgrading(null);
    }
  }

  return (
    <div className="space-y-12 pb-16">
      {/* Header */}
      <div className="text-center pt-8">
        <h1 className="text-3xl md:text-4xl font-bold text-text-primary mb-3">
          Simple, Transparent Pricing
        </h1>
        <p className="text-text-secondary text-lg max-w-xl mx-auto">
          Start free. Upgrade when you need more. Cancel anytime.
        </p>
        <div className="flex items-center justify-center gap-3 mt-6">
          <span className={`text-sm ${!annual ? "text-text-primary" : "text-text-muted"}`}>Monthly</span>
          <button
            onClick={() => setAnnual(!annual)}
            role="switch"
            aria-checked={annual}
            className={`relative w-12 h-6 rounded-full transition-colors ${annual ? "bg-shield" : "bg-slate-mid"}`}
          >
            <div className={`absolute top-0.5 w-5 h-5 rounded-full bg-white transition-transform ${annual ? "translate-x-6" : "translate-x-0.5"}`} />
          </button>
          <span className={`text-sm ${annual ? "text-text-primary" : "text-text-muted"}`}>
            Annual <span className="ml-1 text-safe text-xs font-mono">SAVE ~20%</span>
          </span>
        </div>
        <div className="inline-flex items-center gap-2 mt-4 px-4 py-2 rounded-full bg-shield/10 border border-shield/20 text-shield text-sm">
          <Users size={14} />
          Refer friends → they get +20 bonus scans, you get +10 per referral
        </div>
      </div>

      {/* Plan cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4 max-w-7xl mx-auto px-4">
        {PLANS.map((plan) => {
          const Icon = plan.icon;
          const price = annual ? plan.annualPrice : plan.monthlyPrice;
          const isPopular = plan.highlight === "MOST POPULAR";

          return (
            <div
              key={plan.id}
              className={`glass-card p-5 flex flex-col relative overflow-hidden ${isPopular ? "border-yellow-400/30" : ""}`}
            >
              {isPopular && (
                <div className="absolute -top-px left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-yellow-400 to-transparent" />
              )}
              {plan.highlight && (
                <div className="absolute top-3 right-3 px-2 py-0.5 rounded-full bg-yellow-400/10 border border-yellow-400/20 text-yellow-400 text-[10px] font-mono">
                  {plan.highlight}
                </div>
              )}

              <div className="mb-4">
                <div className={`flex items-center gap-2 mb-2 ${plan.color}`}>
                  <Icon className="w-5 h-5" />
                  <h2 className="text-base font-semibold text-text-primary">{plan.name}</h2>
                </div>
                <div className="flex items-baseline gap-1 mb-1">
                  {price === 0 ? (
                    <span className="text-3xl font-bold font-mono text-text-primary">$0</span>
                  ) : (
                    <>
                      <span className="text-3xl font-bold font-mono text-text-primary">${price}</span>
                      <span className="text-text-muted text-xs">/mo{annual ? " billed yearly" : ""}</span>
                    </>
                  )}
                </div>
                <div className={`text-xs font-mono ${plan.color} mb-2`}>{plan.scansLabel}</div>
                <p className="text-text-muted text-xs">{plan.description}</p>
              </div>

              <ul className="space-y-2 flex-1 mb-5">
                {plan.features.map((f) => (
                  <li key={f} className="flex items-start gap-2 text-xs text-text-secondary">
                    <Check className={`w-3.5 h-3.5 shrink-0 mt-0.5 ${plan.color}`} />
                    {f}
                  </li>
                ))}
                {plan.notIncluded.map((f) => (
                  <li key={f} className="flex items-start gap-2 text-xs text-text-muted">
                    <X className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                    {f}
                  </li>
                ))}
              </ul>

              <button
                onClick={() => handleUpgrade(plan.id)}
                disabled={upgrading === plan.id}
                className={`w-full py-2.5 px-4 rounded-lg text-sm font-semibold transition-all flex items-center justify-center gap-2 disabled:opacity-50 ${
                  plan.id === "free"
                    ? "border border-border text-text-primary hover:border-shield/30 hover:bg-shield/5"
                    : isPopular
                    ? "bg-yellow-400 text-void hover:bg-yellow-300"
                    : "bg-shield text-void hover:bg-shield/90 shield-glow"
                }`}
              >
                <Lock className="w-3.5 h-3.5" />
                {upgrading === plan.id ? "Redirecting..." : plan.id === "free" ? "Get Started Free" : `Get ${plan.name}`}
              </button>
            </div>
          );
        })}
      </div>

      {/* Replenishment explainer */}
      <div className="max-w-2xl mx-auto px-4">
        <div className="glass-card p-6 space-y-3">
          <h3 className="text-base font-semibold text-text-primary flex items-center gap-2">
            <Zap size={16} className="text-shield" />
            How daily replenishment works
          </h3>
          <p className="text-sm text-text-secondary">
            Every day at midnight UTC, your scan allowance tops up by your plan&apos;s daily amount — stopping at your monthly cap.
            Monthly caps reset on the 1st of each month. Referral bonus scans stack on top and never expire.
          </p>
          <div className="grid grid-cols-3 gap-3 pt-2">
            {[
              { label: "Day 1", value: "+10 scans", sub: "Starter daily top-up" },
              { label: "Day 30", value: "300 cap hit", sub: "month ends soon" },
              { label: "Month reset", value: "Back to 0", sub: "bonus pool stays" },
            ].map((item) => (
              <div key={item.label} className="text-center p-3 rounded-lg bg-abyss/60 border border-border/50">
                <div className="text-xs text-text-muted mb-1">{item.label}</div>
                <div className="text-sm font-mono text-shield">{item.value}</div>
                <div className="text-[10px] text-text-muted mt-1">{item.sub}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* FAQ */}
      <div className="max-w-2xl mx-auto px-4">
        <h2 className="text-xl font-semibold text-text-primary mb-6 text-center">FAQ</h2>
        <div className="space-y-2">
          {FAQ.map((item, i) => {
            const isOpen = expandedFaq === i;
            return (
              <div key={i} className="glass-card overflow-hidden">
                <button
                  onClick={() => setExpandedFaq(isOpen ? null : i)}
                  className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-slate-deep/50 transition-colors"
                >
                  <span className="text-text-primary text-sm font-medium pr-4">{item.question}</span>
                  {isOpen ? <ChevronUp className="w-4 h-4 text-text-muted shrink-0" /> : <ChevronDown className="w-4 h-4 text-text-muted shrink-0" />}
                </button>
                {isOpen && (
                  <div className="px-5 pb-4 border-t border-border/50 pt-3">
                    <p className="text-text-secondary text-sm leading-relaxed">{item.answer}</p>
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
