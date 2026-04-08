"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import {
  Shield, Zap, Check, X, ChevronDown, ChevronUp, Lock, Crown, Building2, Users, Gift,
  Rocket, Globe,
} from "lucide-react";
import { createBrowserClient } from "@/lib/supabase/client";

const PLANS = [
  {
    id: "free",
    name: "Free",
    icon: Shield,
    monthlyPrice: 0,
    annualPrice: 0,
    scansLabel: "50 scans / 30 days",
    seats: 1,
    description: "For occasional scam checking. No card needed.",
    highlight: null,
    color: "text-text-secondary",
    features: [
      "50 scans per 30 days",
      "URL, text & screenshot scanning",
      "VERIDICT threat analysis",
      "Scam pattern database",
      "Earn bonus scans via referrals",
    ],
    notIncluded: ["Scan history", "API access", "Bulk scanning"],
  },
  {
    id: "starter",
    name: "Starter",
    icon: Zap,
    monthlyPrice: 4.99,
    annualPrice: 3.99,
    scansLabel: "200 scans / 30 days",
    seats: 1,
    description: "For people who check links regularly.",
    highlight: null,
    color: "text-shield",
    features: [
      "200 scans per 30 days",
      "Full scan history & dashboard",
      "VERIDICT + WHOIS/SSL analysis",
      "IP intelligence checks",
      "Earn bonus scans via referrals",
    ],
    notIncluded: ["API access", "Bulk scanning"],
  },
  {
    id: "pro",
    name: "Pro",
    icon: Crown,
    monthlyPrice: 12.99,
    annualPrice: 10.49,
    scansLabel: "500 scans / 30 days",
    seats: 1,
    description: "For power users and small businesses.",
    highlight: "POPULAR",
    color: "text-yellow-400",
    features: [
      "500 scans per 30 days",
      "Full scan history & dashboard",
      "All analysis engines",
      "Bulk scan (up to 20)",
      "Priority analysis speed",
      "Earn bonus scans via referrals",
    ],
    notIncluded: ["REST API access"],
  },
  {
    id: "team",
    name: "Team",
    icon: Users,
    monthlyPrice: 49,
    annualPrice: 39,
    scansLabel: "5,000 scans / 30 days",
    seats: 5,
    comingSoon: true,
    description: "For small teams and agencies. API included.",
    highlight: null,
    color: "text-green-400",
    features: [
      "5,000 scans per 30 days",
      "Full scan history & dashboard",
      "All analysis engines",
      "Bulk scanning (unlimited)",
      "REST API access",
      "5 team seats",
      "Earn bonus scans via referrals",
      "$3 / 1,000 overage scans",
    ],
    notIncluded: [] as string[],
  },
  {
    id: "organization",
    name: "Organization",
    icon: Building2,
    monthlyPrice: 149,
    annualPrice: 119,
    scansLabel: "20,000 scans / 30 days",
    seats: 15,
    comingSoon: true,
    description: "For growing organizations needing scale.",
    highlight: null,
    color: "text-purple-400",
    features: [
      "20,000 scans per 30 days",
      "Full scan history & dashboard",
      "All analysis engines",
      "Bulk scanning (unlimited)",
      "REST API access",
      "15 team seats",
      "Priority support",
      "$3 / 1,000 overage scans",
    ],
    notIncluded: [] as string[],
  },
  {
    id: "enterprise",
    name: "Enterprise",
    icon: Globe,
    monthlyPrice: 399,
    annualPrice: 319,
    scansLabel: "100,000 scans / 30 days",
    seats: 999,
    comingSoon: true,
    description: "For large enterprises and high-volume platforms.",
    highlight: null,
    color: "text-orange-400",
    features: [
      "100,000 scans per 30 days",
      "Full scan history & dashboard",
      "All analysis engines",
      "Bulk scanning (unlimited)",
      "REST API access + webhooks",
      "Unlimited seats",
      "SLA + dedicated support",
      "$3 / 1,000 overage scans",
    ],
    notIncluded: [] as string[],
  },
] as const;

const FAQ = [
  {
    question: "How does the 30-day rolling window work?",
    answer: "Your scan allowance resets 30 days after you signed up (or last renewed). So if you joined on the 10th, your next reset is the 10th of the following month — not the 1st. This means you always get a full 30 days regardless of when you join.",
  },
  {
    question: "What are referral bonus scans?",
    answer: "Share your referral code with a friend. When they sign up using your code, they get +10 bonus scans and you get +10. Bonus scans stack on top of your plan's allowance and never expire — they carry over when your 30-day window resets.",
  },
  {
    question: "How many people can I refer?",
    answer: "You can refer up to 5 new accounts per day. Each successful referral earns you +10 bonus scans. There's no cap on total bonus scans you can accumulate.",
  },
  {
    question: "What are overage scans?",
    answer: "On Team, Organization, and Enterprise plans, if you exceed your monthly scan cap, additional scans are charged at $3 per 1,000 scans. This way you never get cut off mid-month. You'll receive a bill at the end of the billing period for any overages.",
  },
  {
    question: "What counts as a scan?",
    answer: "Each submission — URL, text message, email body, or screenshot — counts as one scan. Re-submitting the same content counts as a new scan.",
  },
  {
    question: "Can I cancel anytime?",
    answer: "Yes. All paid plans are monthly or annual with no lock-in. Cancel from Settings and you keep access until your current period ends.",
  },
  {
    question: "Is the API production-ready?",
    answer: "Yes. The REST API is available on Team plan and above, with API key authentication, rate limit headers, and JSON responses. Generate your key from Settings.",
  },
  {
    question: "How do team seats work?",
    answer: "Team seats let multiple people share one subscription. Each seat gets their own login and scan quota from the shared pool. Add and remove seats from Settings at any time.",
  },
];

export default function PricingPage() {
  const router = useRouter();
  const [expandedFaq, setExpandedFaq] = useState<number | null>(null);
  const [annual, setAnnual] = useState(false);
  const [upgrading, setUpgrading] = useState<string | null>(null);
  const [currentUser, setCurrentUser] = useState<{ id: string; email: string } | null>(null);

  useEffect(() => {
    const supabase = createBrowserClient();
    supabase.auth.getUser().then(({ data }) => {
      if (data.user) setCurrentUser({ id: data.user.id, email: data.user.email ?? "" });
    });
  }, []);

  const LEMON_URLS: Record<string, { monthly: string; annual: string }> = {
    starter:      { monthly: "https://mo-digital-labs.lemonsqueezy.com/checkout/buy/69c41815-6062-42e0-8d6a-c3d82b3f3756", annual: "https://mo-digital-labs.lemonsqueezy.com/checkout/buy/5bbad25c-f267-4059-a5ec-4678df9cb95e" },
    pro:          { monthly: "https://mo-digital-labs.lemonsqueezy.com/checkout/buy/31f6181c-1155-4f2c-a0b1-c88b325853b2", annual: "https://mo-digital-labs.lemonsqueezy.com/checkout/buy/45d28624-08df-4369-a476-0cfa5bd6a9bf" },
    team:         { monthly: "https://mo-digital-labs.lemonsqueezy.com/checkout/buy/546bd752-a465-4fe6-a03f-f44776796d7a", annual: "https://mo-digital-labs.lemonsqueezy.com/checkout/buy/1f411d08-a726-4b55-9bff-b7b4821c79a6" },
    organization: { monthly: "https://mo-digital-labs.lemonsqueezy.com/checkout/buy/d9ae6baf-dae9-4b09-9dab-c1e3df1228c9", annual: "https://mo-digital-labs.lemonsqueezy.com/checkout/buy/4a76a922-10ae-48cf-b44e-c6683225f38b" },
    enterprise:   { monthly: "https://mo-digital-labs.lemonsqueezy.com/checkout/buy/eff6c38f-1169-427c-994d-816d65e3b148", annual: "https://mo-digital-labs.lemonsqueezy.com/checkout/buy/2ee8e14a-d483-4d85-b2b6-96d74be0790e" },
  };

  async function handleUpgrade(planId: string) {
    if (planId === "free") { router.push("/"); return; }

    // Must be logged in — webhook needs user ID to link payment to account
    if (!currentUser) {
      router.push("/login?redirect=/pricing");
      return;
    }

    const urls = LEMON_URLS[planId];
    if (!urls) return;

    setUpgrading(planId);

    const baseUrl = annual ? urls.annual : urls.monthly;

    // Pass user identity so webhook can match payment to account
    const params = new URLSearchParams();
    params.set("checkout[custom][user_id]", currentUser.id);
    params.set("checkout[email]", currentUser.email);
    params.set("checkout[custom][plan]", planId);

    window.location.href = baseUrl + "?" + params.toString();
  }

  // Split into 2 rows: individual (3) + business (3)
  const individualPlans = PLANS.slice(0, 3);
  const businessPlans = PLANS.slice(3);

  return (
    <div className="space-y-12 pb-16">
      {/* Header */}
      <div className="text-center pt-8">
        <h1 className="text-3xl md:text-4xl font-bold text-text-primary mb-3">
          Simple, Transparent Pricing
        </h1>
        <p className="text-text-secondary text-lg max-w-xl mx-auto">
          Flat 30-day allowances. No daily limits. Cancel anytime.
        </p>

        {/* Annual toggle */}
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

        {/* Referral banner */}
        <div className="inline-flex items-center gap-2 mt-4 px-4 py-2 rounded-full bg-shield/10 border border-shield/20 text-shield text-sm">
          <Gift size={14} />
          Refer a friend → they get +10 scans, you get +10. Bonus scans never expire.
        </div>
      </div>

      {/* Individual plans */}
      <div>
        <p className="text-xs font-mono text-text-muted uppercase tracking-widest text-center mb-4">Individual</p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 max-w-4xl mx-auto px-4">
          {individualPlans.map((plan) => <PlanCard key={plan.id} plan={plan} annual={annual} upgrading={upgrading} onUpgrade={handleUpgrade} />)}
        </div>
      </div>

      {/* Business plans */}
      <div>
        <p className="text-xs font-mono text-text-muted uppercase tracking-widest text-center mb-4">Business &amp; Enterprise</p>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 max-w-4xl mx-auto px-4">
          {businessPlans.map((plan) => <PlanCard key={plan.id} plan={plan} annual={annual} upgrading={upgrading} onUpgrade={handleUpgrade} />)}
        </div>
        <p className="text-center text-xs text-text-muted mt-4">
          All business plans include <strong className="text-text-secondary">$3 / 1,000 overage scans</strong> — you&apos;re never cut off.
        </p>
      </div>

      {/* How referrals work */}
      <div className="max-w-2xl mx-auto px-4">
        <div className="glass-card p-6 space-y-4">
          <h3 className="text-base font-semibold text-text-primary flex items-center gap-2">
            <Users size={16} className="text-shield" />
            How referral bonuses work
          </h3>
          <div className="grid grid-cols-3 gap-3">
            {[
              { step: "1", label: "Share your code", desc: "Find it in Settings after signup" },
              { step: "2", label: "Friend signs up", desc: "They enter your code at registration" },
              { step: "3", label: "Both get bonus scans", desc: "+10 for them, +10 for you" },
            ].map((item) => (
              <div key={item.step} className="text-center p-3 rounded-lg bg-abyss/60 border border-border/50">
                <div className="w-6 h-6 rounded-full bg-shield/20 text-shield text-xs font-bold flex items-center justify-center mx-auto mb-2">{item.step}</div>
                <div className="text-xs font-medium text-text-primary mb-1">{item.label}</div>
                <div className="text-[10px] text-text-muted">{item.desc}</div>
              </div>
            ))}
          </div>
          <p className="text-xs text-text-muted">
            Bonus scans stack on top of your plan allowance and <strong className="text-text-secondary">never expire</strong> — they carry over when your 30-day window resets.
          </p>
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

type PlanType = typeof PLANS[number];

function PlanCard({ plan, annual, upgrading, onUpgrade }: {
  plan: PlanType;
  annual: boolean;
  upgrading: string | null;
  onUpgrade: (id: string) => void;
}) {
  const Icon = plan.icon;
  const price = annual ? plan.annualPrice : plan.monthlyPrice;
  const isPopular = plan.highlight === "POPULAR";
  const comingSoon = (plan as { comingSoon?: boolean }).comingSoon === true;

  return (
    <div className={`glass-card p-5 flex flex-col relative overflow-hidden ${isPopular ? "border-yellow-400/30" : ""} ${comingSoon ? "opacity-50 grayscale pointer-events-none select-none" : ""}`}>
      {isPopular && (
        <div className="absolute -top-px left-0 right-0 h-0.5 bg-gradient-to-r from-transparent via-yellow-400 to-transparent" />
      )}
      {comingSoon ? (
        <div className="absolute top-3 right-3 px-2 py-0.5 rounded-full bg-slate-500/20 border border-slate-500/30 text-slate-400 text-[10px] font-mono">
          COMING SOON
        </div>
      ) : plan.highlight ? (
        <div className="absolute top-3 right-3 px-2 py-0.5 rounded-full bg-yellow-400/10 border border-yellow-400/20 text-yellow-400 text-[10px] font-mono">
          {plan.highlight}
        </div>
      ) : null}

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
        <div className={`text-xs font-mono ${plan.color} mb-1`}>{plan.scansLabel}</div>
        {plan.seats > 1 && (
          <div className="text-xs text-text-muted mb-1">{plan.seats === 999 ? "Unlimited seats" : `${plan.seats} seats`}</div>
        )}
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
        onClick={() => onUpgrade(plan.id)}
        disabled={upgrading === plan.id || comingSoon}
        className={`w-full py-2.5 px-4 rounded-lg text-sm font-semibold transition-all flex items-center justify-center gap-2 disabled:opacity-50 ${
          comingSoon
            ? "bg-slate-700 text-slate-400 cursor-not-allowed"
            : plan.id === "free"
            ? "border border-border text-text-primary hover:border-shield/30 hover:bg-shield/5"
            : isPopular
            ? "bg-yellow-400 text-void hover:bg-yellow-300"
            : "bg-shield text-void hover:bg-shield/90 shield-glow"
        }`}
      >
        {comingSoon ? "Coming Soon" : plan.id === "free" ? <><Shield className="w-3.5 h-3.5" /> Get Started Free</> : upgrading === plan.id ? <><Rocket className="w-3.5 h-3.5 animate-bounce" /> Redirecting...</> : <><Lock className="w-3.5 h-3.5" /> {`Get ${plan.name}`}</>}
      </button>
    </div>
  );
}
