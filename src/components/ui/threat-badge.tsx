import {
  Fish,
  Bitcoin,
  Truck,
  Heart,
  Briefcase,
  Gift,
  ShieldAlert,
  Users,
  CreditCard,
  HandHeart,
  Home,
  GraduationCap,
  MonitorSmartphone,
  ShoppingCart,
  Bell,
  Ticket,
  TrendingUp,
  FileText,
  Smartphone,
  type LucideIcon,
} from "lucide-react";
import clsx from "clsx";

export type ThreatCategory =
  | "phishing"
  | "crypto"
  | "delivery"
  | "romance"
  | "employment"
  | "prize"
  | "social_media"
  | "subscription_trap"
  | "fake_charity"
  | "rental_housing"
  | "student_loan"
  | "tech_support"
  | "marketplace_fraud"
  | "elder_scam"
  | "ticket_scam"
  | "investment_fraud"
  | "employment_scam"
  | "bank_otp"
  | "unknown";

type Severity = "low" | "medium" | "high" | "critical";

interface ThreatBadgeProps {
  category: ThreatCategory;
  severity?: Severity;
  className?: string;
}

const categoryConfig: Record<
  ThreatCategory,
  { label: string; icon: LucideIcon; bg: string; text: string; border: string; glow: string }
> = {
  phishing: {
    label: "Phishing",
    icon: Fish,
    bg: "bg-danger/10",
    text: "text-danger",
    border: "border-danger/30",
    glow: "shadow-[0_0_12px_rgba(255,59,92,0.25)]",
  },
  crypto: {
    label: "Crypto Scam",
    icon: Bitcoin,
    bg: "bg-purple-500/10",
    text: "text-purple-400",
    border: "border-purple-500/30",
    glow: "shadow-[0_0_12px_rgba(168,85,247,0.25)]",
  },
  delivery: {
    label: "Fake Delivery",
    icon: Truck,
    bg: "bg-shield/10",
    text: "text-shield",
    border: "border-shield/30",
    glow: "shadow-[0_0_12px_rgba(0,212,255,0.25)]",
  },
  romance: {
    label: "Romance Scam",
    icon: Heart,
    bg: "bg-pink-500/10",
    text: "text-pink-400",
    border: "border-pink-500/30",
    glow: "shadow-[0_0_12px_rgba(236,72,153,0.25)]",
  },
  employment: {
    label: "Job Scam",
    icon: Briefcase,
    bg: "bg-caution/10",
    text: "text-caution",
    border: "border-caution/30",
    glow: "shadow-[0_0_12px_rgba(251,191,36,0.25)]",
  },
  prize: {
    label: "Fake Prize",
    icon: Gift,
    bg: "bg-orange-500/10",
    text: "text-orange-400",
    border: "border-orange-500/30",
    glow: "shadow-[0_0_12px_rgba(249,115,22,0.25)]",
  },
  social_media: {
    label: "Social Media Scam",
    icon: Users,
    bg: "bg-indigo-500/10",
    text: "text-indigo-400",
    border: "border-indigo-500/30",
    glow: "shadow-[0_0_12px_rgba(99,102,241,0.25)]",
  },
  subscription_trap: {
    label: "Subscription Trap",
    icon: CreditCard,
    bg: "bg-amber-500/10",
    text: "text-amber-400",
    border: "border-amber-500/30",
    glow: "shadow-[0_0_12px_rgba(245,158,11,0.25)]",
  },
  fake_charity: {
    label: "Fake Charity",
    icon: HandHeart,
    bg: "bg-rose-500/10",
    text: "text-rose-400",
    border: "border-rose-500/30",
    glow: "shadow-[0_0_12px_rgba(244,63,94,0.25)]",
  },
  rental_housing: {
    label: "Rental Scam",
    icon: Home,
    bg: "bg-teal-500/10",
    text: "text-teal-400",
    border: "border-teal-500/30",
    glow: "shadow-[0_0_12px_rgba(20,184,166,0.25)]",
  },
  student_loan: {
    label: "Student Loan Scam",
    icon: GraduationCap,
    bg: "bg-emerald-500/10",
    text: "text-emerald-400",
    border: "border-emerald-500/30",
    glow: "shadow-[0_0_12px_rgba(16,185,129,0.25)]",
  },
  tech_support: {
    label: "Tech Support Scam",
    icon: MonitorSmartphone,
    bg: "bg-sky-500/10",
    text: "text-sky-400",
    border: "border-sky-500/30",
    glow: "shadow-[0_0_12px_rgba(14,165,233,0.25)]",
  },
  marketplace_fraud: {
    label: "Marketplace Fraud",
    icon: ShoppingCart,
    bg: "bg-orange-500/10",
    text: "text-orange-400",
    border: "border-orange-500/30",
    glow: "shadow-[0_0_12px_rgba(249,115,22,0.25)]",
  },
  elder_scam: {
    label: "Elder Scam",
    icon: Bell,
    bg: "bg-sky-500/10",
    text: "text-sky-400",
    border: "border-sky-500/30",
    glow: "shadow-[0_0_12px_rgba(14,165,233,0.25)]",
  },
  ticket_scam: {
    label: "Ticket Scam",
    icon: Ticket,
    bg: "bg-violet-500/10",
    text: "text-violet-400",
    border: "border-violet-500/30",
    glow: "shadow-[0_0_12px_rgba(139,92,246,0.25)]",
  },
  investment_fraud: {
    label: "Investment Fraud",
    icon: TrendingUp,
    bg: "bg-emerald-500/10",
    text: "text-emerald-400",
    border: "border-emerald-500/30",
    glow: "shadow-[0_0_12px_rgba(16,185,129,0.25)]",
  },
  employment_scam: {
    label: "Employment Scam",
    icon: FileText,
    bg: "bg-yellow-500/10",
    text: "text-yellow-400",
    border: "border-yellow-500/30",
    glow: "shadow-[0_0_12px_rgba(234,179,8,0.25)]",
  },
  bank_otp: {
    label: "Bank OTP Bypass",
    icon: Smartphone,
    bg: "bg-danger/10",
    text: "text-danger",
    border: "border-danger/30",
    glow: "shadow-[0_0_12px_rgba(255,59,92,0.25)]",
  },
  unknown: {
    label: "Unknown",
    icon: ShieldAlert,
    bg: "bg-text-muted/10",
    text: "text-text-secondary",
    border: "border-text-muted/30",
    glow: "",
  },
};

export function ThreatBadge({ category, severity = "medium", className }: ThreatBadgeProps) {
  const config = categoryConfig[category];
  const Icon = config.icon;
  const isHighSeverity = severity === "high" || severity === "critical";

  return (
    <span
      className={clsx(
        "inline-flex items-center gap-2 px-3 py-1.5 rounded-full border text-sm font-mono font-medium",
        config.bg,
        config.text,
        config.border,
        isHighSeverity && config.glow,
        isHighSeverity && "threat-pulse",
        className
      )}
    >
      <Icon size={14} />
      {config.label}
      {severity === "critical" && (
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-critical opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-critical" />
        </span>
      )}
    </span>
  );
}
