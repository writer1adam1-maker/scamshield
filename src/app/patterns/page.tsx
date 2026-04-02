"use client";

import { useState, useMemo } from "react";
import {
  Search,
  Shield,
  Mail,
  Package,
  Landmark,
  MonitorSmartphone,
  Heart,
  Bitcoin,
  Gift,
  Briefcase,
  Users,
  AlertTriangle,
  ChevronDown,
  ChevronUp,
  ShoppingCart,
  Bell,
  Ticket,
  TrendingUp,
  FileText,
  Smartphone,
} from "lucide-react";
import type { ThreatLevel } from "@/lib/algorithms/types";

// ---------------------------------------------------------------------------
// Scam pattern definitions
// ---------------------------------------------------------------------------

interface ScamPattern {
  id: string;
  icon: React.ReactNode;
  category: string;
  name: string;
  description: string;
  example: string;
  threatLevel: ThreatLevel;
  howItWorks: string;
  redFlags: string[];
  protectionTips: string[];
}

const PATTERNS: ScamPattern[] = [
  {
    id: "phishing",
    icon: <Mail className="w-6 h-6" />,
    category: "Phishing",
    name: "Phishing Attacks",
    description:
      "Fraudulent messages impersonating legitimate companies to steal login credentials, credit card numbers, or personal information.",
    example:
      "\"Your Netflix account has been suspended. Click here to update your payment information immediately: http://netfl1x-billing.com/update\"",
    threatLevel: "CRITICAL",
    howItWorks:
      "Attackers send emails or texts that look identical to legitimate services. They create fake websites that mirror real login pages. When you enter your credentials, they capture everything.",
    redFlags: [
      "Misspelled domain names (bankofamer1ca.com)",
      "Urgency: 'Your account will be closed in 24 hours'",
      "Generic greetings instead of your name",
      "Requests to 'verify' or 'update' account info via link",
      "Hover over links to see the real URL destination",
    ],
    protectionTips: [
      "Never click links in unsolicited emails",
      "Go directly to the company's website by typing the URL",
      "Enable two-factor authentication on all accounts",
      "Check the sender's actual email address, not just the display name",
    ],
  },
  {
    id: "package",
    icon: <Package className="w-6 h-6" />,
    category: "Package Delivery",
    name: "Package Delivery Scams",
    description:
      "Fake notifications about package deliveries that require a small payment or personal information to 'release' your package.",
    example:
      "\"USPS: Your package #US9214551 has been held at customs. Pay $1.99 shipping fee to release: usps-customs-pay.xyz\"",
    threatLevel: "HIGH",
    howItWorks:
      "Scammers send SMS or email pretending to be USPS, FedEx, or UPS. They claim a small fee is needed to release a package. The link leads to a phishing site that steals your credit card info.",
    redFlags: [
      "Unexpected delivery notification you didn't order",
      "Request for small payment ($1-5) to release a package",
      "Links to non-official domains",
      "Tracking numbers that don't match any real shipment",
    ],
    protectionTips: [
      "Track packages only through official carrier websites",
      "USPS, FedEx, and UPS never ask for payment via text",
      "If you didn't order anything, ignore the message",
      "Report suspicious texts by forwarding to 7726 (SPAM)",
    ],
  },
  {
    id: "bank",
    icon: <Landmark className="w-6 h-6" />,
    category: "Bank/Financial",
    name: "Banking & Financial Fraud",
    description:
      "Impersonation of banks or financial institutions to trick you into revealing account credentials or authorizing fraudulent transfers.",
    example:
      "\"Bank of America Security Alert: Unusual activity detected on your account ending in 4821. Call 1-888-555-0142 to verify.\"",
    threatLevel: "CRITICAL",
    howItWorks:
      "Scammers pose as your bank's fraud department. They may already know partial account details (from data breaches). They create urgency to get you to act without thinking.",
    redFlags: [
      "Unsolicited calls or texts about 'suspicious activity'",
      "Requests to share full account numbers or PINs",
      "Pressure to act immediately or face account closure",
      "Callback numbers that don't match your bank's official number",
    ],
    protectionTips: [
      "Hang up and call the number on the back of your card",
      "Banks never ask for your full PIN or password",
      "Set up official bank alerts through the banking app",
      "Never share one-time passcodes with callers",
    ],
  },
  {
    id: "irs",
    icon: <Landmark className="w-6 h-6" />,
    category: "IRS/Government",
    name: "Government Impersonation",
    description:
      "Scammers pretending to be the IRS, SSA, or other government agencies threatening arrest or legal action unless immediate payment is made.",
    example:
      "\"IRS FINAL WARNING: You owe $3,847 in back taxes. Failure to pay within 24 hours will result in arrest warrant #IRS-2026-8842. Call immediately.\"",
    threatLevel: "HIGH",
    howItWorks:
      "Scammers use caller ID spoofing to appear as government numbers. They threaten arrest, deportation, or license suspension. They demand payment via gift cards or wire transfer.",
    redFlags: [
      "Threats of arrest or legal action",
      "Demands for payment via gift cards or cryptocurrency",
      "Caller ID showing 'IRS' or 'Social Security'",
      "Refusal to send written documentation",
      "Urgency: 'Pay now or face consequences'",
    ],
    protectionTips: [
      "The IRS always contacts you by mail first",
      "Government agencies never demand gift card payment",
      "Never give personal info to unsolicited callers",
      "Report IRS scams to treasury.gov",
    ],
  },
  {
    id: "tech-support",
    icon: <MonitorSmartphone className="w-6 h-6" />,
    category: "Tech Support",
    name: "Tech Support Scams",
    description:
      "Fake alerts or cold calls claiming your computer is infected, then charging for unnecessary 'repairs' or installing malware.",
    example:
      "\"MICROSOFT WARNING: Your computer has been infected with a Trojan virus. Call our certified technicians immediately at 1-888-555-0199 to prevent data loss.\"",
    threatLevel: "HIGH",
    howItWorks:
      "Pop-up warnings or cold calls claim your computer is compromised. They request remote access via TeamViewer or similar tools. Once in, they may install malware, steal data, or charge hundreds for fake repairs.",
    redFlags: [
      "Pop-up warnings that won't close",
      "Unsolicited calls from 'Microsoft' or 'Apple'",
      "Requests for remote access to your computer",
      "Payment demanded via gift cards or wire transfer",
      "Phone numbers displayed on fake error screens",
    ],
    protectionTips: [
      "Microsoft and Apple never cold-call about viruses",
      "Close pop-ups using Task Manager (Ctrl+Alt+Delete)",
      "Never give remote access to unsolicited callers",
      "Use reputable antivirus software instead",
    ],
  },
  {
    id: "romance",
    icon: <Heart className="w-6 h-6" />,
    category: "Romance",
    name: "Romance Scams",
    description:
      "Fraudsters create fake profiles on dating sites or social media, build emotional relationships, then request money for emergencies.",
    example:
      "\"I'm a US military officer stationed overseas. I want to send you a package but I need $500 for customs fees. I'll pay you back when I return. I love you so much.\"",
    threatLevel: "HIGH",
    howItWorks:
      "Scammers create attractive fake profiles using stolen photos. They build an emotional connection over weeks or months. Eventually they claim an emergency requiring money. Requests escalate over time.",
    redFlags: [
      "Professing love very quickly",
      "Always has excuses to avoid video calls",
      "Claims to be military, doctor, or engineer overseas",
      "Requests money for 'emergencies' or travel",
      "Story inconsistencies when pressed for details",
    ],
    protectionTips: [
      "Reverse image search profile photos",
      "Never send money to someone you haven't met in person",
      "Be suspicious of anyone who avoids video calls",
      "Take relationships slowly and verify claims",
    ],
  },
  {
    id: "crypto",
    icon: <Bitcoin className="w-6 h-6" />,
    category: "Crypto/Investment",
    name: "Crypto & Investment Scams",
    description:
      "Fake investment opportunities promising guaranteed high returns, often involving cryptocurrency or forex trading.",
    example:
      "\"Join our exclusive crypto trading group! Our AI bot generates 500% returns monthly. Early investors get bonus tokens. Minimum investment only $250.\"",
    threatLevel: "CRITICAL",
    howItWorks:
      "Scammers promote fake trading platforms or tokens. Early 'investors' may see fake returns to encourage larger deposits. The platform eventually disappears with all funds (rug pull).",
    redFlags: [
      "Guaranteed returns (nothing is guaranteed in investing)",
      "Pressure to invest quickly before 'opportunity ends'",
      "Celebrity endorsements (usually fake)",
      "Unsolicited DMs about investment opportunities",
      "Platforms that make withdrawal difficult",
    ],
    protectionTips: [
      "If it sounds too good to be true, it is",
      "Research any platform on SEC.gov before investing",
      "Never invest based on social media tips",
      "Only use well-known, regulated exchanges",
    ],
  },
  {
    id: "lottery",
    icon: <Gift className="w-6 h-6" />,
    category: "Lottery/Prize",
    name: "Lottery & Prize Scams",
    description:
      "Notifications claiming you've won a lottery, sweepstakes, or prize that requires a fee to claim.",
    example:
      "\"CONGRATULATIONS! You've been selected as the winner of our $1,000,000 International Lottery. To claim your prize, pay the $99 processing fee.\"",
    threatLevel: "HIGH",
    howItWorks:
      "You receive a notification about winning a contest you never entered. To claim the 'prize' you must pay taxes, fees, or processing charges upfront. There is no prize.",
    redFlags: [
      "You never entered the contest",
      "Must pay fees to receive the prize",
      "Request for bank details to 'deposit winnings'",
      "Poor grammar and spelling",
      "Pressure to respond quickly",
    ],
    protectionTips: [
      "You can't win a contest you didn't enter",
      "Legitimate prizes never require upfront payment",
      "Never share bank details to receive a 'prize'",
      "Report to FTC at reportfraud.ftc.gov",
    ],
  },
  {
    id: "job",
    icon: <Briefcase className="w-6 h-6" />,
    category: "Job Offer",
    name: "Fake Job Offers",
    description:
      "Fraudulent job postings or unsolicited offers designed to steal personal information or money through fake 'training fees.'",
    example:
      "\"We found your resume online! Work from home and earn $5,000/week as a data entry specialist. No experience needed. Pay $199 for training materials to start.\"",
    threatLevel: "MEDIUM",
    howItWorks:
      "Scammers post attractive job listings or send unsolicited offers. They may conduct fake interviews to seem legitimate. Eventually they request payment for training, equipment, or background checks.",
    redFlags: [
      "Unrealistic salary for the position",
      "Upfront payment required for training or equipment",
      "Vague job description",
      "Interview via text message only",
      "Request for SSN or bank info before hiring",
    ],
    protectionTips: [
      "Research the company thoroughly",
      "Legitimate employers never charge to hire you",
      "Verify job postings on the company's official website",
      "Never share SSN until you've verified the employer",
    ],
  },
  {
    id: "social",
    icon: <Users className="w-6 h-6" />,
    category: "Social Media",
    name: "Social Media Scams",
    description:
      "Hacked accounts, fake profiles, and deceptive posts on social platforms designed to steal information or money.",
    example:
      "\"OMG look at this video of you! 😱 [suspicious-link.com] I can't believe someone posted this!!!\"",
    threatLevel: "MEDIUM",
    howItWorks:
      "Scammers hack or clone accounts to message friends. They share links to fake login pages or malware. They may also run fake giveaways or charity drives using stolen brand identities.",
    redFlags: [
      "Messages from friends with unusual tone or content",
      "Links to external sites from social DMs",
      "Requests for money from 'friends' in emergency",
      "Too-good-to-be-true giveaways",
      "New accounts impersonating brands or celebrities",
    ],
    protectionTips: [
      "Verify unusual messages through another channel",
      "Enable 2FA on all social media accounts",
      "Don't click links in unexpected DMs",
      "Report impersonation accounts to the platform",
    ],
  },
  {
    id: "marketplace",
    icon: <ShoppingCart className="w-6 h-6" />,
    category: "Marketplace Fraud",
    name: "Online Marketplace Scams",
    description:
      "Fraudulent buyers or sellers on platforms like Facebook Marketplace, Craigslist, or eBay using fake payments, overpayment tricks, or advance-fee schemes.",
    example:
      "\"I'll send you a Zelle payment for $800 but I accidentally sent $1,200. Please refund the $400 difference before I arrange pickup.\"",
    threatLevel: "HIGH",
    howItWorks:
      "In overpayment scams, the 'buyer' sends a fake check or reverses a payment after you refund the difference. In advance-fee scams, sellers demand shipping fees upfront for items that don't exist. Platforms like PayPal G&S protect buyers, not sellers sending refunds.",
    redFlags: [
      "Buyer offers to pay more than asking price",
      "Requests to move communication off the platform",
      "Insistence on Zelle, Cash App, or wire transfer",
      "Buyer claims to be deployed military unable to meet in person",
      "Overpayment followed by refund request",
    ],
    protectionTips: [
      "Meet in person for cash transactions when possible",
      "Use PayPal Goods & Services, not Friends & Family",
      "Never refund a payment you didn't receive in hand",
      "If overpaid, return the item — don't send cash back",
    ],
  },
  {
    id: "elder",
    icon: <Bell className="w-6 h-6" />,
    category: "Elder Scam",
    name: "Elder-Targeted Scams",
    description:
      "Scams specifically designed to exploit older adults through grandparent emergencies, fake government officials, or caregiver fraud.",
    example:
      "\"Grandma, it's me! I was in a car accident and I'm in jail. Please don't tell Mom and Dad — just wire $3,000 for bail money to my lawyer.\"",
    threatLevel: "CRITICAL",
    howItWorks:
      "The grandparent scam uses social engineering to make seniors believe a grandchild is in trouble. Scammers create urgency and secrecy to prevent victims from verifying. They often follow up with a fake 'lawyer' or 'police officer' who confirms the story.",
    redFlags: [
      "Caller claims to be a relative in an emergency",
      "Asks you to keep it secret from other family members",
      "Requests cash, gift cards, or wire transfer urgently",
      "A second caller posing as a lawyer, officer, or bail agent",
      "Story involves accidents, arrests, or hospital bills",
    ],
    protectionTips: [
      "Hang up and call the relative directly at their known number",
      "Establish a family code word for real emergencies",
      "Never send cash or gift cards for 'bail' or 'fines'",
      "Talk to trusted family members before acting",
    ],
  },
  {
    id: "ticket",
    icon: <Ticket className="w-6 h-6" />,
    category: "Ticket Scam",
    name: "Fake Event & Concert Tickets",
    description:
      "Fraudulent ticket sellers offering counterfeit, invalid, or non-existent tickets to high-demand concerts, sports, or events.",
    example:
      "\"2 Taylor Swift VIP tickets, floor seats, $350 each. Last minute can't go. Will send PDF after Venmo payment. No refunds.\"",
    threatLevel: "HIGH",
    howItWorks:
      "Scammers list tickets for sold-out events at slightly above face value to seem legitimate. They use stolen ticket images or duplicate barcodes. Once payment is sent, they disappear or send PDFs that are rejected at the gate.",
    redFlags: [
      "Seller insists on Venmo, Zelle, or wire — no buyer protection",
      "Sends PDF tickets that can be easily duplicated",
      "No verifiable identity or social media history",
      "Tickets to events that are sold out everywhere else",
      "Pressure to buy immediately before 'someone else takes them'",
    ],
    protectionTips: [
      "Only buy from official box offices or verified resellers (StubHub, Ticketmaster)",
      "Never pay via apps without buyer protection",
      "Ask to transfer tickets through the official platform",
      "Check seller's profile age and reviews carefully",
    ],
  },
  {
    id: "investment",
    icon: <TrendingUp className="w-6 h-6" />,
    category: "Investment Fraud",
    name: "Investment & Ponzi Schemes",
    description:
      "Fraudulent investment opportunities including Ponzi schemes, unregistered securities, and forex/crypto 'guaranteed return' platforms.",
    example:
      "\"Our AI-powered trading bot generates 40% monthly returns. Join 10,000 members already earning passive income. Slots closing in 48 hours. Min deposit: $500.\"",
    threatLevel: "CRITICAL",
    howItWorks:
      "Ponzi schemes pay early investors with new investor money to create the illusion of returns. Promoters show fabricated dashboards with growing balances. Withdrawals are processed initially, then become 'delayed' as the scheme collapses. Recruitment bonuses disguise the pyramid structure.",
    redFlags: [
      "Guaranteed returns above 10% per month",
      "Pressure to recruit others for bonus commissions",
      "Unregistered investment platform or unlicensed advisor",
      "Difficulty or fees required to withdraw funds",
      "Celebrity or influencer endorsements (often fake or paid)",
    ],
    protectionTips: [
      "Verify any investment firm at SEC.gov/check",
      "Guaranteed returns don't exist in legitimate investing",
      "Avoid platforms requiring recruitment for maximum returns",
      "Never invest money you can't afford to lose completely",
    ],
  },
  {
    id: "employment-scam",
    icon: <FileText className="w-6 h-6" />,
    category: "Employment Scam",
    name: "Employment & Reshipping Scams",
    description:
      "Fake job offers that turn victims into unwitting money mules or package reshippers, exposing them to legal liability and financial loss.",
    example:
      "\"Work from home! Receive packages, repackage, and ship overseas. $50/package. You'll receive a check for supplies — keep $200, wire the rest.\"",
    threatLevel: "HIGH",
    howItWorks:
      "Reshipping scams make victims handle stolen goods without knowing. Money mule scams use fake payroll checks that bounce after the victim forwards the funds. Both expose victims to fraud charges and identity theft.",
    redFlags: [
      "Job involves receiving and forwarding packages or money",
      "Overpayment check with request to wire back the difference",
      "No interview or vague job description",
      "Employer asks for personal bank account details immediately",
      "Unsolicited job offer via text or LinkedIn from unknown recruiter",
    ],
    protectionTips: [
      "Legitimate employers never pay you to forward their money",
      "Never use your personal bank account for employer transactions",
      "Research the company on LinkedIn and Google before applying",
      "Be suspicious of jobs requiring no experience with high pay",
    ],
  },
  {
    id: "bank-otp",
    icon: <Smartphone className="w-6 h-6" />,
    category: "Bank OTP Bypass",
    name: "Bank OTP & Vishing Scams",
    description:
      "Phone-based scams where impersonators pose as bank fraud departments to extract one-time passcodes and authorize fraudulent transfers.",
    example:
      "\"This is Citibank Fraud Prevention. We detected suspicious activity on your account. To freeze it, please confirm the 6-digit code we just sent you.\"",
    threatLevel: "CRITICAL",
    howItWorks:
      "Scammers already have partial account details from data breaches. They call posing as bank security teams, creating urgency. They ask victims to read back the OTP sent to their phone — which actually authorizes the scammer's own transaction. Once the code is shared, money is gone instantly.",
    redFlags: [
      "Unsolicited call from 'your bank' about suspicious activity",
      "Request to read back a text message code you just received",
      "Caller discourages you from calling the number on your card",
      "Urgency: 'We need the code now to protect your account'",
      "Request to transfer funds to a 'safe account'",
    ],
    protectionTips: [
      "Never share OTP codes with anyone — not even your bank",
      "Hang up and call the number on the back of your card",
      "Your bank will never ask you to read back an SMS code",
      "Report vishing calls to your bank's fraud line immediately",
    ],
  },
];

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export default function PatternsPage() {
  const [search, setSearch] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [levelFilter, setLevelFilter] = useState<"all" | ThreatLevel>("all");

  const filtered = useMemo(() => {
    return PATTERNS.filter((p) => {
      if (levelFilter !== "all" && p.threatLevel !== levelFilter) return false;
      if (search) {
        const q = search.toLowerCase();
        return (
          p.category.toLowerCase().includes(q) ||
          p.name.toLowerCase().includes(q) ||
          p.description.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [search, levelFilter]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-text-primary flex items-center gap-2">
          <Shield className="w-6 h-6 text-shield" />
          Scam Patterns Database
        </h1>
        <p className="text-text-secondary text-sm mt-1">
          Learn to recognize common scam tactics and protect yourself
        </p>
      </div>

      {/* Search & Filter */}
      <div className="glass-card p-4 flex flex-wrap items-center gap-4">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
          <input
            type="text"
            placeholder="Search scam patterns..."
            aria-label="Search scam patterns"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-10 pr-4 py-2 bg-slate-deep border border-border rounded-lg text-sm text-text-primary placeholder:text-text-muted focus:outline-none focus:border-shield/50 transition-colors"
          />
        </div>

        <select
          value={levelFilter}
          onChange={(e) => setLevelFilter(e.target.value as "all" | ThreatLevel)}
          aria-label="Filter by threat level"
          className="bg-slate-deep border border-border rounded-lg px-3 py-2 text-sm text-text-primary focus:outline-none focus:border-shield/50"
        >
          <option value="all">All Threat Levels</option>
          <option value="MEDIUM">Medium</option>
          <option value="HIGH">High</option>
          <option value="CRITICAL">Critical</option>
        </select>
      </div>

      {/* Pattern Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filtered.map((pattern) => {
          const isExpanded = expandedId === pattern.id;

          return (
            <div
              key={pattern.id}
              className="glass-card overflow-hidden hover:border-shield/20 transition-all duration-300"
            >
              {/* Card Header */}
              <div className="p-5">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg bg-shield/10 border border-shield/20 flex items-center justify-center text-shield">
                      {pattern.icon}
                    </div>
                    <div>
                      <h3 className="font-semibold text-text-primary">
                        {pattern.category}
                      </h3>
                      <PatternLevelBadge level={pattern.threatLevel} />
                    </div>
                  </div>
                </div>

                <p className="text-text-secondary text-sm mb-4">
                  {pattern.description}
                </p>

                {/* Example */}
                <div className="bg-slate-deep rounded-lg p-3 border border-border/50 mb-4">
                  <p className="text-xs font-mono text-text-muted uppercase tracking-wider mb-1">
                    Example
                  </p>
                  <p className="text-text-secondary text-sm italic">
                    {pattern.example}
                  </p>
                </div>

                {/* Expand button */}
                <button
                  onClick={() => setExpandedId(isExpanded ? null : pattern.id)}
                  className="flex items-center gap-1 text-shield text-sm font-mono hover:text-shield-dim transition-colors"
                >
                  {isExpanded ? (
                    <>
                      <ChevronUp className="w-4 h-4" />
                      Less info
                    </>
                  ) : (
                    <>
                      <ChevronDown className="w-4 h-4" />
                      Learn more
                    </>
                  )}
                </button>
              </div>

              {/* Expanded Educational Content */}
              {isExpanded && (
                <div className="px-5 pb-5 border-t border-border/50 pt-4 space-y-4">
                  {/* How it works */}
                  <div>
                    <h4 className="text-xs font-mono text-text-muted uppercase tracking-wider mb-2">
                      How It Works
                    </h4>
                    <p className="text-text-secondary text-sm">
                      {pattern.howItWorks}
                    </p>
                  </div>

                  {/* Red Flags */}
                  <div>
                    <h4 className="text-xs font-mono text-text-muted uppercase tracking-wider mb-2 flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3 text-danger" />
                      Red Flags
                    </h4>
                    <ul className="space-y-1">
                      {pattern.redFlags.map((flag, i) => (
                        <li key={i} className="flex items-start gap-2 text-sm text-text-secondary">
                          <span className="w-1.5 h-1.5 rounded-full bg-danger shrink-0 mt-1.5" />
                          {flag}
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* Protection Tips */}
                  <div>
                    <h4 className="text-xs font-mono text-text-muted uppercase tracking-wider mb-2 flex items-center gap-1">
                      <Shield className="w-3 h-3 text-safe" />
                      How to Protect Yourself
                    </h4>
                    <ul className="space-y-1">
                      {pattern.protectionTips.map((tip, i) => (
                        <li key={i} className="flex items-start gap-2 text-sm text-text-secondary">
                          <span className="w-1.5 h-1.5 rounded-full bg-safe shrink-0 mt-1.5" />
                          {tip}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {filtered.length === 0 && (
        <div className="glass-card p-12 text-center">
          <p className="text-text-muted">No patterns match your search.</p>
        </div>
      )}
    </div>
  );
}

function PatternLevelBadge({ level }: { level: ThreatLevel }) {
  const styles: Record<ThreatLevel, string> = {
    SAFE: "bg-safe/10 text-safe border-safe/20",
    LOW: "bg-safe/10 text-safe border-safe/20",
    MEDIUM: "bg-caution/10 text-caution border-caution/20",
    HIGH: "bg-danger/10 text-danger border-danger/20",
    CRITICAL: "bg-critical/10 text-critical border-critical/20",
  };

  return (
    <span className={`inline-block px-2 py-0.5 text-[10px] font-mono uppercase rounded border ${styles[level]} mt-1`}>
      {level} THREAT
    </span>
  );
}
