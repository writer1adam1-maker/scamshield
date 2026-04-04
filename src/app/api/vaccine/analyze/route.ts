// ============================================================================
// POST /api/vaccine/analyze — Analyze phone number, SMS text, or email body
// for scam indicators and return vaccine breach cards
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { analyzePhoneNumbers } from "@/lib/algorithms/phone-analyzer";
import { detectLinguisticDeception } from "@/lib/algorithms/linguistic-deception";
import { checkRateLimit } from "@/lib/rate-limit";
import { getClientIp } from "@/lib/utils";
import { getUserFromRequest, canScan, incrementScanCount } from "@/lib/auth-helpers";

export type VaccineAnalyzeMode = "phone" | "sms" | "email";

export interface VaccineBreachPoint {
  id: string;
  title: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  category: string;
  ruleType: "block" | "warn" | "sandbox" | "disable" | "monitor";
  message?: string;
}

export interface VaccineAnalyzeResponse {
  mode: VaccineAnalyzeMode;
  input: string;
  threatScore: number;
  threatLevel: "safe" | "low" | "medium" | "high" | "critical";
  breachPoints: VaccineBreachPoint[];
  summary: string;
  processingTimeMs: number;
}

function severityFromScore(score: number): VaccineBreachPoint["severity"] {
  if (score >= 0.75) return "critical";
  if (score >= 0.55) return "high";
  if (score >= 0.35) return "medium";
  return "low";
}

function threatLevelFromScore(score: number): VaccineAnalyzeResponse["threatLevel"] {
  if (score >= 75) return "critical";
  if (score >= 55) return "high";
  if (score >= 30) return "medium";
  if (score >= 10) return "low";
  return "safe";
}

function analyzePhone(text: string): { breachPoints: VaccineBreachPoint[]; score: number } {
  const result = analyzePhoneNumbers(text);
  const breachPoints: VaccineBreachPoint[] = [];

  for (const phone of result.phones) {
    if (phone.scamAssociationScore < 0.1) continue;
    const sev = severityFromScore(phone.scamAssociationScore);
    const topFlag = phone.flags[0] || "Suspicious phone number";
    breachPoints.push({
      id: `phone-${phone.normalizedNumber.slice(-6)}`,
      title: phone.isPremiumRate
        ? "Premium-Rate Number Detected"
        : phone.isSuspiciousAreaCode
        ? "High-Risk Area Code"
        : "Suspicious Phone Number",
      description: `${phone.number} (${phone.country}) — ${topFlag}`,
      severity: sev,
      category: "Phone Fraud",
      ruleType: sev === "critical" || sev === "high" ? "block" : "warn",
      message: phone.flags.join(" · "),
    });
  }

  const score = result.highestRisk * 100;
  return { breachPoints, score };
}

function analyzeText(text: string, mode: "sms" | "email"): { breachPoints: VaccineBreachPoint[]; score: number } {
  const result = detectLinguisticDeception(text);
  const breachPoints: VaccineBreachPoint[] = [];

  // De-duplicate by tactic id
  const seen = new Set<string>();
  for (const tactic of result.deceptionTactics) {
    if (seen.has(tactic.tacticId)) continue;
    seen.add(tactic.tacticId);
    const sev = severityFromScore(tactic.severity);
    const categoryLabel =
      tactic.category === "authority"    ? "Authority Faking" :
      tactic.category === "urgency"      ? "False Urgency" :
      tactic.category === "isolation"    ? "Isolation Tactic" :
      tactic.category === "fear"         ? "Fear Manipulation" :
      tactic.category === "greed"        ? "Greed Exploitation" :
      tactic.category === "reciprocity"  ? "Reciprocity Trap" :
      tactic.category === "social_proof" ? "Fake Social Proof" :
      "Deception Tactic";
    breachPoints.push({
      id: `${mode}-${tactic.tacticId.toLowerCase()}`,
      title: tactic.tacticName,
      description: `Deceptive language pattern: "${tactic.evidence.substring(0, 80)}${tactic.evidence.length > 80 ? "…" : ""}"`,
      severity: sev,
      category: categoryLabel,
      ruleType: sev === "critical" || sev === "high" ? "block" : sev === "medium" ? "warn" : "monitor",
      message: tactic.tacticName + " — " + categoryLabel,
    });
  }

  // Also run phone analysis on the same text
  const phoneResult = analyzePhoneNumbers(text);
  for (const phone of phoneResult.phones) {
    if (phone.scamAssociationScore < 0.25) continue;
    const sev = severityFromScore(phone.scamAssociationScore);
    breachPoints.push({
      id: `${mode}-phone-${phone.normalizedNumber.slice(-6)}`,
      title: "Suspicious Phone Number in " + (mode === "email" ? "Email" : "Message"),
      description: `${phone.number} (${phone.country}) — ${phone.flags[0] || "Suspicious"}`,
      severity: sev,
      category: "Phone Fraud",
      ruleType: sev === "critical" || sev === "high" ? "block" : "warn",
      message: phone.flags.join(" · "),
    });
  }

  return { breachPoints, score: result.score };
}

export async function POST(req: NextRequest) {
  const startTime = Date.now();
  try {
    const ip = getClientIp(req);
    const rateLimit = checkRateLimit(ip, false);
    if (!rateLimit.allowed) {
      return NextResponse.json(
        { error: "Rate limit exceeded." },
        { status: 429 }
      );
    }

    const body = await req.json().catch(() => null);
    if (!body || typeof body.mode !== "string" || typeof body.input !== "string" || !body.input.trim()) {
      return NextResponse.json(
        { error: "Provide { mode: 'phone'|'sms'|'email', input: string }" },
        { status: 400 }
      );
    }

    const mode = body.mode as VaccineAnalyzeMode;
    if (!["phone", "sms", "email"].includes(mode)) {
      return NextResponse.json({ error: "mode must be 'phone', 'sms', or 'email'" }, { status: 400 });
    }

    const input: string = body.input.slice(0, 50_000);

    // Auth + quota check
    const authUser = await getUserFromRequest(req);
    if (authUser) {
      const quota = await canScan(authUser);
      if (!quota.allowed) {
        return NextResponse.json({ error: "Scan quota reached. Upgrade your plan." }, { status: 429 });
      }
    }

    let breachPoints: VaccineBreachPoint[] = [];
    let score = 0;

    if (mode === "phone") {
      ({ breachPoints, score } = analyzePhone(input));
    } else {
      ({ breachPoints, score } = analyzeText(input, mode));
    }

    const threatLevel = threatLevelFromScore(score);

    const summaryMap: Record<string, string> = {
      safe: "No significant threats detected.",
      low: "Minor risk indicators found — proceed with caution.",
      medium: "Moderate scam patterns detected — review before acting.",
      high: "High-risk manipulation tactics found — likely a scam.",
      critical: "Critical scam signals — do not engage.",
    };

    // Increment scan count
    if (authUser) {
      await incrementScanCount(authUser.id);
    }

    const response: VaccineAnalyzeResponse = {
      mode,
      input: input.slice(0, 200),
      threatScore: Math.round(score),
      threatLevel,
      breachPoints,
      summary: summaryMap[threatLevel],
      processingTimeMs: Date.now() - startTime,
    };

    return NextResponse.json(response, { status: 200 });
  } catch (err) {
    console.error("[/api/vaccine/analyze] Error:", err);
    return NextResponse.json({ error: "Analysis failed. Please try again." }, { status: 500 });
  }
}
