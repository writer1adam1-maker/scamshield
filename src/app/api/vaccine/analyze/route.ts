// ============================================================================
// POST /api/vaccine/analyze
// Vaccine-specific analysis for phone, SMS, and email content.
// Unlike the normal scan (which only scores threat), the vaccine engine:
//   1. Runs pattern engine (Aho-Corasick multi-pattern matching)
//   2. Runs linguistic deception detection
//   3. Generates a Threat DNA fingerprint (12-dimension genetic signature)
//   4. Builds an immunity profile (decay model, antibodies, booster schedule)
//   5. Classifies mutation type (NOVEL/VARIANT/CLONE/EVOLVED/SYNTHETIC)
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { analyzePhoneNumbers } from "@/lib/algorithms/phone-analyzer";
import { detectLinguisticDeception } from "@/lib/algorithms/linguistic-deception";
import { scanPatterns, scanPatternMaxWeights } from "@/lib/algorithms/pattern-engine";
import { generateThreatDNA, dnaStrandLabel } from "@/lib/vaccine/threat-dna";
import { buildImmunityProfile, tierLabel } from "@/lib/vaccine/immunity-model";
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

export interface VaccineDNAResult {
  hex: string;
  dimensions: Array<{ name: string; intensity: number; label: string }>;
  dominantStrand: string;
  mutationClass: string;
  mutationLabel: string;
}

export interface VaccineImmunityResult {
  strength: number;
  peakStrength: number;
  tier: string;
  tierLabel: string;
  boosterDueAt: number;
  exposureCount: number;
  decayRateLabel: string;
  antibodies: Array<{ dimension: string; strength: number; targetLabel: string }>;
}

export interface VaccinePatternHit {
  group: string;
  maxWeight: number;
  severity: string;
}

export interface VaccineAnalyzeResponse {
  mode: VaccineAnalyzeMode;
  input: string;
  threatScore: number;
  threatLevel: "safe" | "low" | "medium" | "high" | "critical";
  breachPoints: VaccineBreachPoint[];
  summary: string;
  processingTimeMs: number;
  // Vaccine-specific fields (absent in normal scan)
  dna: VaccineDNAResult;
  immunity: VaccineImmunityResult;
  patternHits: VaccinePatternHit[];
  totalPatternMatches: number;
  uniqueGroupsHit: number;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Pattern-engine layer (new — not in original analyze route)
// Converts Aho-Corasick hits into breach points
// ---------------------------------------------------------------------------
function extractPatternBreachPoints(text: string): {
  breachPoints: VaccineBreachPoint[];
  patternHits: VaccinePatternHit[];
  patternScore: number;
  totalMatches: number;
  uniqueGroups: number;
} {
  const matches = scanPatterns(text);
  const maxWeights = scanPatternMaxWeights(text);

  const breachPoints: VaccineBreachPoint[] = [];
  const patternHits: VaccinePatternHit[] = [];
  const seenGroups = new Set<string>();

  // Aggregate by group — one breach card per group
  const groupBest = new Map<string, { weight: number; severity: string; texts: string[] }>();
  for (const m of matches) {
    const existing = groupBest.get(m.group);
    const mSev = m.severity ?? "medium";
    if (!existing || m.weight > existing.weight) {
      groupBest.set(m.group, {
        weight: m.weight,
        severity: mSev,
        texts: existing?.texts ?? [],
      });
    }
    groupBest.get(m.group)!.texts.push(m.text);
    seenGroups.add(m.group);
  }

  for (const [group, best] of groupBest) {
    if (best.weight < 8) continue; // skip very low weight patterns

    const sevMap: Record<string, VaccineBreachPoint["severity"]> = {
      critical: "critical", high: "high", medium: "medium", low: "low",
    };
    const severity = sevMap[best.severity] ?? "medium";
    const ruleType = severity === "critical" ? "block"
      : severity === "high"     ? "warn"
      : severity === "medium"   ? "sandbox"
      : "monitor";

    const topPatterns = [...new Set(best.texts)].slice(0, 3).join(", ");
    const groupLabel = group.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());

    breachPoints.push({
      id: `pattern-${group}`,
      title: `${groupLabel} Pattern Cluster`,
      description: `Pattern engine matched ${best.texts.length} phrase(s) in this category. Top matches: "${topPatterns}"`,
      severity,
      category: groupLabel,
      ruleType,
      message: `Weight ${best.weight} · ${best.texts.length} match${best.texts.length !== 1 ? "es" : ""}`,
    });

    patternHits.push({
      group,
      maxWeight: maxWeights[group] ?? best.weight,
      severity: best.severity,
    });
  }

  // Score from pattern engine: weighted sum, capped at 100
  const patternScore = Math.min(100,
    Array.from(groupBest.values()).reduce((s, b) => s + b.weight, 0) * 1.5
  );

  return {
    breachPoints,
    patternHits,
    patternScore,
    totalMatches: matches.length,
    uniqueGroups: seenGroups.size,
  };
}

// ---------------------------------------------------------------------------
// Phone analysis
// ---------------------------------------------------------------------------
function analyzePhone(text: string): { breachPoints: VaccineBreachPoint[]; score: number } {
  const result = analyzePhoneNumbers(text);
  const breachPoints: VaccineBreachPoint[] = [];

  for (const phone of result.phones) {
    if (phone.scamAssociationScore < 0.1) continue;
    const sev = severityFromScore(phone.scamAssociationScore);
    breachPoints.push({
      id: `phone-${phone.normalizedNumber.slice(-6)}`,
      title: phone.isPremiumRate ? "Premium-Rate Number Detected"
        : phone.isSuspiciousAreaCode ? "High-Risk Area Code"
        : "Suspicious Phone Number",
      description: `${phone.number} (${phone.country}) — ${phone.flags[0] || "Suspicious phone number"}`,
      severity: sev,
      category: "Phone Fraud",
      ruleType: sev === "critical" || sev === "high" ? "block" : "warn",
      message: phone.flags.join(" · "),
    });
  }

  return { breachPoints, score: result.highestRisk * 100 };
}

// ---------------------------------------------------------------------------
// Text analysis (SMS / Email) — combines linguistic + pattern engine
// ---------------------------------------------------------------------------
function analyzeText(text: string, mode: "sms" | "email"): {
  breachPoints: VaccineBreachPoint[];
  score: number;
  linguisticResult: ReturnType<typeof detectLinguisticDeception>;
  patternData: ReturnType<typeof extractPatternBreachPoints>;
} {
  const linguisticResult = detectLinguisticDeception(text);
  const patternData = extractPatternBreachPoints(text);

  const breachPoints: VaccineBreachPoint[] = [];
  const seen = new Set<string>();

  // Linguistic deception tactics
  for (const tactic of linguisticResult.deceptionTactics) {
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
      description: `Deceptive language: "${tactic.evidence.substring(0, 80)}${tactic.evidence.length > 80 ? "…" : ""}"`,
      severity: sev,
      category: categoryLabel,
      ruleType: sev === "critical" || sev === "high" ? "block" : sev === "medium" ? "warn" : "monitor",
      message: `${tactic.tacticName} — ${categoryLabel}`,
    });
  }

  // Pattern engine hits (deduped with linguistic)
  for (const bp of patternData.breachPoints) {
    if (!seen.has(bp.id)) {
      seen.add(bp.id);
      breachPoints.push(bp);
    }
  }

  // Phone numbers embedded in text
  const phoneResult = analyzePhoneNumbers(text);
  for (const phone of phoneResult.phones) {
    if (phone.scamAssociationScore < 0.25) continue;
    const sev = severityFromScore(phone.scamAssociationScore);
    const id = `${mode}-phone-${phone.normalizedNumber.slice(-6)}`;
    if (!seen.has(id)) {
      seen.add(id);
      breachPoints.push({
        id,
        title: "Suspicious Phone Number in " + (mode === "email" ? "Email" : "Message"),
        description: `${phone.number} (${phone.country}) — ${phone.flags[0] || "Suspicious"}`,
        severity: sev,
        category: "Phone Fraud",
        ruleType: sev === "critical" || sev === "high" ? "block" : "warn",
        message: phone.flags.join(" · "),
      });
    }
  }

  // Combined score: 60% linguistic, 40% pattern engine
  const score = linguisticResult.score * 0.6 + patternData.patternScore * 0.4;

  return { breachPoints, score, linguisticResult, patternData };
}

// ---------------------------------------------------------------------------
// POST handler
// ---------------------------------------------------------------------------
export async function POST(req: NextRequest) {
  const startTime = Date.now();
  try {
    const ip = getClientIp(req);
    const rateLimit = checkRateLimit(ip, false);
    if (!rateLimit.allowed) {
      return NextResponse.json({ error: "Rate limit exceeded." }, { status: 429 });
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

    const authUser = await getUserFromRequest(req);
    if (authUser) {
      const quota = await canScan(authUser);
      if (!quota.allowed) {
        return NextResponse.json({ error: "Scan quota reached. Upgrade your plan." }, { status: 429 });
      }
    }

    // --- Run analysis ---
    let breachPoints: VaccineBreachPoint[] = [];
    let score = 0;
    let linguisticResult = detectLinguisticDeception(""); // empty fallback
    let patternData = extractPatternBreachPoints("");

    if (mode === "phone") {
      ({ breachPoints, score } = analyzePhone(input));
      linguisticResult = detectLinguisticDeception(input);
      patternData = extractPatternBreachPoints(input);
    } else {
      const r = analyzeText(input, mode);
      breachPoints = r.breachPoints;
      score = r.score;
      linguisticResult = r.linguisticResult;
      patternData = r.patternData;
    }

    const threatLevel = threatLevelFromScore(score);

    // --- Generate Threat DNA ---
    const rawDna = generateThreatDNA(input, linguisticResult);
    const dna: VaccineDNAResult = {
      hex: rawDna.hex,
      dimensions: rawDna.dimensions,
      dominantStrand: rawDna.dominantStrand,
      mutationClass: rawDna.mutation,
      mutationLabel: dnaStrandLabel(rawDna.mutation),
    };

    // --- Build Immunity Profile ---
    const rawImmunity = buildImmunityProfile(
      threatLevel,
      score,
      rawDna.hex,
      rawDna.dimensions
    );
    const immunity: VaccineImmunityResult = {
      strength: rawImmunity.strength,
      peakStrength: rawImmunity.peakStrength,
      tier: rawImmunity.tier,
      tierLabel: tierLabel(rawImmunity.tier),
      boosterDueAt: rawImmunity.boosterDueAt,
      exposureCount: rawImmunity.exposureCount,
      decayRateLabel: rawImmunity.decayRateLabel,
      antibodies: rawImmunity.antibodies,
    };

    const summaryMap: Record<string, string> = {
      safe:     "No significant threats detected. Minimal immunity required.",
      low:      "Minor indicators found. Low-level immunity has been generated.",
      medium:   "Moderate scam patterns detected. Partial immunity built — review before acting.",
      high:     "High-risk manipulation tactics found. Strong immunity generated. Likely a scam.",
      critical: "Critical scam signals. Maximum immunity deployed. Do not engage.",
    };

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
      dna,
      immunity,
      patternHits: patternData.patternHits,
      totalPatternMatches: patternData.totalMatches,
      uniqueGroupsHit: patternData.uniqueGroups,
    };

    return NextResponse.json(response, { status: 200 });
  } catch (err) {
    console.error("[/api/vaccine/analyze] Error:", err);
    return NextResponse.json({ error: "Analysis failed. Please try again." }, { status: 500 });
  }
}
