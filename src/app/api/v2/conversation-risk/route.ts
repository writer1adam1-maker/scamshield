// ============================================================================
// POST /api/v2/conversation-risk — B2B Conversation Risk API
// ============================================================================
// Combines Conversation Arc analysis + IP intelligence + profile metadata
// signals into a single combined risk score.
//
// SELL TO: Dating apps (Tinder/Bumble/Hinge), social platforms, banks
//
// Request body:
// {
//   conversation: string,          // raw conversation text (required)
//   user_ip?: string,              // submitting user's IP (optional)
//   profile?: {
//     account_age_days?: number,
//     profile_photo_count?: number,
//     messages_sent_today?: number,
//     conversation_count?: number,
//     has_verified_phone?: boolean,
//     platform?: string
//   }
// }

import { NextRequest, NextResponse } from "next/server";
import { analyzeConversationArc } from "@/lib/algorithms/conversation-arc";
import { analyzeIp } from "@/lib/ip-intelligence";
import { checkRateLimit } from "@/lib/rate-limit";
import { getClientIp } from "@/lib/utils";

// ---------------------------------------------------------------------------
// Profile risk scoring
// ---------------------------------------------------------------------------

interface ProfileInput {
  account_age_days?: number;
  profile_photo_count?: number;
  messages_sent_today?: number;
  conversation_count?: number;
  has_verified_phone?: boolean;
  platform?: string;
}

interface ProfileRiskResult {
  score: number;
  signals: { finding: string; severity: "low" | "medium" | "high" }[];
}

function scoreProfile(profile: ProfileInput): ProfileRiskResult {
  let score = 0;
  const signals: ProfileRiskResult["signals"] = [];

  if (typeof profile.account_age_days === "number") {
    if (profile.account_age_days < 1) {
      score += 30; signals.push({ finding: "Account created less than 24 hours ago", severity: "high" });
    } else if (profile.account_age_days < 7) {
      score += 22; signals.push({ finding: `Account only ${profile.account_age_days} day(s) old — newly created accounts are high-risk`, severity: "high" });
    } else if (profile.account_age_days < 30) {
      score += 12; signals.push({ finding: `Account ${profile.account_age_days} days old — recent account`, severity: "medium" });
    }
  }

  if (typeof profile.profile_photo_count === "number") {
    if (profile.profile_photo_count === 0) {
      score += 18; signals.push({ finding: "No profile photos — common in catfish/scam accounts", severity: "high" });
    } else if (profile.profile_photo_count === 1) {
      score += 8; signals.push({ finding: "Only 1 profile photo — limited verification signal", severity: "low" });
    }
  }

  if (typeof profile.messages_sent_today === "number" && profile.messages_sent_today > 30) {
    score += 15;
    signals.push({ finding: `${profile.messages_sent_today} messages sent today — unusually high activity suggests scripted operation`, severity: "medium" });
  }

  if (typeof profile.conversation_count === "number" && profile.conversation_count > 5) {
    score += 12;
    signals.push({ finding: `Running ${profile.conversation_count} simultaneous conversations — consistent with bulk scam scripting`, severity: "medium" });
  }

  if (profile.has_verified_phone === false) {
    score += 10;
    signals.push({ finding: "No verified phone number — bypasses account authenticity check", severity: "medium" });
  }

  return { score: Math.min(50, score), signals };
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

export async function POST(req: NextRequest) {
  const startTime = performance.now();

  try {
    const ip = getClientIp(req);
    const rateLimit = checkRateLimit(ip, false);

    if (!rateLimit.allowed) {
      return NextResponse.json(
        { error: "Rate limit exceeded.", remaining: rateLimit.remaining },
        { status: 429 },
      );
    }

    const body = await req.json().catch(() => null);

    if (!body || typeof body.conversation !== "string" || !body.conversation.trim()) {
      return NextResponse.json(
        { error: "Provide { conversation: string }. Optional: user_ip, profile." },
        { status: 400 },
      );
    }

    if (body.conversation.length > 100_000) {
      return NextResponse.json(
        { error: "Conversation too long. Max 100,000 characters." },
        { status: 400 },
      );
    }

    // Run conversation arc + IP analysis in parallel
    const userIp: string | null =
      typeof body.user_ip === "string" && body.user_ip.trim() ? body.user_ip.trim() : null;

    const [arcResult, ipResult] = await Promise.all([
      analyzeConversationArc(body.conversation),
      userIp ? analyzeIp(userIp) : Promise.resolve(null),
    ]);

    // Profile risk
    const profileResult: ProfileRiskResult = body.profile && typeof body.profile === "object"
      ? scoreProfile(body.profile as ProfileInput)
      : { score: 0, signals: [] };

    // Combined risk score
    // Weights: conversation arc 60%, IP intel 25%, profile 15%
    const conversationWeight = 0.60;
    const ipWeight           = 0.25;
    const profileWeight      = 0.15;

    const ipScore = ipResult ? Math.min(100, (ipResult.scoreBoost / 40) * 100) : 0;
    const profileScore = profileResult.score * 2; // profile returns 0-50, normalize to 0-100

    const combinedRisk = Math.min(100, Math.round(
      arcResult.overallRisk * conversationWeight +
      ipScore              * ipWeight +
      profileScore         * profileWeight,
    ));

    const threatLevel =
      combinedRisk >= 75 ? "CRITICAL" :
      combinedRisk >= 55 ? "HIGH" :
      combinedRisk >= 35 ? "MEDIUM" :
      combinedRisk >= 15 ? "LOW" : "SAFE";

    // Build response
    const processingTimeMs = Math.round(performance.now() - startTime);

    return NextResponse.json({
      // Combined output
      combinedRisk,
      threatLevel,
      recommendation:
        combinedRisk >= 75 ? "BLOCK or FLAG — immediate intervention required" :
        combinedRisk >= 55 ? "FLAG for review — multiple risk signals detected" :
        combinedRisk >= 35 ? "MONITOR — moderate risk signals present" :
        combinedRisk >= 15 ? "WATCH — low-level signals detected" :
        "ALLOW — no significant risk signals",

      // Component breakdown
      scores: {
        conversationArc: arcResult.overallRisk,
        ipIntelligence:  Math.round(ipScore),
        profileRisk:     profileResult.score,
      },
      weights: { conversationArc: 0.60, ipIntelligence: 0.25, profileRisk: 0.15 },

      // Arc details
      arc: {
        type:         arcResult.arcType,
        label:        arcResult.arcLabel,
        phasesDetected: arcResult.phases.filter(p => p.present).length,
        totalPhases:   6,
        criticalFindings: arcResult.criticalFindings,
        phases: arcResult.phases.map(p => ({
          phase: p.phase,
          label: p.label,
          score: p.score,
          present: p.present,
        })),
      },

      // IP intelligence
      ip: ipResult ? {
        address:         ipResult.ip,
        country:         ipResult.country,
        countryCode:     ipResult.countryCode,
        city:            ipResult.city,
        isp:             ipResult.isp,
        org:             ipResult.org,
        asn:             ipResult.asn,
        hostingCategory: ipResult.hostingCategory,
        isDatacenter:    ipResult.isDatacenter,
        isVpnOrProxy:    ipResult.isVpnOrProxy,
        countryRiskLevel: ipResult.countryRiskLevel,
        flags:           ipResult.flags,
      } : null,

      // Profile signals
      profileSignals: profileResult.signals,

      // Recommended actions
      recommendedActions: arcResult.recommendedActions,

      processingTimeMs,
    }, {
      status: 200,
      headers: {
        "X-RateLimit-Remaining": String(rateLimit.remaining),
        "X-Processing-Time": `${processingTimeMs}ms`,
      },
    });

  } catch (err) {
    console.error("[/api/v2/conversation-risk] Error:", err);
    return NextResponse.json({ error: "Internal server error." }, { status: 500 });
  }
}
