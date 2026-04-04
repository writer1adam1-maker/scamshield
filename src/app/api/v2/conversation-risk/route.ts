// ============================================================================
// POST /api/v2/conversation-risk — B2B Conversation Risk API
// ============================================================================
// Auth: API key required (ss_live_... or ss_test_...)
// Free key:  conversation arc analysis only (no IP intel, no profile scoring)
// Pro key:   full analysis (arc + IP intel + profile metadata signals)
//
// SELL TO: Dating apps (Tinder/Bumble/Hinge), social platforms, banks
//
// Request body:
// {
//   conversation: string,          // raw conversation text (required)
//   user_ip?: string,              // submitting user's IP (Pro only)
//   profile?: {                    // profile metadata signals (Pro only)
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
import { requireApiKey } from "@/lib/api-key-auth";

// CORS headers for B2B clients (restrict to https origins in production)
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, X-API-Key, Content-Type",
};

export async function OPTIONS() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

// ---------------------------------------------------------------------------
// Profile risk scoring (Pro only)
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
    // --- Auth + rate limit (tracks usage automatically) ---
    const auth = await requireApiKey(req);
    if (auth.error) {
      return NextResponse.json(auth.body, {
        status: auth.status,
        headers: { ...CORS_HEADERS, ...(auth.headers ?? {}) },
      });
    }
    const { keyInfo, rateLimit } = auth;
    const isPro = keyInfo.plan === "pro";

    // --- Parse body ---
    const body = await req.json().catch(() => null);

    if (!body || typeof body.conversation !== "string" || !body.conversation.trim()) {
      return NextResponse.json(
        { error: "Provide { conversation: string }. Optional (Pro): user_ip, profile." },
        { status: 400, headers: CORS_HEADERS },
      );
    }

    if (body.conversation.length > 100_000) {
      return NextResponse.json(
        { error: "Conversation too long. Max 100,000 characters." },
        { status: 400, headers: CORS_HEADERS },
      );
    }

    // --- Run analysis ---
    // Pro: full triple analysis (arc + IP + profile)
    // Free: conversation arc only
    const IPV4_RE = /^(\d{1,3}\.){3}\d{1,3}$/;
    const IPV6_RE = /^[0-9a-f:]+$/i;
    const rawUserIp = typeof body.user_ip === "string" ? body.user_ip.trim() : "";
    const userIp: string | null = isPro && rawUserIp && (IPV4_RE.test(rawUserIp) || IPV6_RE.test(rawUserIp))
      ? rawUserIp
      : null;

    const [arcResult, ipResult] = await Promise.all([
      analyzeConversationArc(body.conversation),
      isPro && userIp ? analyzeIp(userIp) : Promise.resolve(null),
    ]);

    const profileResult: ProfileRiskResult = isPro && body.profile && typeof body.profile === "object"
      ? scoreProfile(body.profile as ProfileInput)
      : { score: 0, signals: [] };

    // --- Score combination ---
    const ipScore = ipResult ? Math.min(100, (ipResult.scoreBoost / 40) * 100) : 0;
    const profileScore = profileResult.score * 2;

    // Free: arc only. Pro: weighted combination.
    const combinedRisk = isPro
      ? Math.min(100, Math.round(
          arcResult.overallRisk * 0.60 +
          ipScore              * 0.25 +
          profileScore         * 0.15,
        ))
      : Math.round(arcResult.overallRisk);

    const threatLevel =
      combinedRisk >= 75 ? "CRITICAL" :
      combinedRisk >= 55 ? "HIGH" :
      combinedRisk >= 35 ? "MEDIUM" :
      combinedRisk >= 15 ? "LOW" : "SAFE";

    const processingTimeMs = Math.round(performance.now() - startTime);

    // --- Response (Pro gets full breakdown, Free gets arc summary) ---
    const response: Record<string, unknown> = {
      combinedRisk,
      threatLevel,
      recommendation:
        combinedRisk >= 75 ? "BLOCK or FLAG — immediate intervention required" :
        combinedRisk >= 55 ? "FLAG for review — multiple risk signals detected" :
        combinedRisk >= 35 ? "MONITOR — moderate risk signals present" :
        combinedRisk >= 15 ? "WATCH — low-level signals detected" :
        "ALLOW — no significant risk signals",
      arc: {
        type:             arcResult.arcType,
        label:            arcResult.arcLabel,
        overallRisk:      arcResult.overallRisk,
        phasesDetected:   arcResult.phases.filter(p => p.present).length,
        totalPhases:      6,
        criticalFindings: arcResult.criticalFindings,
        ...(isPro ? {
          phases: arcResult.phases.map(p => ({
            phase:   p.phase,
            label:   p.label,
            score:   p.score,
            present: p.present,
          })),
          recommendedActions: arcResult.recommendedActions,
        } : {}),
      },
      meta: {
        plan:                keyInfo.plan,
        keyId:               keyInfo.keyId,
        rateLimitRemaining:  rateLimit.remaining,
        rateLimitLimit:      rateLimit.limit,
        rateLimitResetAt:    new Date(rateLimit.resetAt).toISOString(),
        processingTimeMs,
        ...(isPro ? {} : {
          upgrade: "Upgrade to a Pro API key for IP intelligence, profile risk scoring, and full phase breakdown. See /pricing",
        }),
      },
    };

    if (isPro) {
      response.scores = {
        conversationArc: arcResult.overallRisk,
        ipIntelligence:  Math.round(ipScore),
        profileRisk:     profileResult.score,
      };
      response.weights = { conversationArc: 0.60, ipIntelligence: 0.25, profileRisk: 0.15 };
      response.ip = ipResult ? {
        address:          ipResult.ip,
        country:          ipResult.country,
        countryCode:      ipResult.countryCode,
        city:             ipResult.city,
        isp:              ipResult.isp,
        org:              ipResult.org,
        asn:              ipResult.asn,
        hostingCategory:  ipResult.hostingCategory,
        isDatacenter:     ipResult.isDatacenter,
        isVpnOrProxy:     ipResult.isVpnOrProxy,
        countryRiskLevel: ipResult.countryRiskLevel,
        flags:            ipResult.flags,
      } : null;
      response.profileSignals = profileResult.signals;
    }

    return NextResponse.json(response, {
      status: 200,
      headers: {
        ...CORS_HEADERS,
        "X-RateLimit-Plan":      keyInfo.plan,
        "X-RateLimit-Limit":     String(rateLimit.limit),
        "X-RateLimit-Remaining": String(rateLimit.remaining),
        "X-RateLimit-Reset":     String(rateLimit.resetAt),
        "X-Processing-Time":     `${processingTimeMs}ms`,
      },
    });

  } catch (err) {
    console.error("[/api/v2/conversation-risk] Error:", err);
    return NextResponse.json({ error: "Internal server error." }, { status: 500, headers: CORS_HEADERS });
  }
}

// GET — API info
export async function GET() {
  return NextResponse.json({
    api: "ScamShield Conversation Risk API",
    version: "2.0",
    auth: "API key required: Authorization: Bearer ss_live_YOUR_KEY",
    tiers: {
      free:  "Conversation arc analysis only — 100 req/day",
      pro:   "Full analysis: arc + IP intel + profile metadata — 10,000 req/day",
    },
    getKey: "/settings",
    docs:   "https://scamshieldy.com/api-docs",
  }, { headers: CORS_HEADERS });
}
