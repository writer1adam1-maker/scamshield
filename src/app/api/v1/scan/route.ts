// ============================================================================
// POST /api/v1/scan — Public REST API with API key authentication
// Enables third-party integration (browser extensions, apps, B2B)
// Auth: Bearer token in Authorization header OR X-API-Key header
// Rate limit: 100 req/day (free key), 10,000 req/day (pro key)
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { runVERIDICT } from "@/lib/algorithms/veridict-engine";
import { requireApiKey, extractApiKey } from "@/lib/api-key-auth";
import type { AnalysisInput } from "@/lib/algorithms/types";

const API_VERSION = "1.0";

// Anonymous (no API key) rate limit: 20 scans/day per IP
const anonLimits = new Map<string, { count: number; resetAt: number }>();
const ANON_DAILY_LIMIT = 20;

function buildAnalysisInput(type: string, content: string): AnalysisInput {
  if (type === "url") return { url: content, text: content };
  const urlMatch = content.match(/https?:\/\/[^\s]+/);
  return {
    text: content,
    url: urlMatch ? urlMatch[0] : undefined,
    smsBody: content.length < 500 ? content : undefined,
    emailBody: content.length >= 500 ? content : undefined,
  };
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

// CORS headers for browser extension and third-party API consumers
const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, X-API-Key, Content-Type",
};

// OPTIONS preflight — required for browser extension CORS requests
export async function OPTIONS() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

export async function POST(req: NextRequest) {
  const startTime = performance.now();

  // --- Check if API key is provided ---
  const hasKey = !!extractApiKey(req);
  let keyInfo: { keyId: string; plan: "free" | "pro"; valid: boolean } = { keyId: "anon", plan: "free", valid: true };
  let rateLimitRemaining = 0;
  let rateLimitLimit = ANON_DAILY_LIMIT;

  if (hasKey) {
    // Authenticated path — full rate limits
    const auth = await requireApiKey(req);
    if (auth.error) {
      return NextResponse.json(auth.body, { status: auth.status, headers: { ...CORS_HEADERS, ...auth.headers } });
    }
    keyInfo = auth.keyInfo;
    rateLimitRemaining = auth.rateLimit.remaining;
    rateLimitLimit = auth.rateLimit.limit;
  } else {
    // Anonymous path — 20 scans/day per IP (extension without key)
    const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
    const now = Date.now();
    const entry = anonLimits.get(ip);
    if (!entry || now > entry.resetAt) {
      anonLimits.set(ip, { count: 1, resetAt: now + 24 * 60 * 60 * 1000 });
      rateLimitRemaining = ANON_DAILY_LIMIT - 1;
    } else if (entry.count >= ANON_DAILY_LIMIT) {
      return NextResponse.json({
        error: "Daily limit reached (20 free scans). Add an API key in extension settings for 100/day, or upgrade to Pro for 10,000/day.",
        limit: ANON_DAILY_LIMIT,
        remaining: 0,
        upgrade: "https://scamshieldy.com/pricing",
      }, { status: 429, headers: CORS_HEADERS });
    } else {
      entry.count++;
      rateLimitRemaining = ANON_DAILY_LIMIT - entry.count;
    }
  }

  // --- Parse body ---
  const body = await req.json().catch(() => null);
  if (!body) {
    return NextResponse.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const { type, content, options } = body as {
    type?: string;
    content?: string;
    options?: { includeLayerDetails?: boolean; includeEvidence?: boolean };
  };

  if (!type || !["url", "text"].includes(type)) {
    return NextResponse.json(
      { error: "type must be 'url' or 'text'" },
      { status: 400 }
    );
  }
  if (!content || typeof content !== "string" || content.trim().length === 0) {
    return NextResponse.json(
      { error: "content must be a non-empty string" },
      { status: 400 }
    );
  }
  if (content.length > 10_000) {
    return NextResponse.json(
      { error: "content exceeds 10,000 character limit" },
      { status: 400 }
    );
  }

  // --- Scan ---
  const analysisInput = buildAnalysisInput(type, content);
  const result = await runVERIDICT(analysisInput);

  const totalTime = Math.round((performance.now() - startTime) * 100) / 100;

  // Build response — Pro gets full details, free gets summary
  const response: Record<string, unknown> = {
    apiVersion: API_VERSION,
    scan: {
      score: result.score,
      threatLevel: result.threatLevel,
      category: result.category,
      similarKnownScam: result.similarKnownScam,
      processingTimeMs: totalTime,
    },
  };

  if (keyInfo.plan === "pro" || options?.includeEvidence) {
    response.evidence = result.evidence;
    response.layerScores = result.layerScores;
    response.confidenceInterval = result.confidenceInterval;
    response.financialRisk = result.financialRisk ?? null;
    response.linguisticDeception = result.linguisticDeception
      ? {
          score: result.linguisticDeception.score,
          tacticCount: result.linguisticDeception.deceptionTactics.length,
          flags: result.linguisticDeception.flags,
        }
      : null;
    response.multilingualDetection = result.multilingualDetection
      ? {
          detected: true,
          language: result.multilingualDetection.dominantLanguage,
          matchCount: result.multilingualDetection.matches.length,
        }
      : null;
    response.phoneAnalysis = result.phoneAnalysis
      ? {
          detected: true,
          highestRisk: result.phoneAnalysis.highestRisk,
          flags: result.phoneAnalysis.flags,
        }
      : null;
  }

  if (options?.includeLayerDetails && keyInfo.plan === "pro") {
    response.layerDetails = {
      fisher: { score: result.layerDetails.fisher.score, earlyStop: result.layerDetails.fisher.earlyStopTriggered },
      conservation: { score: result.layerDetails.conservation.score },
      cascadeBreaker: { score: result.layerDetails.cascadeBreaker.score },
      immune: { score: result.layerDetails.immune.score, matchedCount: result.layerDetails.immune.matchedAntibodies.length },
    };
  }

  response.meta = {
    keyId: keyInfo.keyId,
    plan: keyInfo.plan,
    rateLimitRemaining,
    rateLimitLimit,
  };

  return NextResponse.json(response, {
    status: 200,
    headers: {
      ...CORS_HEADERS,
      "X-RateLimit-Plan": keyInfo.plan,
      "X-RateLimit-Limit": String(rateLimitLimit),
      "X-RateLimit-Remaining": String(rateLimitRemaining),
      "X-API-Version": API_VERSION,
    },
  });
}

// --- GET: API info / health ---
export async function GET() {
  return NextResponse.json({
    api: "ScamShieldy Detection API",
    version: API_VERSION,
    endpoints: {
      "POST /api/v1/scan": "Scan a URL or text for scam indicators",
      "POST /api/scan/bulk": "Batch scan up to 50 items",
    },
    auth: "Include your API key as: Authorization: Bearer ss_live_YOUR_KEY",
    getKey: "/settings",
    docs: "https://scamshieldy.com/api-docs",
  });
}
