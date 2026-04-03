// ============================================================================
// POST /api/v1/scan — Public REST API with API key authentication
// Enables third-party integration (browser extensions, apps, B2B)
// Auth: Bearer token in Authorization header OR X-API-Key header
// Rate limit: 100 req/day (free key), 10,000 req/day (pro key)
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { runVERIDICT } from "@/lib/algorithms/veridict-engine";
import { createServiceRoleClient } from "@/lib/supabase/client";
import { checkApiKeyRateLimit } from "@/lib/api-key-rate-limit";
import type { AnalysisInput } from "@/lib/algorithms/types";

const API_VERSION = "1.0";

// ---------------------------------------------------------------------------
// API key validation
// In production: look up key in Supabase api_keys table, check rate limit,
// return the associated plan tier. Currently validates format only.
// ---------------------------------------------------------------------------

interface ApiKeyInfo {
  keyId: string;
  plan: "free" | "pro";
  valid: boolean;
  reason?: string;
  revokedAt?: string | null;
}

async function validateApiKey(key: string): Promise<ApiKeyInfo> {
  // Format validation
  if (!key || typeof key !== "string") {
    return { keyId: "", plan: "free", valid: false, reason: "Missing API key" };
  }
  if (!key.startsWith("ss_live_") && !key.startsWith("ss_test_")) {
    return { keyId: "", plan: "free", valid: false, reason: "Invalid API key format. Expected ss_live_... or ss_test_..." };
  }
  if (key.length < 24) {
    return { keyId: "", plan: "free", valid: false, reason: "API key too short" };
  }

  try {
    const db = createServiceRoleClient();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data } = await (db as any)
      .from("api_keys")
      .select("key_prefix, key_hash, plan, revoked_at")
      .eq("key_prefix", key.substring(0, 16))
      .single();

    if (!data) {
      return { keyId: key.substring(0, 16) + "...", plan: "free", valid: false, reason: "API key not found" };
    }

    if (data.revoked_at) {
      return {
        keyId: key.substring(0, 16) + "...",
        plan: "free",
        valid: false,
        reason: "API key has been revoked",
        revokedAt: data.revoked_at,
      };
    }

    // In production, verify key_hash using bcrypt.compare()
    // For now, just verify prefix match (real security requires bcrypt)
    return {
      keyId: key.substring(0, 16) + "...",
      plan: (data.plan as "free" | "pro") || "free",
      valid: true,
    };
  } catch {
    // Graceful fallback if api_keys table doesn't exist yet
    console.warn("[API v1] api_keys table lookup failed, rejecting key");
    return {
      keyId: key.substring(0, 16) + "...",
      plan: "free",
      valid: false,
      reason: "API key validation unavailable",
    };
  }
}

function extractApiKey(req: NextRequest): string | null {
  const auth = req.headers.get("authorization");
  if (auth?.startsWith("Bearer ")) return auth.slice(7);
  return req.headers.get("x-api-key");
}

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

export async function POST(req: NextRequest) {
  const startTime = performance.now();

  // --- Auth ---
  const rawKey = extractApiKey(req);
  if (!rawKey) {
    return NextResponse.json(
      {
        error: "API key required",
        docs: "Include your key as: Authorization: Bearer ss_live_YOUR_KEY or X-API-Key: ss_live_YOUR_KEY",
        getKey: "/settings",
      },
      { status: 401 }
    );
  }

  const keyInfo = await validateApiKey(rawKey);
  if (!keyInfo.valid) {
    return NextResponse.json(
      { error: keyInfo.reason ?? "Invalid API key" },
      { status: 401 }
    );
  }

  // --- Rate limiting ---
  const rateLimit = checkApiKeyRateLimit(keyInfo.keyId, keyInfo.plan);
  if (!rateLimit.allowed) {
    return NextResponse.json(
      {
        error: "API rate limit exceeded",
        plan: keyInfo.plan,
        limit: rateLimit.limit,
        remaining: 0,
        resetAt: new Date(rateLimit.resetAt).toISOString(),
      },
      {
        status: 429,
        headers: {
          "X-RateLimit-Limit": String(rateLimit.limit),
          "X-RateLimit-Remaining": "0",
          "X-RateLimit-Reset": String(rateLimit.resetAt),
          "Retry-After": String(Math.ceil((rateLimit.resetAt - Date.now()) / 1000)),
        },
      }
    );
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
    rateLimitRemaining: rateLimit.remaining,
    rateLimitLimit: rateLimit.limit,
    rateLimitResetAt: new Date(rateLimit.resetAt).toISOString(),
  };

  return NextResponse.json(response, {
    status: 200,
    headers: {
      "X-RateLimit-Plan": keyInfo.plan,
      "X-RateLimit-Limit": String(rateLimit.limit),
      "X-RateLimit-Remaining": String(rateLimit.remaining),
      "X-RateLimit-Reset": String(rateLimit.resetAt),
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
