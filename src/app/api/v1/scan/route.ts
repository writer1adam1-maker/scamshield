// ============================================================================
// POST /api/v1/scan — Public REST API with API key authentication
// Enables third-party integration (browser extensions, apps, B2B)
// Auth: Bearer token in Authorization header OR X-API-Key header
// Rate limit: 100 req/day (free key), 10,000 req/day (pro key)
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { runVERIDICT } from "@/lib/algorithms/veridict-engine";
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
}

function validateApiKey(key: string): ApiKeyInfo {
  // Format: ss_live_XXXX... or ss_test_XXXX...
  if (!key || typeof key !== "string") {
    return { keyId: "", plan: "free", valid: false, reason: "Missing API key" };
  }
  if (!key.startsWith("ss_live_") && !key.startsWith("ss_test_")) {
    return { keyId: "", plan: "free", valid: false, reason: "Invalid API key format. Expected ss_live_... or ss_test_..." };
  }
  if (key.length < 24) {
    return { keyId: "", plan: "free", valid: false, reason: "API key too short" };
  }
  // TODO: query Supabase api_keys table for real validation
  const isPro = key.includes("_pro_") || key.startsWith("ss_live_");
  return {
    keyId: key.substring(0, 16) + "...",
    plan: isPro ? "pro" : "free",
    valid: true,
  };
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

  const keyInfo = validateApiKey(rawKey);
  if (!keyInfo.valid) {
    return NextResponse.json(
      { error: keyInfo.reason ?? "Invalid API key" },
      { status: 401 }
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
    rateLimitRemaining: keyInfo.plan === "pro" ? 9999 : 99, // TODO: real counter from Redis
  };

  return NextResponse.json(response, {
    status: 200,
    headers: {
      "X-RateLimit-Plan": keyInfo.plan,
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
