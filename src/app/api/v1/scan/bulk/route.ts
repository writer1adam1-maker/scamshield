// ============================================================================
// POST /api/v1/scan/bulk — Batch scan API (API key authenticated)
// ============================================================================
// Auth:    API key required (ss_live_... or ss_test_...)
// Free:    up to 10 items per request
// Pro:     up to 50 items per request
//
// Each batch request counts as 1 API key rate-limit unit regardless of size.
// Each item in the batch consumes 1 scan from the key's daily quota.
//
// Request body:
// {
//   items: Array<{
//     id?: string,           // optional client-side ID for correlation
//     type: "url" | "text",
//     content: string        // max 10,000 chars per item
//   }>
// }

import { NextRequest, NextResponse } from "next/server";
import { runVERIDICT } from "@/lib/algorithms/veridict-engine";
import { requireApiKey } from "@/lib/api-key-auth";
import type { AnalysisInput } from "@/lib/algorithms/types";

const API_VERSION = "1.0";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Authorization, X-API-Key, Content-Type",
};

export async function OPTIONS() {
  return new Response(null, { status: 204, headers: CORS_HEADERS });
}

const MAX_ITEMS: Record<"free" | "pro", number> = {
  free: 10,
  pro:  50,
};

interface BulkItem {
  id?: string;
  type: "url" | "text";
  content: string;
}

function buildInput(type: "url" | "text", content: string): AnalysisInput {
  if (type === "url") return { url: content, text: content };
  const urlMatch = content.match(/https?:\/\/[^\s]+/);
  return {
    text: content,
    url: urlMatch ? urlMatch[0] : undefined,
    smsBody: content.length < 500 ? content : undefined,
    emailBody: content.length >= 500 ? content : undefined,
  };
}

export async function POST(req: NextRequest) {
  const startTime = performance.now();

  // --- Auth + rate limit ---
  const auth = await requireApiKey(req);
  if (auth.error) {
    return NextResponse.json(auth.body, {
      status: auth.status,
      headers: { ...CORS_HEADERS, ...(auth.headers ?? {}) },
    });
  }
  const { keyInfo, rateLimit } = auth;
  const isPro = keyInfo.plan === "pro";
  const maxItems = MAX_ITEMS[keyInfo.plan];

  // --- Parse body ---
  const body = await req.json().catch(() => null);

  if (!body || !Array.isArray(body.items)) {
    return NextResponse.json(
      { error: "Request body must include an 'items' array" },
      { status: 400, headers: CORS_HEADERS }
    );
  }

  const items = body.items as BulkItem[];

  if (items.length === 0) {
    return NextResponse.json(
      { error: "'items' array cannot be empty" },
      { status: 400, headers: CORS_HEADERS }
    );
  }

  if (items.length > maxItems) {
    return NextResponse.json(
      {
        error: `Batch size ${items.length} exceeds the ${maxItems}-item limit for ${keyInfo.plan} API keys.`,
        limit: maxItems,
        upgrade: isPro ? null : "Upgrade to a Pro API key for up to 50 items per batch. See /pricing",
      },
      { status: 422, headers: CORS_HEADERS }
    );
  }

  // --- Validate all items upfront ---
  for (const [i, item] of items.entries()) {
    if (!["url", "text"].includes(item.type)) {
      return NextResponse.json(
        { error: `Item ${i}: 'type' must be "url" or "text"` },
        { status: 400, headers: CORS_HEADERS }
      );
    }
    if (typeof item.content !== "string" || item.content.trim().length === 0) {
      return NextResponse.json(
        { error: `Item ${i}: 'content' must be a non-empty string` },
        { status: 400, headers: CORS_HEADERS }
      );
    }
    if (item.content.length > 10_000) {
      return NextResponse.json(
        { error: `Item ${i}: 'content' exceeds 10,000 character limit` },
        { status: 400, headers: CORS_HEADERS }
      );
    }
  }

  // --- Run scans sequentially (avoid memory pressure on serverless) ---
  const results = [];
  for (const item of items) {
    try {
      const input = buildInput(item.type, item.content);
      const result = await runVERIDICT(input);

      results.push({
        id:             item.id ?? null,
        type:           item.type,
        contentPreview: item.content.substring(0, 80),
        score:          result.score,
        threatLevel:    result.threatLevel,
        category:       result.category,
        // Free: top 2 evidence items. Pro: top 5 + layer scores.
        topEvidence:    result.evidence.slice(0, isPro ? 5 : 2).map(e => ({
          finding:  e.finding,
          severity: e.severity,
        })),
        ...(isPro ? {
          layerScores:       result.layerScores,
          similarKnownScam:  result.similarKnownScam,
          processingTimeMs:  result.processingTimeMs,
        } : {}),
      });
    } catch {
      results.push({
        id:             item.id ?? null,
        type:           item.type,
        contentPreview: item.content.substring(0, 80),
        error:          "Analysis failed for this item",
      });
    }
  }

  const totalTime = Math.round((performance.now() - startTime) * 100) / 100;
  const completed = results.filter(r => !("error" in r)).length;

  return NextResponse.json(
    {
      apiVersion: API_VERSION,
      results,
      meta: {
        totalItems:          items.length,
        completedItems:      completed,
        failedItems:         items.length - completed,
        totalProcessingTimeMs: totalTime,
        plan:                keyInfo.plan,
        keyId:               keyInfo.keyId,
        rateLimitRemaining:  rateLimit.remaining,
        rateLimitLimit:      rateLimit.limit,
        rateLimitResetAt:    new Date(rateLimit.resetAt).toISOString(),
      },
    },
    {
      status: 200,
      headers: {
        ...CORS_HEADERS,
        "X-RateLimit-Plan":      keyInfo.plan,
        "X-RateLimit-Limit":     String(rateLimit.limit),
        "X-RateLimit-Remaining": String(rateLimit.remaining),
        "X-RateLimit-Reset":     String(rateLimit.resetAt),
        "X-API-Version":         API_VERSION,
      },
    }
  );
}

// GET — endpoint info
export async function GET() {
  return NextResponse.json({
    api:       "ScamShield Bulk Scan API",
    version:   API_VERSION,
    auth:      "API key required: Authorization: Bearer ss_live_YOUR_KEY",
    limits:    { free: "10 items/batch", pro: "50 items/batch" },
    rateLimit: { free: "100 req/day", pro: "10,000 req/day" },
    getKey:    "/settings",
  }, { headers: CORS_HEADERS });
}
