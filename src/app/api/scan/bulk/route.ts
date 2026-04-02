// ============================================================================
// POST /api/scan/bulk — Batch scan up to 50 URLs/texts at once
// Pro feature: requires authenticated session
// Body: { items: Array<{ type: "url"|"text", content: string, id?: string }> }
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { runVERIDICT } from "@/lib/algorithms/veridict-engine";
import { getClientIp } from "@/lib/utils";
import type { AnalysisInput } from "@/lib/algorithms/types";

const MAX_ITEMS_FREE = 5;
const MAX_ITEMS_PRO = 50;

interface BulkScanItem {
  id?: string;
  type: "url" | "text";
  content: string;
}

interface BulkScanRequest {
  items: BulkScanItem[];
}

function buildAnalysisInput(type: "url" | "text", content: string): AnalysisInput {
  if (type === "url") {
    return { url: content, text: content };
  }
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

  try {
    const body = await req.json().catch(() => null);

    if (!body || !Array.isArray(body.items)) {
      return NextResponse.json(
        { error: "Request body must include an 'items' array" },
        { status: 400 }
      );
    }

    const { items } = body as BulkScanRequest;

    // TODO: integrate Supabase auth — isPro from session
    const isPro = false;
    const maxItems = isPro ? MAX_ITEMS_PRO : MAX_ITEMS_FREE;

    if (items.length === 0) {
      return NextResponse.json({ error: "items array cannot be empty" }, { status: 400 });
    }

    if (items.length > maxItems) {
      return NextResponse.json(
        {
          error: `Batch size ${items.length} exceeds limit of ${maxItems} for ${isPro ? "Pro" : "Free"} plan`,
          limit: maxItems,
          upgradeUrl: "/pricing",
        },
        { status: 422 }
      );
    }

    // Validate all items first
    for (const [i, item] of items.entries()) {
      if (!["url", "text"].includes(item.type)) {
        return NextResponse.json(
          { error: `Item ${i}: type must be "url" or "text"` },
          { status: 400 }
        );
      }
      if (typeof item.content !== "string" || item.content.trim().length === 0) {
        return NextResponse.json(
          { error: `Item ${i}: content must be a non-empty string` },
          { status: 400 }
        );
      }
      if (item.content.length > 10_000) {
        return NextResponse.json(
          { error: `Item ${i}: content exceeds 10,000 character limit` },
          { status: 400 }
        );
      }
    }

    const ip = getClientIp(req);

    // Run scans sequentially to avoid memory pressure on serverless
    const results = [];
    for (const item of items) {
      try {
        const analysisInput = buildAnalysisInput(item.type, item.content);
        const result = await runVERIDICT(analysisInput);
        results.push({
          id: item.id ?? null,
          type: item.type,
          contentPreview: item.content.substring(0, 80),
          score: result.score,
          threatLevel: result.threatLevel,
          category: result.category,
          topEvidence: result.evidence.slice(0, 3).map((e) => e.finding),
          processingTimeMs: result.processingTimeMs,
        });
      } catch {
        results.push({
          id: item.id ?? null,
          type: item.type,
          contentPreview: item.content.substring(0, 80),
          error: "Analysis failed for this item",
        });
      }
    }

    const totalTime = Math.round((performance.now() - startTime) * 100) / 100;

    return NextResponse.json(
      {
        results,
        meta: {
          totalItems: items.length,
          completedItems: results.filter((r) => !("error" in r)).length,
          failedItems: results.filter((r) => "error" in r).length,
          totalProcessingTimeMs: totalTime,
          scannedFrom: ip,
        },
      },
      { status: 200 }
    );
  } catch (error) {
    console.error("[Bulk Scan] Error:", error);
    return NextResponse.json(
      { error: "Bulk scan failed" },
      { status: 500 }
    );
  }
}
