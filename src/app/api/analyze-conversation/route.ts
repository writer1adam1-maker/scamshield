// ============================================================================
// POST /api/analyze-conversation — Conversation Arc Analyzer endpoint
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { analyzeConversationArc } from "@/lib/algorithms/conversation-arc";
import { checkRateLimit } from "@/lib/rate-limit";
import { getClientIp } from "@/lib/utils";
import { getUserFromRequest, canScan, incrementScanCount } from "@/lib/auth-helpers";

/** 1 scan per 1,000 words, minimum 1, capped at 10 */
function scansForText(text: string): number {
  const words = text.trim().split(/\s+/).filter(Boolean).length;
  return Math.min(10, Math.max(1, Math.floor(words / 1000)));
}

export async function POST(req: NextRequest) {
  try {
    const ip = getClientIp(req);
    const rateLimit = checkRateLimit(ip, false);

    if (!rateLimit.allowed) {
      return NextResponse.json(
        {
          error: "Rate limit exceeded. Upgrade to Pro for unlimited scans.",
          remaining: rateLimit.remaining,
          resetAt: new Date(rateLimit.resetAt).toISOString(),
        },
        { status: 429 },
      );
    }

    const body = await req.json().catch(() => null);

    if (!body || typeof body.conversation !== "string" || !body.conversation.trim()) {
      return NextResponse.json(
        { error: "Provide { conversation: string } with non-empty conversation text." },
        { status: 400 },
      );
    }

    if (body.conversation.length > 100_000) {
      return NextResponse.json(
        { error: "Conversation too long. Maximum 100,000 characters (~10,000 messages)." },
        { status: 400 },
      );
    }

    // --- Auth + quota check ---
    const authUser = await getUserFromRequest(req);
    const scansNeeded = scansForText(body.conversation);

    if (authUser) {
      const quota = await canScan(authUser);
      if (!quota.allowed) {
        return NextResponse.json(
          { error: `Scan quota reached. This analysis requires ${scansNeeded} scan${scansNeeded > 1 ? "s" : ""} (1 per 1,000 words). Upgrade your plan for more.` },
          { status: 429 },
        );
      }
    }

    const result = analyzeConversationArc(body.conversation);

    // --- Deduct scans after successful analysis ---
    if (authUser) {
      for (let i = 0; i < scansNeeded; i++) {
        await incrementScanCount(authUser.id);
      }
    }

    return NextResponse.json(
      { ...result, scansUsed: scansNeeded },
      {
        status: 200,
        headers: {
          "X-RateLimit-Remaining": String(rateLimit.remaining),
          "X-Processing-Time": `${result.processingTimeMs}ms`,
          "X-Scans-Used": String(scansNeeded),
        },
      },
    );
  } catch (err) {
    console.error("[/api/analyze-conversation] Unexpected error:", err);
    return NextResponse.json(
      { error: "Internal server error. Please try again." },
      { status: 500 },
    );
  }
}
