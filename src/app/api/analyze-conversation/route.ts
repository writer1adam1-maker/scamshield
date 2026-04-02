// ============================================================================
// POST /api/analyze-conversation — Conversation Arc Analyzer endpoint
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { analyzeConversationArc } from "@/lib/algorithms/conversation-arc";
import { checkRateLimit } from "@/lib/rate-limit";
import { getClientIp } from "@/lib/utils";

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

    const result = analyzeConversationArc(body.conversation);

    return NextResponse.json(result, {
      status: 200,
      headers: {
        "X-RateLimit-Remaining": String(rateLimit.remaining),
        "X-Processing-Time": `${result.processingTimeMs}ms`,
      },
    });
  } catch (err) {
    console.error("[/api/analyze-conversation] Unexpected error:", err);
    return NextResponse.json(
      { error: "Internal server error. Please try again." },
      { status: 500 },
    );
  }
}
