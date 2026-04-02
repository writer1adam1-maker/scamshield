// ============================================================================
// POST /api/feedback — Community scam reporting
// Lets users submit scam reports to improve the dataset
// GET  /api/feedback/stats — Aggregate community stats
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { createServiceRoleClient } from "@/lib/supabase/client";

interface FeedbackRequest {
  content: string;              // The URL or text being reported
  contentType: "url" | "text";
  isScam: boolean;              // true = scam, false = false positive
  category?: string;            // optional: what type of scam
  details?: string;             // optional: free-text description
}

function validateFeedback(body: unknown): body is FeedbackRequest {
  if (!body || typeof body !== "object") return false;
  const b = body as Record<string, unknown>;
  if (!["url", "text"].includes(b.contentType as string)) return false;
  if (typeof b.content !== "string" || b.content.trim().length === 0) return false;
  if (b.content.length > 2_000) return false;
  if (typeof b.isScam !== "boolean") return false;
  return true;
}

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => null);

    if (!validateFeedback(body)) {
      return NextResponse.json(
        { error: "Invalid feedback body. Required: content (string), contentType ('url'|'text'), isScam (boolean)" },
        { status: 400 }
      );
    }

    const { content, contentType, isScam, category, details } = body;

    // Sanitize details input
    const sanitizedDetails = typeof details === "string"
      ? details.substring(0, 500).replace(/[<>]/g, "")
      : null;

    // Persist to Supabase community_reports table
    // (table created via migration — graceful fallback if not yet migrated)
    try {
      const db = createServiceRoleClient();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (db as any).from("community_reports").insert({
        content_type: contentType,
        content_preview: content.substring(0, 200),
        is_scam: isScam,
        category: category ?? null,
        details: sanitizedDetails,
        ip_hash: null, // TODO: hash IP for spam detection
        created_at: new Date().toISOString(),
      });
    } catch {
      // Silently continue if table doesn't exist yet — don't break the API
      console.warn("[Feedback] community_reports table may not exist yet");
    }

    return NextResponse.json(
      {
        received: true,
        message: isScam
          ? "Thank you for reporting this scam. Your report helps protect others."
          : "Thank you for reporting a false positive. We'll review it to improve accuracy.",
      },
      { status: 201 }
    );
  } catch (error) {
    console.error("[Feedback] Error:", error);
    return NextResponse.json({ error: "Failed to submit feedback" }, { status: 500 });
  }
}

export async function GET() {
  // Return community stats — real data when table exists, fallback to placeholder
  try {
    const db = createServiceRoleClient();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { count: totalReports } = await (db as any)
      .from("community_reports")
      .select("*", { count: "exact", head: true });

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { count: scamReports } = await (db as any)
      .from("community_reports")
      .select("*", { count: "exact", head: true })
      .eq("is_scam", true);

    return NextResponse.json({
      totalReports: totalReports ?? 0,
      scamReports: scamReports ?? 0,
      falsPositiveReports: (totalReports ?? 0) - (scamReports ?? 0),
      accuracy: totalReports ? ((scamReports ?? 0) / totalReports * 100).toFixed(1) + "%" : "N/A",
    });
  } catch {
    return NextResponse.json({
      totalReports: 0,
      scamReports: 0,
      falsePositiveReports: 0,
      accuracy: "N/A",
    });
  }
}
