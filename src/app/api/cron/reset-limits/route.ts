// ============================================================================
// GET /api/cron/reset-limits — Reset daily scan counts (Vercel Cron)
// Schedule: daily at midnight (configure in vercel.json)
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { createServiceRoleClient } from "@/lib/supabase/client";

export async function GET(req: NextRequest) {
  const authHeader = req.headers.get("authorization");
  const cronSecret = process.env.CRON_SECRET;

  if (!cronSecret || authHeader !== `Bearer ${cronSecret}`) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  try {
    const db = createServiceRoleClient();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const dbAny = db as any;

    const { data, error } = await dbAny
      .from("users")
      .update({ scan_count_today: 0 })
      .gt("scan_count_today", 0)
      .select("id");

    if (error) {
      console.error("[cron/reset-limits] Supabase error:", error);
      return NextResponse.json({ error: "Database update failed" }, { status: 500 });
    }

    const rowsUpdated = (data ?? []).length;
    console.log(`[cron/reset-limits] Reset scan_count_today for ${rowsUpdated} user(s)`);

    return NextResponse.json({ reset: true, timestamp: new Date().toISOString() });
  } catch (err) {
    console.error("[cron/reset-limits] Unexpected error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
