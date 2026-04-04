// GET /api/gmail/scan-results — Paginated list of scanned emails for the current user
import { NextRequest, NextResponse } from "next/server";
import { getUserFromRequest } from "@/lib/auth-helpers";
import { createServiceRoleClient } from "@/lib/supabase/client";

export async function GET(req: NextRequest) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const { searchParams } = new URL(req.url);
  const limit = Math.min(50, parseInt(searchParams.get("limit") ?? "20", 10));
  const offset = Math.max(0, parseInt(searchParams.get("offset") ?? "0", 10));
  const threatOnly = searchParams.get("threats") === "1";

  const db = createServiceRoleClient();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let query = (db as any)
    .from("gmail_scan_results")
    .select("id, gmail_message_id, sender_domain, subject_preview, received_at, score, threat_level, category, scanned_at")
    .eq("user_id", user.id)
    .order("scanned_at", { ascending: false })
    .range(offset, offset + limit - 1);

  if (threatOnly) {
    query = query.in("threat_level", ["HIGH", "CRITICAL", "MEDIUM"]);
  }

  const { data, error } = await query;

  if (error) {
    console.error("[gmail/scan-results]", error.message);
    return NextResponse.json({ error: "Failed to load results" }, { status: 500 });
  }

  return NextResponse.json({ results: data ?? [], limit, offset });
}
