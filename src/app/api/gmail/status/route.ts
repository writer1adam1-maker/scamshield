// GET /api/gmail/status — Return connection status + stats for the current user
import { NextRequest, NextResponse } from "next/server";
import { getUserFromRequest } from "@/lib/auth-helpers";
import { createServiceRoleClient } from "@/lib/supabase/client";

export async function GET(req: NextRequest) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const db = createServiceRoleClient();

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data: conn } = await (db as any)
    .from("gmail_connections")
    .select("google_email, connected_at, last_polled_at, emails_scanned_total, threats_found_total, is_active")
    .eq("user_id", user.id)
    .single();

  if (!conn || !conn.is_active) {
    return NextResponse.json({ connected: false });
  }

  return NextResponse.json({
    connected: true,
    googleEmail: conn.google_email,
    connectedAt: conn.connected_at,
    lastPolledAt: conn.last_polled_at,
    emailsScannedTotal: conn.emails_scanned_total,
    threatsFoundTotal: conn.threats_found_total,
  });
}
