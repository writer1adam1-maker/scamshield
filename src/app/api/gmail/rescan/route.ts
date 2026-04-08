/**
 * POST /api/gmail/rescan
 * Resets the user's Gmail historyId + clears stale scan records,
 * then immediately does a full rescan of recent 50 emails.
 * Called by the dashboard "Scan Now" button to force fresh results.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { createServiceRoleClient } from "@/lib/supabase/client";
import { decryptToken } from "@/lib/gmail/token-crypto";
import { refreshAccessToken } from "@/lib/gmail/oauth";
import { fetchNewMessages } from "@/lib/gmail/gmail-client";
import { scanEmails } from "@/lib/gmail/scan-emails";

export async function POST(req: NextRequest) {
  // Verify user session
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    { cookies: { getAll() { return req.cookies.getAll(); }, setAll() {} } }
  );
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const db = createServiceRoleClient();

  // Get this user's active Gmail connection
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data: conn, error: connErr } = await (db as any)
    .from("gmail_connections")
    .select("id, user_id, encrypted_refresh_token, emails_scanned_total, threats_found_total, google_email")
    .eq("user_id", user.id)
    .eq("is_active", true)
    .single();

  if (connErr || !conn) {
    return NextResponse.json({ error: "No active Gmail connection" }, { status: 404 });
  }

  try {
    // Reset historyId → next fetch will pull 50 most recent messages
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await (db as any)
      .from("gmail_connections")
      .update({ history_id: null })
      .eq("id", conn.id);

    // Clear stale scan results so old scores don't persist
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await (db as any)
      .from("gmail_scan_results")
      .delete()
      .eq("user_id", user.id);

    // Fetch + scan fresh
    const refreshToken = await decryptToken(conn.encrypted_refresh_token);
    const { access_token } = await refreshAccessToken(refreshToken);
    const { messages, newHistoryId } = await fetchNewMessages(access_token, null);

    const { scanned, threats } = await scanEmails(messages, user.id);

    // Update connection with fresh stats
    const now = new Date().toISOString();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await (db as any)
      .from("gmail_connections")
      .update({
        last_polled_at: now,
        history_id: newHistoryId,
        emails_scanned_total: scanned,
        threats_found_total: threats,
      })
      .eq("id", conn.id);

    return NextResponse.json({ scanned, threats });
  } catch (err) {
    console.error("[gmail/rescan] Error:", err);
    return NextResponse.json({ error: "Rescan failed" }, { status: 500 });
  }
}
