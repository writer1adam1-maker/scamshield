// POST /api/gmail/poll — Cron-invoked: scan new emails for all active connections
// Called every 15 minutes by Vercel cron (vercel.json)
// Auth: Authorization: Bearer <CRON_SECRET>
import { NextRequest, NextResponse } from "next/server";
import { createServiceRoleClient } from "@/lib/supabase/client";
import { decryptToken } from "@/lib/gmail/token-crypto";
import { refreshAccessToken } from "@/lib/gmail/oauth";
import { fetchNewMessages } from "@/lib/gmail/gmail-client";
import { scanEmails } from "@/lib/gmail/scan-emails";

const CRON_SECRET = process.env.CRON_SECRET;

export async function POST(req: NextRequest) {
  // Authenticate cron caller
  const auth = req.headers.get("authorization");
  if (CRON_SECRET && auth !== `Bearer ${CRON_SECRET}`) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const db = createServiceRoleClient();

  // Fetch all active connections
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data: connections, error } = await (db as any)
    .from("gmail_connections")
    .select("id, user_id, encrypted_refresh_token, history_id, emails_scanned_total, threats_found_total")
    .eq("is_active", true);

  if (error) {
    console.error("[gmail/poll] Failed to fetch connections:", error.message);
    return NextResponse.json({ error: "DB error" }, { status: 500 });
  }

  if (!connections || connections.length === 0) {
    return NextResponse.json({ polled: 0, message: "No active connections" });
  }

  let totalPolled = 0;
  let totalScanned = 0;
  let totalThreats = 0;

  for (const conn of connections) {
    try {
      // Decrypt + refresh access token
      const refreshToken = await decryptToken(conn.encrypted_refresh_token);
      const { access_token } = await refreshAccessToken(refreshToken);

      // Fetch new messages
      const { messages, newHistoryId } = await fetchNewMessages(access_token, conn.history_id);

      if (messages.length === 0) {
        // Update last_polled_at even with no new messages
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        await (db as any)
          .from("gmail_connections")
          .update({ last_polled_at: new Date().toISOString(), history_id: newHistoryId ?? conn.history_id })
          .eq("id", conn.id);
        continue;
      }

      // Scan emails
      const { scanned, threats } = await scanEmails(messages, conn.user_id);
      totalScanned += scanned;
      totalThreats += threats;
      totalPolled++;

      // Update connection stats + historyId
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (db as any)
        .from("gmail_connections")
        .update({
          last_polled_at: new Date().toISOString(),
          history_id: newHistoryId ?? conn.history_id,
          emails_scanned_total: (conn.emails_scanned_total ?? 0) + scanned,
          threats_found_total: (conn.threats_found_total ?? 0) + threats,
        })
        .eq("id", conn.id);
    } catch (err) {
      console.error("[gmail/poll] Failed for connection", conn.id, err);
      // Mark connection as inactive if token refresh failed
      if (String(err).includes("Token refresh failed")) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        await (db as any)
          .from("gmail_connections")
          .update({ is_active: false })
          .eq("id", conn.id);
      }
    }
  }

  return NextResponse.json({
    polled: totalPolled,
    scanned: totalScanned,
    threats: totalThreats,
    totalConnections: connections.length,
  });
}
