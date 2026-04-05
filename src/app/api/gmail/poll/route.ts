// POST/GET /api/gmail/poll — Cron-invoked: scan new emails for all active connections
// Auth: Authorization: Bearer <CRON_SECRET>
import { NextRequest, NextResponse } from "next/server";
import { createServiceRoleClient } from "@/lib/supabase/client";
import { decryptToken } from "@/lib/gmail/token-crypto";
import { refreshAccessToken } from "@/lib/gmail/oauth";
import { fetchNewMessages } from "@/lib/gmail/gmail-client";
import { scanEmails } from "@/lib/gmail/scan-emails";
import { shouldSendDigest, sendDigestEmail, type DigestFrequency } from "@/lib/gmail/digest-email";

const CRON_SECRET = process.env.CRON_SECRET;

export async function GET(req: NextRequest) {
  return POST(req);
}

export async function POST(req: NextRequest) {
  // Authenticate cron caller (skip auth if no secret set — allows manual trigger from dashboard)
  const auth = req.headers.get("authorization");
  if (CRON_SECRET && auth !== `Bearer ${CRON_SECRET}`) {
    return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  }

  const db = createServiceRoleClient();

  // Fetch all active connections including digest prefs
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data: connections, error } = await (db as any)
    .from("gmail_connections")
    .select("id, user_id, encrypted_refresh_token, history_id, emails_scanned_total, threats_found_total, digest_frequency, last_digest_sent_at, user_email, google_email")
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
        await (db as any)
          .from("gmail_connections")
          .update({ last_polled_at: new Date().toISOString(), history_id: newHistoryId ?? conn.history_id })
          .eq("id", conn.id);
        continue;
      }

      // Scan emails
      const { scanned, threats, results } = await scanEmails(messages, conn.user_id);
      totalScanned += scanned;
      totalThreats += threats;
      totalPolled++;

      const now = new Date().toISOString();

      // Update connection stats
      await (db as any)
        .from("gmail_connections")
        .update({
          last_polled_at: now,
          history_id: newHistoryId ?? conn.history_id,
          emails_scanned_total: (conn.emails_scanned_total ?? 0) + scanned,
          threats_found_total: (conn.threats_found_total ?? 0) + threats,
        })
        .eq("id", conn.id);

      // Send digest email if due
      const frequency = (conn.digest_frequency ?? "daily") as DigestFrequency;
      const toEmail = conn.user_email || conn.google_email;

      if (toEmail && shouldSendDigest(frequency, conn.last_digest_sent_at)) {
        try {
          await sendDigestEmail({
            toEmail,
            googleEmail: conn.google_email,
            scanned,
            threats,
            topResults: results.slice(0, 8).map((r: { subject_preview: string | null; sender_domain: string | null; threat_level: string; score: number }) => ({
              subject: r.subject_preview,
              senderDomain: r.sender_domain,
              threatLevel: r.threat_level,
              score: r.score,
            })),
            frequency,
          });

          await (db as any)
            .from("gmail_connections")
            .update({ last_digest_sent_at: now })
            .eq("id", conn.id);

          console.log(`[gmail/poll] Digest sent to ${toEmail}`);
        } catch (emailErr) {
          console.error("[gmail/poll] Failed to send digest email:", emailErr);
        }
      }
    } catch (err) {
      console.error("[gmail/poll] Failed for connection", conn.id, err);
      if (String(err).includes("Token refresh failed")) {
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
