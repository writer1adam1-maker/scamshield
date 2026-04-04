/**
 * Email scanning — runs VERIDICT on each Gmail message's subject + snippet.
 * Email body content is NEVER read or stored.
 * Only subject_preview + scan result are persisted.
 */

import { runVERIDICT } from "@/lib/algorithms/veridict-engine";
import { createServiceRoleClient } from "@/lib/supabase/client";
import type { GmailMessage } from "./gmail-client";

interface ScanEmailsResult {
  scanned: number;
  threats: number;
}

export async function scanEmails(
  messages: GmailMessage[],
  userId: string
): Promise<ScanEmailsResult> {
  if (messages.length === 0) return { scanned: 0, threats: 0 };

  const db = createServiceRoleClient();
  let scanned = 0;
  let threats = 0;

  // Process in series to avoid hitting internal algorithm rate limits
  for (const msg of messages) {
    try {
      // Build scan input from subject + snippet only (no body)
      const text = [
        msg.subject ? `Subject: ${msg.subject}` : "",
        msg.senderDomain ? `From domain: ${msg.senderDomain}` : "",
        msg.snippet ? msg.snippet : "",
      ].filter(Boolean).join("\n");

      if (!text.trim()) continue;

      const result = await runVERIDICT({ text });
      scanned++;

      const threatLevel = result.threatLevel;
      if (threatLevel === "HIGH" || threatLevel === "CRITICAL") threats++;

      // Upsert result — don't store duplicate message IDs
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (db as any).from("gmail_scan_results").upsert({
        user_id: userId,
        gmail_message_id: msg.id,
        sender_domain: msg.senderDomain || null,
        subject_preview: msg.subject ? msg.subject.substring(0, 80) : null,
        received_at: msg.receivedAt?.toISOString() ?? null,
        score: result.score,
        threat_level: threatLevel,
        category: result.category,
        evidence_json: (result.evidence ?? []).slice(0, 5),
      }, { onConflict: "user_id,gmail_message_id" });
    } catch (err) {
      console.error("[scan-emails] Failed to scan message", msg.id, err);
    }
  }

  return { scanned, threats };
}
