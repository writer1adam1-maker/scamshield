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
  results: { subject_preview: string | null; sender_domain: string | null; threat_level: string; score: number }[];
}

export async function scanEmails(
  messages: GmailMessage[],
  userId: string
): Promise<ScanEmailsResult> {
  if (messages.length === 0) return { scanned: 0, threats: 0, results: [] };

  const db = createServiceRoleClient();
  let scanned = 0;
  let threats = 0;
  const results: ScanEmailsResult["results"] = [];

  // Process in series to avoid hitting internal algorithm rate limits
  for (const msg of messages) {
    try {
      // Build scan input from subject + snippet + sender domain URL analysis
      const textParts = [
        msg.subject ? `Subject: ${msg.subject}` : "",
        msg.snippet ? msg.snippet : "",
      ].filter(Boolean);

      const text = textParts.join("\n");
      const url = msg.senderDomain ? `https://${msg.senderDomain}` : undefined;

      // Need at least something to scan
      if (!text.trim() && !url) continue;

      const result = await runVERIDICT({ text: text || undefined, url, emailMode: true });
      scanned++;

      let finalScore = result.score;
      let threatLevel = result.threatLevel;

      // Gmail already classified this as SPAM — minimum score is HIGH (65)
      // The sender domain may look clean but the content triggered Gmail's own filters
      if (msg.isSpam && finalScore < 65) {
        finalScore = Math.max(finalScore, 65);
        threatLevel = "HIGH";
      }
      if (threatLevel === "HIGH" || threatLevel === "CRITICAL") threats++;

      results.push({
        subject_preview: msg.subject ? msg.subject.substring(0, 80) : null,
        sender_domain: msg.senderDomain || null,
        threat_level: threatLevel,
        score: finalScore,
      });

      // Upsert result — don't store duplicate message IDs
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const { error: upsertErr } = await (db as any).from("gmail_scan_results").upsert({
        user_id: userId,
        gmail_message_id: msg.id,
        sender_domain: msg.senderDomain || null,
        subject_preview: msg.subject ? msg.subject.substring(0, 80) : null,
        received_at: msg.receivedAt?.toISOString() ?? null,
        score: Math.round(finalScore),   // DB column is integer
        threat_level: threatLevel,
        category: result.category ?? "GENERIC",
        evidence_json: (result.evidence ?? []).slice(0, 5),
      }, { onConflict: "user_id,gmail_message_id" });

      if (upsertErr) console.error("[scan-emails] Upsert failed for", msg.id, upsertErr.message);
    } catch (err) {
      console.error("[scan-emails] Failed to scan message", msg.id, err);
    }
  }

  return { scanned, threats, results };
}
