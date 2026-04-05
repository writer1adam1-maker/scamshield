/**
 * Gmail Shield digest email — sent after a scan based on user's chosen frequency.
 * Uses Resend (resend.com) — free tier: 3,000 emails/month.
 */

import { Resend } from "resend";

const resend = new Resend(process.env.RESEND_API_KEY);
const FROM = process.env.RESEND_FROM || "ScamShield <noreply@scamshieldy.com>";

export type DigestFrequency = "hourly" | "12h" | "daily" | "weekly" | "never";

/** Returns true if a digest should be sent based on frequency + last sent time */
export function shouldSendDigest(
  frequency: DigestFrequency,
  lastSentAt: string | null
): boolean {
  if (frequency === "never") return false;
  if (!lastSentAt) return true; // never sent before → send now

  const last = new Date(lastSentAt).getTime();
  const now = Date.now();
  const elapsed = now - last;

  const thresholds: Record<Exclude<DigestFrequency, "never">, number> = {
    hourly:  60 * 60 * 1000,
    "12h":   12 * 60 * 60 * 1000,
    daily:   24 * 60 * 60 * 1000,
    weekly:  7  * 24 * 60 * 60 * 1000,
  };

  return elapsed >= thresholds[frequency as Exclude<DigestFrequency, "never">];
}

export interface DigestPayload {
  toEmail: string;
  googleEmail: string;
  scanned: number;
  threats: number;
  topResults: {
    subject: string | null;
    senderDomain: string | null;
    threatLevel: string;
    score: number;
  }[];
  frequency: DigestFrequency;
}

export async function sendDigestEmail(payload: DigestPayload): Promise<void> {
  const { toEmail, googleEmail, scanned, threats, topResults, frequency } = payload;

  const freqLabel: Record<DigestFrequency, string> = {
    hourly: "hourly",
    "12h": "every 12 hours",
    daily: "daily",
    weekly: "weekly",
    never: "",
  };

  const threatRows = topResults
    .filter((r) => r.threatLevel === "HIGH" || r.threatLevel === "CRITICAL")
    .slice(0, 5);

  const safeRows = topResults
    .filter((r) => r.threatLevel !== "HIGH" && r.threatLevel !== "CRITICAL")
    .slice(0, 3);

  const threatColor = threats > 0 ? "#ef4444" : "#22c55e";
  const threatText  = threats > 0 ? `⚠️ ${threats} threat${threats !== 1 ? "s" : ""} found` : "✅ No threats found";

  const renderRow = (r: typeof topResults[0]) => {
    const color = r.threatLevel === "HIGH" || r.threatLevel === "CRITICAL" ? "#ef4444" : "#22c55e";
    return `
      <tr>
        <td style="padding:8px 12px;border-bottom:1px solid #1e293b;font-size:13px;color:#e2e8f0;">
          ${r.subject || "(No subject)"}
        </td>
        <td style="padding:8px 12px;border-bottom:1px solid #1e293b;font-size:12px;color:#94a3b8;">
          ${r.senderDomain || "unknown"}
        </td>
        <td style="padding:8px 12px;border-bottom:1px solid #1e293b;font-size:12px;font-weight:600;color:${color};">
          ${r.threatLevel}
        </td>
        <td style="padding:8px 12px;border-bottom:1px solid #1e293b;font-size:12px;color:#94a3b8;text-align:right;">
          ${r.score}
        </td>
      </tr>`;
  };

  const html = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0f1e;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#0a0f1e;padding:32px 16px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">

        <!-- Header -->
        <tr>
          <td style="background:#0d1526;border:1px solid #1e3a5f;border-radius:16px 16px 0 0;padding:28px 32px;">
            <table width="100%">
              <tr>
                <td>
                  <span style="font-size:22px;font-weight:700;color:#38bdf8;">⚡ ScamShield</span>
                  <span style="font-size:13px;color:#64748b;margin-left:8px;">Gmail Shield Report</span>
                </td>
                <td align="right">
                  <span style="font-size:11px;color:#475569;background:#1e293b;padding:4px 10px;border-radius:20px;">
                    ${freqLabel[frequency]} digest
                  </span>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Summary -->
        <tr>
          <td style="background:#0f1a2e;border-left:1px solid #1e3a5f;border-right:1px solid #1e3a5f;padding:24px 32px;">
            <table width="100%" cellspacing="8">
              <tr>
                <td width="50%" style="background:#0a0f1e;border:1px solid #1e3a5f;border-radius:12px;padding:16px;text-align:center;">
                  <div style="font-size:28px;font-weight:700;color:#38bdf8;">${scanned}</div>
                  <div style="font-size:11px;color:#64748b;margin-top:4px;">Emails Scanned</div>
                </td>
                <td width="50%" style="background:#0a0f1e;border:1px solid #1e3a5f;border-radius:12px;padding:16px;text-align:center;">
                  <div style="font-size:28px;font-weight:700;color:${threatColor};">${threats}</div>
                  <div style="font-size:11px;color:#64748b;margin-top:4px;">Threats Found</div>
                </td>
              </tr>
            </table>
            <div style="margin-top:16px;padding:12px 16px;background:${threats > 0 ? "#1a0a0a" : "#0a1a0a"};border:1px solid ${threats > 0 ? "#ef444430" : "#22c55e30"};border-radius:10px;font-size:13px;color:${threatColor};font-weight:600;">
              ${threatText} in your inbox (${googleEmail})
            </div>
          </td>
        </tr>

        <!-- Threat emails -->
        ${threatRows.length > 0 ? `
        <tr>
          <td style="background:#0f1a2e;border-left:1px solid #1e3a5f;border-right:1px solid #1e3a5f;padding:0 32px 24px;">
            <div style="font-size:13px;font-weight:600;color:#ef4444;margin-bottom:12px;">⚠️ Suspicious Emails</div>
            <table width="100%" cellspacing="0" style="background:#0a0f1e;border:1px solid #ef444430;border-radius:10px;overflow:hidden;">
              <thead>
                <tr style="background:#1a0a0a;">
                  <th style="padding:8px 12px;text-align:left;font-size:11px;color:#64748b;font-weight:500;">Subject</th>
                  <th style="padding:8px 12px;text-align:left;font-size:11px;color:#64748b;font-weight:500;">Sender</th>
                  <th style="padding:8px 12px;text-align:left;font-size:11px;color:#64748b;font-weight:500;">Level</th>
                  <th style="padding:8px 12px;text-align:right;font-size:11px;color:#64748b;font-weight:500;">Score</th>
                </tr>
              </thead>
              <tbody>${threatRows.map(renderRow).join("")}</tbody>
            </table>
          </td>
        </tr>` : ""}

        <!-- Safe emails sample -->
        ${safeRows.length > 0 ? `
        <tr>
          <td style="background:#0f1a2e;border-left:1px solid #1e3a5f;border-right:1px solid #1e3a5f;padding:0 32px 24px;">
            <div style="font-size:13px;font-weight:600;color:#22c55e;margin-bottom:12px;">✅ Safe Emails (sample)</div>
            <table width="100%" cellspacing="0" style="background:#0a0f1e;border:1px solid #22c55e20;border-radius:10px;overflow:hidden;">
              <tbody>${safeRows.map(renderRow).join("")}</tbody>
            </table>
          </td>
        </tr>` : ""}

        <!-- CTA -->
        <tr>
          <td style="background:#0f1a2e;border-left:1px solid #1e3a5f;border-right:1px solid #1e3a5f;padding:0 32px 28px;text-align:center;">
            <a href="https://scamshieldy.com/dashboard/gmail"
               style="display:inline-block;background:#38bdf8;color:#0a0f1e;font-weight:700;font-size:14px;padding:12px 32px;border-radius:10px;text-decoration:none;">
              View Full Report →
            </a>
            <p style="font-size:11px;color:#475569;margin-top:16px;">
              You're receiving this because you connected Gmail Shield on ScamShield.<br>
              <a href="https://scamshieldy.com/dashboard/gmail" style="color:#38bdf8;">Change frequency</a> or
              <a href="https://scamshieldy.com/dashboard/gmail" style="color:#38bdf8;">disconnect</a>
            </p>
          </td>
        </tr>

        <!-- Footer -->
        <tr>
          <td style="background:#080d1a;border:1px solid #1e3a5f;border-radius:0 0 16px 16px;padding:16px 32px;text-align:center;">
            <span style="font-size:11px;color:#334155;">ScamShield · scamshieldy.com · Email content is never read or stored</span>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>`;

  await resend.emails.send({
    from: FROM,
    to: toEmail,
    subject: threats > 0
      ? `⚠️ ScamShield: ${threats} suspicious email${threats !== 1 ? "s" : ""} detected`
      : `✅ ScamShield: Inbox scan complete — ${scanned} emails checked`,
    html,
  });
}
