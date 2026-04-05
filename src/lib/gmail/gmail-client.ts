/**
 * Gmail API client — fetches message metadata (headers only, no body).
 * Uses gmail.metadata scope — returns From, Subject, Date headers only.
 */

const GMAIL_API = "https://www.googleapis.com/gmail/v1";

export interface GmailMessage {
  id: string;
  threadId: string;
  subject: string;
  from: string;
  senderDomain: string;
  receivedAt: Date | null;
  snippet: string; // Gmail snippet (first ~100 chars, safe to use for scanning)
}

export interface GmailHistoryResult {
  messages: GmailMessage[];
  newHistoryId: string | null;
}

/**
 * Fetch new messages since the given historyId.
 * If no historyId (first sync), fetches the 20 most recent messages.
 * Cap: 50 messages per call to prevent quota exhaustion.
 */
export async function fetchNewMessages(
  accessToken: string,
  historyId: string | null
): Promise<GmailHistoryResult> {
  const headers = { Authorization: "Bearer " + accessToken };

  // If we have a historyId, use history.list for incremental sync
  if (historyId) {
    const histRes = await fetch(
      `${GMAIL_API}/users/me/history?startHistoryId=${historyId}&maxResults=50`,
      { headers }
    );

    if (!histRes.ok) {
      if (histRes.status === 404) {
        // historyId expired — fall back to recent messages
        return fetchRecentMessages(accessToken, headers);
      }
      throw new Error("Gmail history.list failed: " + histRes.status);
    }

    const histData = await histRes.json();
    const newHistoryId = histData.historyId ?? historyId;

    if (!histData.history || histData.history.length === 0) {
      return { messages: [], newHistoryId };
    }

    // Collect unique message IDs from history
    const msgIds = new Set<string>();
    for (const record of histData.history) {
      for (const added of record.messagesAdded ?? []) {
        if (added.message?.id) msgIds.add(added.message.id);
      }
    }

    const messages = await batchGetMessages(accessToken, Array.from(msgIds).slice(0, 50), headers);
    return { messages, newHistoryId };
  }

  return fetchRecentMessages(accessToken, headers);
}

async function fetchRecentMessages(
  accessToken: string,
  headers: Record<string, string>
): Promise<GmailHistoryResult> {
  // Get list of recent message IDs
  const listRes = await fetch(
    `${GMAIL_API}/users/me/messages?maxResults=50`,
    { headers }
  );

  if (!listRes.ok) {
    const errBody = await listRes.text();
    throw new Error(`Gmail messages.list failed: ${listRes.status} — ${errBody}`);
  }
  const listData = await listRes.json();
  const msgIds: string[] = (listData.messages ?? []).map((m: { id: string }) => m.id);

  // Get profile to capture current historyId
  const profileRes = await fetch(`${GMAIL_API}/users/me/profile`, { headers });
  const profile = profileRes.ok ? await profileRes.json() : {};
  const newHistoryId = profile.historyId ?? null;

  const messages = await batchGetMessages(accessToken, msgIds, headers);
  return { messages, newHistoryId };
}

/** Fetch message metadata for a list of IDs */
async function batchGetMessages(
  _accessToken: string,
  ids: string[],
  headers: Record<string, string>
): Promise<GmailMessage[]> {
  if (ids.length === 0) return [];

  // Fetch messages in parallel (up to 10 at a time)
  const results: GmailMessage[] = [];
  const chunks = chunkArray(ids, 10);

  for (const chunk of chunks) {
    const fetched = await Promise.allSettled(
      chunk.map((id) =>
        fetch(`${GMAIL_API}/users/me/messages/${id}?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date`, { headers })
          .then((r) => (r.ok ? r.json() : null))
          .then((data) => parseMessage(data))
      )
    );

    for (const r of fetched) {
      if (r.status === "fulfilled" && r.value) results.push(r.value);
    }
  }

  return results;
}

function parseMessage(data: Record<string, unknown> | null): GmailMessage | null {
  if (!data || typeof data !== "object") return null;

  const id = data.id as string;
  const threadId = data.threadId as string;
  const snippet = (data.snippet as string | undefined) ?? "";
  const headers = (data.payload as { headers?: { name: string; value: string }[] } | undefined)?.headers ?? [];

  const getHeader = (name: string) =>
    headers.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value ?? "";

  const from = getHeader("From");
  const subject = getHeader("Subject");
  const dateStr = getHeader("Date");

  // Extract domain from From header safely
  const emailMatch = from.match(/<([^>]+)>/) || from.match(/([^\s@]+@[^\s>]+)/);
  const email = emailMatch?.[1] ?? from;
  const senderDomain = email.includes("@") ? email.split("@")[1].toLowerCase().trim() : "";

  let receivedAt: Date | null = null;
  if (dateStr) {
    try { receivedAt = new Date(dateStr); } catch { /* ignore */ }
  }

  return {
    id,
    threadId,
    subject: subject.substring(0, 120),
    from,
    senderDomain,
    receivedAt,
    snippet: snippet.substring(0, 200),
  };
}

function chunkArray<T>(arr: T[], size: number): T[][] {
  const chunks: T[][] = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}
