// ============================================================================
// API Key Rate Limiter (In-Memory)
// ============================================================================
// Tracks API key usage across requests. Resets daily at midnight UTC.
// In production, replace with Redis or Supabase for distributed rate limiting.

interface ApiKeyLimitEntry {
  requestsToday: number;
  requestsTotal: number;
  lastUsedAt: number;
  resetAt: number;
  createdAt: number;
}

const store = new Map<string, ApiKeyLimitEntry>();
const MAX_STORE_SIZE = 10_000;

function getResetTimestamp(): number {
  const now = new Date();
  const tomorrow = new Date(Date.UTC(
    now.getUTCFullYear(),
    now.getUTCMonth(),
    now.getUTCDate() + 1,
    0, 0, 0, 0,
  ));
  return tomorrow.getTime();
}

let lastCleanup = 0;
function cleanupExpired() {
  const now = Date.now();
  if (now - lastCleanup < 60_000) return;
  lastCleanup = now;

  for (const [key, entry] of store) {
    if (now >= entry.resetAt && entry.createdAt < now - 24 * 60 * 60 * 1000) {
      store.delete(key);
    }
  }
}

export interface ApiKeyRateLimitResult {
  allowed: boolean;
  remaining: number;
  limit: number;
  resetAt: number;
  requestsToday: number;
  requestsTotal: number;
}

/**
 * Track API key usage and enforce daily limits.
 * free key: 100 requests/day
 * pro key:  10,000 requests/day
 */
export function checkApiKeyRateLimit(
  keyId: string,
  plan: "free" | "pro",
): ApiKeyRateLimitResult {
  cleanupExpired();

  const limit = plan === "pro" ? 10_000 : 100;
  // Note: these match PLAN_DEFAULTS.apiKeyDailyLimit / apiKeyProDailyLimit in plan-config.ts
  const now = Date.now();
  let entry = store.get(keyId);

  // Reset if the day has rolled over
  if (!entry || now >= entry.resetAt) {
    entry = {
      requestsToday: 0,
      requestsTotal: 0,
      lastUsedAt: now,
      resetAt: getResetTimestamp(),
      createdAt: now,
    };
    store.set(keyId, entry);
  }

  // Evict oldest entries if store exceeds max size
  if (store.size > MAX_STORE_SIZE) {
    let oldestKey: string | null = null;
    let oldestTime = Infinity;
    for (const [key, val] of store) {
      if (val.createdAt < oldestTime) {
        oldestTime = val.createdAt;
        oldestKey = key;
      }
    }
    if (oldestKey) store.delete(oldestKey);
  }

  const remaining = Math.max(0, limit - entry.requestsToday);

  if (entry.requestsToday >= limit) {
    return {
      allowed: false,
      remaining: 0,
      limit,
      resetAt: entry.resetAt,
      requestsToday: entry.requestsToday,
      requestsTotal: entry.requestsTotal,
    };
  }

  // Consume one request
  entry.requestsToday += 1;
  entry.requestsTotal += 1;
  entry.lastUsedAt = now;

  return {
    allowed: true,
    remaining: limit - entry.requestsToday,
    limit,
    resetAt: entry.resetAt,
    requestsToday: entry.requestsToday,
    requestsTotal: entry.requestsTotal,
  };
}
