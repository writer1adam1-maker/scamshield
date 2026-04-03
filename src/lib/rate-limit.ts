// ============================================================================
// In-Memory Rate Limiter
// ============================================================================
// Tracks scan counts per IP per day. Resets automatically at midnight UTC.
// In production, replace with Redis or Supabase-backed limiter.
//
// NOTE: x-forwarded-for is only trustworthy when running behind a reverse proxy
// (e.g. Vercel, Cloudflare, nginx). In other environments it can be spoofed by
// the client. Do NOT rely on it for security-critical decisions without a trusted
// proxy chain.

interface RateLimitEntry {
  count: number;
  resetAt: number; // Unix timestamp (ms) when the day resets
  createdAt: number; // Unix timestamp (ms) when this entry was created
}

// Default anonymous limit — overridden at runtime via setAnonRateLimit()
let _anonLimit = 4;
export function setAnonRateLimit(n: number) { _anonLimit = n; }
const MAX_STORE_SIZE = 10_000;
const store = new Map<string, RateLimitEntry>();

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

/**
 * Clean up expired entries periodically to prevent memory leaks.
 * Runs at most once every 60 seconds.
 */
let lastCleanup = 0;
function cleanupExpired() {
  const now = Date.now();
  if (now - lastCleanup < 60_000) return;
  lastCleanup = now;

  for (const [key, entry] of store) {
    if (now >= entry.resetAt) {
      store.delete(key);
    }
  }
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  limit: number;
  resetAt: number;
}

/**
 * Check and consume one scan for the given IP.
 * Pro users bypass the limit entirely.
 */
export function checkRateLimit(ip: string, isPro: boolean): RateLimitResult {
  cleanupExpired();

  if (isPro) {
    return {
      allowed: true,
      remaining: 999999,
      limit: 999999,
      resetAt: 0,
    };
  }

  const now = Date.now();
  let entry = store.get(ip);

  // Reset if the day has rolled over
  if (!entry || now >= entry.resetAt) {
    entry = { count: 0, resetAt: getResetTimestamp(), createdAt: now };
    store.set(ip, entry);
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

  const remaining = Math.max(0, _anonLimit - entry.count);

  if (entry.count >= _anonLimit) {
    return {
      allowed: false,
      remaining: 0,
      limit: _anonLimit,
      resetAt: entry.resetAt,
    };
  }

  // Consume one scan
  entry.count += 1;

  return {
    allowed: true,
    remaining: _anonLimit - entry.count,
    limit: _anonLimit,
    resetAt: entry.resetAt,
  };
}
