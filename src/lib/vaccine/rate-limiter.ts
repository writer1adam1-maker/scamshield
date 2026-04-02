/**
 * API Rate Limiter for Vaccine Endpoints
 *
 * Prevents abuse of the scan endpoint as a free proxy and DoS attacks.
 * Uses sliding-window counter per IP with configurable limits.
 */

interface RateLimitEntry {
  count: number;
  windowStart: number;
}

const WINDOW_MS = 60 * 1000;  // 1-minute sliding window
const MAX_REQUESTS_PER_WINDOW = 10; // 10 requests per minute per IP
const MAX_SCAN_REQUESTS_PER_HOUR = 60; // 60 scans per hour per IP
const HOUR_MS = 60 * 60 * 1000;

// In-memory stores (in production, use Redis or Vercel KV)
const minuteWindow = new Map<string, RateLimitEntry>();
const hourWindow = new Map<string, RateLimitEntry>();
const abuseFlags = new Map<string, { count: number; flaggedAt: number }>();

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  retryAfterMs: number;
  reason?: string;
}

/**
 * Check if a request from this IP is within rate limits.
 */
export function checkRateLimit(ip: string, endpoint: string = 'scan'): RateLimitResult {
  const now = Date.now();
  const key = `${ip}:${endpoint}`;

  // Check abuse flag first
  const abuse = abuseFlags.get(ip);
  if (abuse && abuse.count >= 3 && (now - abuse.flaggedAt) < HOUR_MS) {
    return {
      allowed: false,
      remaining: 0,
      retryAfterMs: HOUR_MS - (now - abuse.flaggedAt),
      reason: 'Temporarily blocked due to excessive requests',
    };
  }

  // Minute window check
  const minuteEntry = minuteWindow.get(key);
  if (minuteEntry) {
    if (now - minuteEntry.windowStart < WINDOW_MS) {
      if (minuteEntry.count >= MAX_REQUESTS_PER_WINDOW) {
        flagAbuse(ip, now);
        return {
          allowed: false,
          remaining: 0,
          retryAfterMs: WINDOW_MS - (now - minuteEntry.windowStart),
          reason: 'Rate limit exceeded (per minute)',
        };
      }
      minuteEntry.count++;
    } else {
      minuteWindow.set(key, { count: 1, windowStart: now });
    }
  } else {
    minuteWindow.set(key, { count: 1, windowStart: now });
  }

  // Hour window check (for scan endpoint)
  if (endpoint === 'scan') {
    const hourKey = `${ip}:hour`;
    const hourEntry = hourWindow.get(hourKey);
    if (hourEntry) {
      if (now - hourEntry.windowStart < HOUR_MS) {
        if (hourEntry.count >= MAX_SCAN_REQUESTS_PER_HOUR) {
          return {
            allowed: false,
            remaining: 0,
            retryAfterMs: HOUR_MS - (now - hourEntry.windowStart),
            reason: 'Hourly scan limit exceeded',
          };
        }
        hourEntry.count++;
      } else {
        hourWindow.set(hourKey, { count: 1, windowStart: now });
      }
    } else {
      hourWindow.set(hourKey, { count: 1, windowStart: now });
    }
  }

  const current = minuteWindow.get(key);
  return {
    allowed: true,
    remaining: MAX_REQUESTS_PER_WINDOW - (current?.count || 0),
    retryAfterMs: 0,
  };
}

function flagAbuse(ip: string, now: number): void {
  const existing = abuseFlags.get(ip);
  if (existing) {
    existing.count++;
  } else {
    abuseFlags.set(ip, { count: 1, flaggedAt: now });
  }
}

// Periodic cleanup (every 5 minutes)
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of minuteWindow) {
    if (now - entry.windowStart > WINDOW_MS * 2) minuteWindow.delete(key);
  }
  for (const [key, entry] of hourWindow) {
    if (now - entry.windowStart > HOUR_MS * 2) hourWindow.delete(key);
  }
  for (const [ip, flag] of abuseFlags) {
    if (now - flag.flaggedAt > HOUR_MS) abuseFlags.delete(ip);
  }
}, 5 * 60 * 1000);
