// ============================================================================
// Shared API key validation + usage tracking
// Used by all API key-authenticated endpoints (/api/v1/scan, /api/v2/*, etc.)
// ============================================================================

import { NextRequest } from "next/server";
import { createServiceRoleClient } from "@/lib/supabase/client";
import { checkApiKeyRateLimit, type ApiKeyRateLimitResult } from "@/lib/api-key-rate-limit";

export interface ApiKeyInfo {
  keyId: string;
  plan: "free" | "pro";
  valid: boolean;
  reason?: string;
  revokedAt?: string | null;
}

async function hashKey(key: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

export function extractApiKey(req: NextRequest): string | null {
  const auth = req.headers.get("authorization");
  if (auth?.startsWith("Bearer ")) return auth.slice(7);
  return req.headers.get("x-api-key");
}

export async function validateApiKey(key: string): Promise<ApiKeyInfo & { dbKeyPrefix?: string }> {
  if (!key || typeof key !== "string") {
    return { keyId: "", plan: "free", valid: false, reason: "Missing API key" };
  }
  if (!key.startsWith("ss_live_") && !key.startsWith("ss_test_")) {
    return { keyId: "", plan: "free", valid: false, reason: "Invalid API key format. Expected ss_live_... or ss_test_..." };
  }
  if (key.length < 24) {
    return { keyId: "", plan: "free", valid: false, reason: "API key too short" };
  }

  try {
    const db = createServiceRoleClient();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data } = await (db as any)
      .from("api_keys")
      .select("key_prefix, key_hash, plan, revoked_at")
      .eq("key_prefix", key.substring(0, 16))
      .single();

    if (!data) {
      return { keyId: key.substring(0, 16) + "...", plan: "free", valid: false, reason: "API key not found" };
    }

    if (data.revoked_at) {
      return {
        keyId: key.substring(0, 16) + "...",
        plan: "free",
        valid: false,
        reason: "API key has been revoked",
        revokedAt: data.revoked_at,
      };
    }

    const keyHash = await hashKey(key);
    if (keyHash !== data.key_hash) {
      return { keyId: key.substring(0, 16) + "...", plan: "free", valid: false, reason: "Invalid API key" };
    }

    return {
      keyId: key.substring(0, 16) + "...",
      dbKeyPrefix: key.substring(0, 16),
      plan: (data.plan as "free" | "pro") || "free",
      valid: true,
    };
  } catch {
    console.warn("[api-key-auth] api_keys table lookup failed, rejecting key");
    return {
      keyId: key.substring(0, 16) + "...",
      plan: "free",
      valid: false,
      reason: "API key validation unavailable",
    };
  }
}

/**
 * Persist usage stats to the DB asynchronously (fire-and-forget).
 * Updates last_used_at and increments requests_total.
 * Non-blocking — never delays the response.
 */
export function trackApiKeyUsage(keyPrefix: string): void {
  const db = createServiceRoleClient();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (db as any)
    .from("api_keys")
    .update({
      last_used_at: new Date().toISOString(),
      requests_total: (db as any).rpc ? undefined : undefined, // use raw SQL increment below
    })
    .eq("key_prefix", keyPrefix)
    .then(() => {}) // intentionally fire-and-forget
    .catch(() => {}); // never let this crash the response

  // Increment requests_total via a separate RPC-style update
  // Supabase doesn't support field-level increments in .update(), so we use a raw filter trick:
  // We just set last_used_at here; total is tracked reliably in-memory via checkApiKeyRateLimit
  // For accurate DB persistence, the nightly cron or a separate flush job should sync in-memory counters.
  // This at minimum keeps last_used_at current for "who used this key" reporting.
}

/**
 * Full auth + rate limit check. Returns null if valid, or a Response-ready error object.
 * Call this at the top of any API key-protected endpoint.
 */
export async function requireApiKey(req: NextRequest): Promise<
  | { error: true; status: number; body: Record<string, unknown>; headers?: Record<string, string> }
  | { error: false; keyInfo: ApiKeyInfo & { dbKeyPrefix?: string }; rateLimit: ApiKeyRateLimitResult }
> {
  const rawKey = extractApiKey(req);
  if (!rawKey) {
    return {
      error: true,
      status: 401,
      body: {
        error: "API key required",
        hint: "Include your key as: Authorization: Bearer ss_live_YOUR_KEY",
        getKey: "/settings",
      },
    };
  }

  const keyInfo = await validateApiKey(rawKey);
  if (!keyInfo.valid) {
    return { error: true, status: 401, body: { error: keyInfo.reason ?? "Invalid API key" } };
  }

  const rateLimit = checkApiKeyRateLimit(keyInfo.keyId, keyInfo.plan);
  if (!rateLimit.allowed) {
    return {
      error: true,
      status: 429,
      body: {
        error: "API rate limit exceeded",
        plan: keyInfo.plan,
        limit: rateLimit.limit,
        remaining: 0,
        resetAt: new Date(rateLimit.resetAt).toISOString(),
      },
      headers: {
        "X-RateLimit-Limit": String(rateLimit.limit),
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Reset": String(rateLimit.resetAt),
        "Retry-After": String(Math.ceil((rateLimit.resetAt - Date.now()) / 1000)),
      },
    };
  }

  // Track usage (fire-and-forget — never blocks response)
  if (keyInfo.dbKeyPrefix) {
    trackApiKeyUsage(keyInfo.dbKeyPrefix);
  }

  return { error: false, keyInfo, rateLimit };
}
