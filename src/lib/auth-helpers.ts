// ============================================================================
// Auth Helpers — Extract user + plan from API route requests
// ============================================================================

import { NextRequest } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { createServiceRoleClient } from "@/lib/supabase/client";

export interface AuthUser {
  id: string;
  email: string;
  plan: "free" | "pro";
  scanCountToday: number;
  scanCountTotal: number;
}

export const ANONYMOUS_SCAN_LIMIT_DEFAULT = 4;
export const REGISTERED_SCAN_LIMIT_DEFAULT = 10;
const PRO_SCAN_LIMIT = 999999;

// In-process cache for admin-configurable limits (refreshed every 60s)
let _dynamicAnonLimit: number | null = null;
let _dynamicRegisteredLimit: number | null = null;
let _limitsLoadedAt = 0;

async function getDynamicLimits(): Promise<{ anonLimit: number; registeredLimit: number }> {
  const now = Date.now();
  if (now - _limitsLoadedAt < 60_000 && _dynamicAnonLimit !== null) {
    return { anonLimit: _dynamicAnonLimit, registeredLimit: _dynamicRegisteredLimit! };
  }
  try {
    const db = createServiceRoleClient();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data } = await (db as any)
      .from("app_config")
      .select("key, value")
      .in("key", ["anonymous_scan_limit", "registered_scan_limit"]);
    if (data) {
      for (const row of data as { key: string; value: string }[]) {
        const n = parseInt(row.value, 10);
        if (!isNaN(n)) {
          if (row.key === "anonymous_scan_limit") _dynamicAnonLimit = n;
          if (row.key === "registered_scan_limit") _dynamicRegisteredLimit = n;
        }
      }
    }
  } catch {
    // Fall back to defaults
  }
  if (!_dynamicAnonLimit) _dynamicAnonLimit = ANONYMOUS_SCAN_LIMIT_DEFAULT;
  if (!_dynamicRegisteredLimit) _dynamicRegisteredLimit = REGISTERED_SCAN_LIMIT_DEFAULT;
  _limitsLoadedAt = now;
  return { anonLimit: _dynamicAnonLimit, registeredLimit: _dynamicRegisteredLimit };
}

export async function getScanLimits() {
  return getDynamicLimits();
}

/**
 * Extract authenticated user from request cookies.
 * Returns null if not authenticated (anonymous scan).
 */
export async function getUserFromRequest(req: NextRequest): Promise<AuthUser | null> {
  try {
    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
      {
        cookies: {
          getAll() {
            return req.cookies.getAll();
          },
          setAll() {
            // Can't set cookies in API route GET/POST — ignore
          },
        },
      }
    );

    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return null;

    // Fetch plan + scan counts from users table (service role to bypass RLS)
    const db = createServiceRoleClient();
    const { data } = await db
      .from("users")
      .select("plan, scan_count_today, scan_count_total")
      .eq("id", user.id)
      .single();

    const dbUser = data as { plan?: string; scan_count_today?: number; scan_count_total?: number } | null;

    return {
      id: user.id,
      email: user.email || "",
      plan: (dbUser?.plan as "free" | "pro") || "free",
      scanCountToday: dbUser?.scan_count_today ?? 0,
      scanCountTotal: dbUser?.scan_count_total ?? 0,
    };
  } catch {
    return null;
  }
}

/**
 * Check if user can perform a scan based on plan and daily quota.
 * registeredLimit must be passed in (fetched async via getScanLimits).
 */
export function canScan(
  user: AuthUser | null,
  registeredLimit: number = REGISTERED_SCAN_LIMIT_DEFAULT,
): { allowed: boolean; remaining: number; limit: number } {
  if (!user) {
    // Anonymous users — tracked by IP in rate-limit.ts; return defaults here
    return { allowed: true, remaining: ANONYMOUS_SCAN_LIMIT_DEFAULT, limit: ANONYMOUS_SCAN_LIMIT_DEFAULT };
  }

  const limit = user.plan === "pro" ? PRO_SCAN_LIMIT : registeredLimit;
  const remaining = Math.max(0, limit - user.scanCountToday);

  return {
    allowed: remaining > 0,
    remaining,
    limit,
  };
}

/**
 * Increment scan count for a user after successful scan.
 * Also resets daily counter if it's a new day.
 */
export async function incrementScanCount(userId: string): Promise<void> {
  try {
    const db = createServiceRoleClient();

    // Use RPC or raw SQL to atomically increment
    // Supabase doesn't support increment directly, so we do read+write
    const { data } = await db
      .from("users")
      .select("scan_count_today, scan_count_total, updated_at")
      .eq("id", userId)
      .single();

    const userRow = data as { scan_count_today?: number; scan_count_total?: number; updated_at?: string } | null;
    if (!userRow) return;

    // Check if we need to reset the daily counter (new UTC day)
    const lastUpdate = new Date(userRow.updated_at || 0);
    const now = new Date();
    const isNewDay =
      lastUpdate.getUTCFullYear() !== now.getUTCFullYear() ||
      lastUpdate.getUTCMonth() !== now.getUTCMonth() ||
      lastUpdate.getUTCDate() !== now.getUTCDate();

    const newDayCount = isNewDay ? 1 : (userRow.scan_count_today || 0) + 1;
    const newTotalCount = (userRow.scan_count_total || 0) + 1;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    await (db as any)
      .from("users")
      .update({
        scan_count_today: newDayCount,
        scan_count_total: newTotalCount,
      })
      .eq("id", userId);
  } catch {
    // Non-blocking — don't fail the scan if count update fails
  }
}
