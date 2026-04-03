// ============================================================================
// Auth Helpers — Extract user + plan from API route requests
// ============================================================================

import { NextRequest } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { createServiceRoleClient } from "@/lib/supabase/client";
import { getPlanLimits, isPlanUnlimited, type Plan } from "@/lib/plan-config";

export interface AuthUser {
  id: string;
  email: string;
  plan: Plan;
  scanCountToday: number;
  scanCountTotal: number;
  scanCountMonth: number;
  scanBonusPool: number;
  lastMonthReset: string | null;
  updatedAt: string | null;
}

// Anonymous limits (IP-based, from app_config)
export const ANONYMOUS_SCAN_LIMIT_DEFAULT = 4;
export const REGISTERED_SCAN_LIMIT_DEFAULT = 50; // free plan monthly

// Legacy compat — used by rate-limit.ts setter
let _dynamicAnonLimit = ANONYMOUS_SCAN_LIMIT_DEFAULT;
let _anonLimitLoadedAt = 0;

export async function getScanLimits(): Promise<{ anonLimit: number; registeredLimit: number }> {
  const now = Date.now();
  if (now - _anonLimitLoadedAt < 60_000) {
    return { anonLimit: _dynamicAnonLimit, registeredLimit: REGISTERED_SCAN_LIMIT_DEFAULT };
  }
  try {
    const db = createServiceRoleClient();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data } = await (db as any)
      .from("app_config")
      .select("key, value")
      .in("key", ["anonymous_scan_limit"]);
    if (data) {
      for (const row of data as { key: string; value: string }[]) {
        const n = parseInt(row.value, 10);
        if (!isNaN(n) && row.key === "anonymous_scan_limit") _dynamicAnonLimit = n;
      }
    }
  } catch { /* use defaults */ }
  _anonLimitLoadedAt = now;
  return { anonLimit: _dynamicAnonLimit, registeredLimit: REGISTERED_SCAN_LIMIT_DEFAULT };
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
          getAll() { return req.cookies.getAll(); },
          setAll() {},
        },
      }
    );

    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return null;

    const db = createServiceRoleClient();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data } = await (db as any)
      .from("users")
      .select("plan, scan_count_today, scan_count_total, scan_count_month, scan_bonus_pool, last_month_reset, updated_at")
      .eq("id", user.id)
      .single();

    const dbUser = data as {
      plan?: string;
      scan_count_today?: number;
      scan_count_total?: number;
      scan_count_month?: number;
      scan_bonus_pool?: number;
      last_month_reset?: string;
      updated_at?: string;
    } | null;

    return {
      id: user.id,
      email: user.email || "",
      plan: (dbUser?.plan as Plan) || "free",
      scanCountToday: dbUser?.scan_count_today ?? 0,
      scanCountTotal: dbUser?.scan_count_total ?? 0,
      scanCountMonth: dbUser?.scan_count_month ?? 0,
      scanBonusPool: dbUser?.scan_bonus_pool ?? 0,
      lastMonthReset: dbUser?.last_month_reset || null,
      updatedAt: dbUser?.updated_at || null,
    };
  } catch {
    return null;
  }
}

/**
 * Check if user can perform a scan based on plan monthly cap + bonus pool.
 * Business plan = unlimited.
 */
export async function canScan(
  user: AuthUser | null,
): Promise<{ allowed: boolean; remaining: number; limit: number }> {
  if (!user) {
    return { allowed: true, remaining: ANONYMOUS_SCAN_LIMIT_DEFAULT, limit: ANONYMOUS_SCAN_LIMIT_DEFAULT };
  }

  if (isPlanUnlimited(user.plan)) {
    return { allowed: true, remaining: 999999, limit: 999999 };
  }

  const limits = await getPlanLimits(user.plan);

  // Check if monthly counter needs reset
  const now = new Date();
  const lastReset = user.lastMonthReset ? new Date(user.lastMonthReset) : new Date(0);
  const isNewMonth =
    lastReset.getUTCFullYear() !== now.getUTCFullYear() ||
    lastReset.getUTCMonth() !== now.getUTCMonth();

  const monthCount = isNewMonth ? 0 : user.scanCountMonth;
  const totalAvailable = limits.monthlyLimit + user.scanBonusPool;
  const remaining = Math.max(0, totalAvailable - monthCount);

  return {
    allowed: remaining > 0,
    remaining,
    limit: totalAvailable,
  };
}

/**
 * Increment scan count after successful scan.
 * Handles: daily reset, monthly reset, daily replenishment.
 */
export async function incrementScanCount(userId: string): Promise<void> {
  try {
    const db = createServiceRoleClient();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const dbAny = db as any;

    const { data } = await dbAny
      .from("users")
      .select("plan, scan_count_today, scan_count_total, scan_count_month, scan_bonus_pool, last_month_reset, updated_at")
      .eq("id", userId)
      .single();

    const userRow = data as {
      plan?: string;
      scan_count_today?: number;
      scan_count_total?: number;
      scan_count_month?: number;
      scan_bonus_pool?: number;
      last_month_reset?: string;
      updated_at?: string;
    } | null;

    if (!userRow) return;

    const now = new Date();
    const plan = (userRow.plan || "free") as Plan;

    // --- Day reset ---
    const lastUpdate = new Date(userRow.updated_at || 0);
    const isNewDay =
      lastUpdate.getUTCFullYear() !== now.getUTCFullYear() ||
      lastUpdate.getUTCMonth() !== now.getUTCMonth() ||
      lastUpdate.getUTCDate() !== now.getUTCDate();

    // --- Month reset ---
    const lastReset = userRow.last_month_reset ? new Date(userRow.last_month_reset) : new Date(0);
    const isNewMonth =
      lastReset.getUTCFullYear() !== now.getUTCFullYear() ||
      lastReset.getUTCMonth() !== now.getUTCMonth();

    let newDayCount = isNewDay ? 0 : (userRow.scan_count_today || 0);
    let newMonthCount = isNewMonth ? 0 : (userRow.scan_count_month || 0);
    let newBonusPool = userRow.scan_bonus_pool || 0;

    // --- Daily replenishment (add scans at start of new day, up to monthly limit) ---
    if (isNewDay && !isPlanUnlimited(plan)) {
      const limits = await getPlanLimits(plan);
      if (limits.monthlyLimit > 0) {
        const currentUsed = isNewMonth ? 0 : (userRow.scan_count_month || 0);
        const capacityLeft = limits.monthlyLimit - currentUsed;
        // Replenish up to dailyReplenish scans, but only if there's capacity left
        // (We don't add to monthly count here — replenish is pre-loaded into today's counter)
        newDayCount = Math.max(0, Math.min(limits.dailyReplenish, capacityLeft));
      }
    }

    // Consume one scan from today's counter
    newDayCount += 1;
    newMonthCount += 1;
    const newTotal = (userRow.scan_count_total || 0) + 1;

    // If month count exceeded monthly limit, consume from bonus pool
    if (!isPlanUnlimited(plan)) {
      const limits = await getPlanLimits(plan);
      if (limits.monthlyLimit > 0 && newMonthCount > limits.monthlyLimit && newBonusPool > 0) {
        newBonusPool = Math.max(0, newBonusPool - 1);
      }
    }

    const updates: Record<string, unknown> = {
      scan_count_today: newDayCount,
      scan_count_total: newTotal,
      scan_count_month: newMonthCount,
      scan_bonus_pool: newBonusPool,
    };
    if (isNewMonth) updates.last_month_reset = now.toISOString();

    await dbAny.from("users").update(updates).eq("id", userId);
  } catch {
    // Non-blocking
  }
}
