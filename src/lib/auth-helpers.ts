// ============================================================================
// Auth Helpers — rolling 30-day scan quota, referral bonus pool
// ============================================================================

import { NextRequest } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { createServiceRoleClient } from "@/lib/supabase/client";
import { getPlanLimits, isPlanUnlimited, type Plan } from "@/lib/plan-config";

export interface AuthUser {
  id: string;
  email: string;
  plan: Plan;
  scanCountTotal: number;
  scanCountPeriod: number;  // scans used in current 30-day window
  scanBonusPool: number;    // referral bonus scans (never expire)
  periodStart: string | null; // when the current 30-day window started
}

export const ANONYMOUS_SCAN_LIMIT_DEFAULT = 4;

// Cache for anon IP limit
let _dynamicAnonLimit = ANONYMOUS_SCAN_LIMIT_DEFAULT;
let _anonLimitLoadedAt = 0;

export async function getScanLimits(): Promise<{ anonLimit: number }> {
  const now = Date.now();
  if (now - _anonLimitLoadedAt < 60_000) return { anonLimit: _dynamicAnonLimit };
  try {
    const db = createServiceRoleClient();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data } = await (db as any)
      .from("app_config").select("key, value").in("key", ["anonymous_scan_limit"]);
    for (const row of (data || []) as { key: string; value: string }[]) {
      const n = parseInt(row.value, 10);
      if (!isNaN(n)) _dynamicAnonLimit = n;
    }
  } catch { /* use default */ }
  _anonLimitLoadedAt = now;
  return { anonLimit: _dynamicAnonLimit };
}

export async function getUserFromRequest(req: NextRequest): Promise<AuthUser | null> {
  try {
    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
      { cookies: { getAll() { return req.cookies.getAll(); }, setAll() {} } }
    );
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return null;

    const db = createServiceRoleClient();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data } = await (db as any)
      .from("users")
      .select("plan, scan_count_total, scan_count_month, scan_bonus_pool, last_month_reset")
      .eq("id", user.id)
      .single();

    const row = data as {
      plan?: string;
      scan_count_total?: number;
      scan_count_month?: number;
      scan_bonus_pool?: number;
      last_month_reset?: string;
    } | null;

    return {
      id: user.id,
      email: user.email || "",
      plan: (row?.plan as Plan) || "free",
      scanCountTotal: row?.scan_count_total ?? 0,
      scanCountPeriod: row?.scan_count_month ?? 0,
      scanBonusPool: row?.scan_bonus_pool ?? 0,
      periodStart: row?.last_month_reset || null,
    };
  } catch {
    return null;
  }
}

/**
 * Returns whether a user can scan, based on rolling 30-day window.
 * Business = unlimited. Bonus pool stacks on top of plan cap.
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

  // Rolling 30-day window: reset if period started more than 30 days ago
  const now = Date.now();
  const periodStart = user.periodStart ? new Date(user.periodStart).getTime() : 0;
  const isNewPeriod = now - periodStart >= 30 * 24 * 60 * 60 * 1000;

  const periodUsed = isNewPeriod ? 0 : user.scanCountPeriod;
  const totalAvailable = limits.rollingLimit + user.scanBonusPool;
  const remaining = Math.max(0, totalAvailable - periodUsed);

  return { allowed: remaining > 0, remaining, limit: totalAvailable };
}

/**
 * Increment scan count after a successful scan.
 * Handles rolling 30-day period reset automatically.
 */
export async function incrementScanCount(userId: string): Promise<void> {
  try {
    const db = createServiceRoleClient();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const dbAny = db as any;

    const { data } = await dbAny
      .from("users")
      .select("plan, scan_count_total, scan_count_month, scan_bonus_pool, last_month_reset")
      .eq("id", userId)
      .single();

    const row = data as {
      plan?: string;
      scan_count_total?: number;
      scan_count_month?: number;
      scan_bonus_pool?: number;
      last_month_reset?: string;
    } | null;
    if (!row) return;

    const now = Date.now();
    const plan = (row.plan || "free") as Plan;
    const periodStart = row.last_month_reset ? new Date(row.last_month_reset).getTime() : 0;
    const isNewPeriod = now - periodStart >= 30 * 24 * 60 * 60 * 1000;

    let periodCount = isNewPeriod ? 1 : (row.scan_count_month || 0) + 1;
    const totalCount = (row.scan_count_total || 0) + 1;
    let bonusPool = row.scan_bonus_pool || 0;

    // If over plan cap, consume from bonus pool
    if (!isPlanUnlimited(plan)) {
      const limits = await getPlanLimits(plan);
      if (limits.rollingLimit > 0 && periodCount > limits.rollingLimit && bonusPool > 0) {
        bonusPool = Math.max(0, bonusPool - 1);
        periodCount = periodCount; // count still increments for tracking
      }
    }

    const updates: Record<string, unknown> = {
      scan_count_total: totalCount,
      scan_count_month: periodCount,
      scan_bonus_pool: bonusPool,
    };
    if (isNewPeriod) updates.last_month_reset = new Date(now).toISOString();

    await dbAny.from("users").update(updates).eq("id", userId);
  } catch {
    // Non-blocking
  }
}
