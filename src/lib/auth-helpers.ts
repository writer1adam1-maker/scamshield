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

const FREE_SCAN_LIMIT = 15;
const PRO_SCAN_LIMIT = 999999;

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
 */
export function canScan(user: AuthUser | null): { allowed: boolean; remaining: number; limit: number } {
  if (!user) {
    // Anonymous users get a limited allowance (tracked by IP in rate-limit.ts)
    return { allowed: true, remaining: FREE_SCAN_LIMIT, limit: FREE_SCAN_LIMIT };
  }

  const limit = user.plan === "pro" ? PRO_SCAN_LIMIT : FREE_SCAN_LIMIT;
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
