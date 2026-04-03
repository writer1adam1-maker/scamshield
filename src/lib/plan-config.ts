// ============================================================================
// Plan Configuration — flat 30-day rolling caps, no daily replenishment
// ============================================================================

import { createServiceRoleClient } from "@/lib/supabase/client";

export type Plan = "free" | "starter" | "pro" | "business";

export interface PlanLimits {
  rollingLimit: number; // max scans per 30-day rolling window (0 = unlimited)
}

// Defaults used if DB unreachable
export const ANONYMOUS_SCAN_LIMIT_DEFAULT = 4;

export const PLAN_DEFAULTS: Record<Plan, PlanLimits> = {
  free:     { rollingLimit: 50  },
  starter:  { rollingLimit: 200 },
  pro:      { rollingLimit: 500 },
  business: { rollingLimit: 0   }, // unlimited
};

export const REFERRAL_DEFAULTS = {
  referrerBonus: 10, // scans referrer earns per successful referral
  referredBonus: 10, // bonus scans new member gets at signup
  maxPerDay: 5,      // max referrals a single user can make per day
};

// 60-second in-process cache
let _cache: Record<string, number> | null = null;
let _cacheAt = 0;

async function loadConfig(): Promise<Record<string, number>> {
  const now = Date.now();
  if (_cache && now - _cacheAt < 60_000) return _cache;
  try {
    const db = createServiceRoleClient();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data } = await (db as any).from("app_config").select("key, value");
    const cfg: Record<string, number> = {};
    for (const row of (data || []) as { key: string; value: string }[]) {
      const n = parseInt(row.value, 10);
      if (!isNaN(n)) cfg[row.key] = n;
    }
    _cache = cfg;
    _cacheAt = now;
    return cfg;
  } catch {
    return {};
  }
}

export async function getPlanLimits(plan: Plan): Promise<PlanLimits> {
  if (plan === "business") return { rollingLimit: 0 };
  const cfg = await loadConfig();
  return {
    rollingLimit: cfg[`${plan}_rolling_limit`] ?? PLAN_DEFAULTS[plan].rollingLimit,
  };
}

export async function getReferralConfig() {
  const cfg = await loadConfig();
  return {
    referrerBonus: cfg["referrer_bonus_scans"] ?? REFERRAL_DEFAULTS.referrerBonus,
    referredBonus: cfg["referred_bonus_scans"] ?? REFERRAL_DEFAULTS.referredBonus,
    maxPerDay:     cfg["max_referrals_per_day"] ?? REFERRAL_DEFAULTS.maxPerDay,
  };
}

export function isPlanUnlimited(plan: Plan): boolean {
  return plan === "business";
}
