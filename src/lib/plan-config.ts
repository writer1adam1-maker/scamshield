// ============================================================================
// Plan Configuration — scan limits, daily replenishment, referral bonuses
// All values are loaded from app_config table (admin-configurable).
// ============================================================================

import { createServiceRoleClient } from "@/lib/supabase/client";

export type Plan = "free" | "starter" | "plus" | "pro" | "business";

export interface PlanLimits {
  monthlyLimit: number;   // max scans/month (0 = unlimited)
  dailyReplenish: number; // scans added per day (up to monthlyLimit)
}

// Hard-coded defaults (used if DB not reachable)
export const PLAN_DEFAULTS: Record<Plan, PlanLimits> = {
  free:     { monthlyLimit: 50,   dailyReplenish: 1  },
  starter:  { monthlyLimit: 300,  dailyReplenish: 10 },
  plus:     { monthlyLimit: 1000, dailyReplenish: 35 },
  pro:      { monthlyLimit: 2500, dailyReplenish: 85 },
  business: { monthlyLimit: 0,    dailyReplenish: 0  }, // unlimited
};

export const REFERRAL_DEFAULTS = {
  referrerBonus: 10,   // scans referrer earns per successful referral
  referredBonus: 20,   // bonus scans new member gets on top of their plan
  maxPerDay: 5,        // max referrals per referrer per day
};

// Cache loaded from DB
let _cache: Record<string, number> | null = null;
let _cacheAt = 0;

async function loadConfig(): Promise<Record<string, number>> {
  const now = Date.now();
  if (_cache && now - _cacheAt < 60_000) return _cache;

  try {
    const db = createServiceRoleClient();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data } = await (db as any)
      .from("app_config")
      .select("key, value");

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
  if (plan === "business") return { monthlyLimit: 0, dailyReplenish: 0 };
  const cfg = await loadConfig();
  return {
    monthlyLimit:  cfg[`${plan}_monthly_limit`]    ?? PLAN_DEFAULTS[plan].monthlyLimit,
    dailyReplenish: cfg[`${plan}_daily_replenish`] ?? PLAN_DEFAULTS[plan].dailyReplenish,
  };
}

export async function getReferralConfig() {
  const cfg = await loadConfig();
  return {
    referrerBonus: cfg["referrer_bonus_scans"] ?? REFERRAL_DEFAULTS.referrerBonus,
    referredBonus: cfg["referred_bonus_scans"] ?? REFERRAL_DEFAULTS.referredBonus,
    maxPerDay:     cfg["max_referrals_per_day"]  ?? REFERRAL_DEFAULTS.maxPerDay,
  };
}

export function isPlanUnlimited(plan: Plan): boolean {
  return plan === "business";
}
