// ============================================================================
// Plan Configuration — flat 30-day rolling caps, no daily replenishment
// ============================================================================

import { createServiceRoleClient } from "@/lib/supabase/client";

export type Plan = "free" | "starter" | "pro" | "team" | "organization" | "enterprise";

export interface PlanLimits {
  rollingLimit: number; // max scans per 30-day rolling window (0 = unlimited)
  seats: number;        // max team seats (1 = individual)
  apiAccess: boolean;
}

// Defaults used if DB unreachable
export const ANONYMOUS_SCAN_LIMIT_DEFAULT = 4;

export const PLAN_DEFAULTS: Record<Plan, PlanLimits> = {
  free:         { rollingLimit: 50,      seats: 1,  apiAccess: false },
  starter:      { rollingLimit: 200,     seats: 1,  apiAccess: false },
  pro:          { rollingLimit: 500,     seats: 1,  apiAccess: false },
  team:         { rollingLimit: 5000,    seats: 5,  apiAccess: true  },
  organization: { rollingLimit: 20000,   seats: 15, apiAccess: true  },
  enterprise:   { rollingLimit: 100000,  seats: 999, apiAccess: true },
};

export const PLAN_PRICES: Record<Plan, { monthly: number; annual: number }> = {
  free:         { monthly: 0,    annual: 0     },
  starter:      { monthly: 4.99, annual: 3.99  },
  pro:          { monthly: 12.99, annual: 10.49 },
  team:         { monthly: 49,   annual: 39    },
  organization: { monthly: 149,  annual: 119   },
  enterprise:   { monthly: 399,  annual: 319   },
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
  const defaults = PLAN_DEFAULTS[plan];
  // enterprise and organization/team use fixed limits from PLAN_DEFAULTS
  // but allow admin override for rolling limit via app_config
  const cfg = await loadConfig();
  const rollingKey = `${plan}_rolling_limit`;
  return {
    ...defaults,
    rollingLimit: cfg[rollingKey] ?? defaults.rollingLimit,
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

export function isPlanUnlimited(_plan: Plan): boolean {
  // No plan is truly unlimited anymore — enterprise has 100k cap
  return false;
}

// Plans that get API access
export function hasApiAccess(plan: Plan): boolean {
  return PLAN_DEFAULTS[plan].apiAccess;
}
