// GET /api/scan/limits — public endpoint, returns current scan limits
import { NextResponse } from "next/server";
import { createServiceRoleClient } from "@/lib/supabase/client";
import { ANONYMOUS_SCAN_LIMIT_DEFAULT, PLAN_DEFAULTS } from "@/lib/plan-config";

export async function GET() {
  try {
    const db = createServiceRoleClient();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data } = await (db as any).from("app_config").select("key, value");

    const limits: Record<string, number> = {
      anonymous_scan_limit:        ANONYMOUS_SCAN_LIMIT_DEFAULT,
      free_rolling_limit:          PLAN_DEFAULTS.free.rollingLimit,
      starter_rolling_limit:       PLAN_DEFAULTS.starter.rollingLimit,
      pro_rolling_limit:           PLAN_DEFAULTS.pro.rollingLimit,
      team_rolling_limit:          PLAN_DEFAULTS.team.rollingLimit,
      organization_rolling_limit:  PLAN_DEFAULTS.organization.rollingLimit,
      enterprise_rolling_limit:    PLAN_DEFAULTS.enterprise.rollingLimit,
    };

    for (const row of (data || []) as { key: string; value: string }[]) {
      const n = parseInt(row.value, 10);
      if (!isNaN(n) && row.key in limits) {
        limits[row.key] = n;
      }
    }
    return NextResponse.json(limits);
  } catch {
    return NextResponse.json({
      anonymous_scan_limit:        ANONYMOUS_SCAN_LIMIT_DEFAULT,
      free_rolling_limit:          PLAN_DEFAULTS.free.rollingLimit,
      starter_rolling_limit:       PLAN_DEFAULTS.starter.rollingLimit,
      pro_rolling_limit:           PLAN_DEFAULTS.pro.rollingLimit,
      team_rolling_limit:          PLAN_DEFAULTS.team.rollingLimit,
      organization_rolling_limit:  PLAN_DEFAULTS.organization.rollingLimit,
      enterprise_rolling_limit:    PLAN_DEFAULTS.enterprise.rollingLimit,
    });
  }
}
