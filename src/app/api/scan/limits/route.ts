// GET /api/scan/limits — public endpoint, returns current scan limits
import { NextResponse } from "next/server";
import { createServiceRoleClient } from "@/lib/supabase/client";
import { ANONYMOUS_SCAN_LIMIT_DEFAULT, REGISTERED_SCAN_LIMIT_DEFAULT } from "@/lib/auth-helpers";

export async function GET() {
  try {
    const db = createServiceRoleClient();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data } = await (db as any)
      .from("app_config")
      .select("key, value")
      .in("key", ["anonymous_scan_limit", "registered_scan_limit"]);

    const limits = {
      anonymous_scan_limit: ANONYMOUS_SCAN_LIMIT_DEFAULT,
      registered_scan_limit: REGISTERED_SCAN_LIMIT_DEFAULT,
    };
    for (const row of (data || []) as { key: string; value: string }[]) {
      const n = parseInt(row.value, 10);
      if (!isNaN(n)) limits[row.key as keyof typeof limits] = n;
    }
    return NextResponse.json(limits);
  } catch {
    return NextResponse.json({
      anonymous_scan_limit: ANONYMOUS_SCAN_LIMIT_DEFAULT,
      registered_scan_limit: REGISTERED_SCAN_LIMIT_DEFAULT,
    });
  }
}
