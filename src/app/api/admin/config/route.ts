// ============================================================================
// GET /api/admin/config — Get current scan limit config
// POST /api/admin/config — Update scan limits
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { createServiceRoleClient } from "@/lib/supabase/client";
import { ANONYMOUS_SCAN_LIMIT_DEFAULT, PLAN_DEFAULTS } from "@/lib/plan-config";

async function requireAdmin(req: NextRequest): Promise<boolean> {
  try {
    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
      { cookies: { getAll() { return req.cookies.getAll(); }, setAll() {} } }
    );
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return false;
    const adminEmails = (process.env.ADMIN_EMAILS || "").split(",").map((e) => e.trim().toLowerCase());
    return adminEmails.includes((user.email || "").toLowerCase());
  } catch { return false; }
}

export async function GET(req: NextRequest) {
  if (!(await requireAdmin(req))) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const db = createServiceRoleClient();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data } = await (db as any).from("app_config").select("key, value");

  const config: Record<string, number> = {
    anonymous_scan_limit: ANONYMOUS_SCAN_LIMIT_DEFAULT,
    free_rolling_limit:     PLAN_DEFAULTS.free.rollingLimit,
    starter_rolling_limit:  PLAN_DEFAULTS.starter.rollingLimit,
    pro_rolling_limit:      PLAN_DEFAULTS.pro.rollingLimit,
  };

  for (const row of (data || []) as { key: string; value: string }[]) {
    const n = parseInt(row.value, 10);
    if (!isNaN(n)) config[row.key] = n;
  }

  return NextResponse.json(config);
}

export async function POST(req: NextRequest) {
  if (!(await requireAdmin(req))) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const body = await req.json().catch(() => null);
  if (!body) return NextResponse.json({ error: "Invalid body" }, { status: 400 });

  const db = createServiceRoleClient();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const dbAny = db as any;
  const updates: Array<{ key: string; value: string }> = [];

  const allowed = ["anonymous_scan_limit", "free_rolling_limit", "starter_rolling_limit", "pro_rolling_limit"];
  for (const key of allowed) {
    if (typeof body[key] === "number" && body[key] > 0) {
      updates.push({ key, value: String(body[key]) });
    }
  }

  if (updates.length === 0) return NextResponse.json({ error: "No valid values" }, { status: 400 });
  for (const u of updates) await dbAny.from("app_config").upsert(u, { onConflict: "key" });

  return NextResponse.json({ success: true });
}
