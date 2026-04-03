// ============================================================================
// GET /api/admin/config — Get current scan limit config
// POST /api/admin/config — Update scan limits
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { createServiceRoleClient } from "@/lib/supabase/client";
import { ANONYMOUS_SCAN_LIMIT_DEFAULT, REGISTERED_SCAN_LIMIT_DEFAULT } from "@/lib/auth-helpers";

async function requireAdmin(req: NextRequest): Promise<boolean> {
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
    if (!user) return false;
    const adminEmails = (process.env.ADMIN_EMAILS || "").split(",").map((e) => e.trim().toLowerCase());
    return adminEmails.includes((user.email || "").toLowerCase());
  } catch {
    return false;
  }
}

export async function GET(req: NextRequest) {
  if (!(await requireAdmin(req))) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const db = createServiceRoleClient();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data } = await (db as any)
    .from("app_config")
    .select("key, value")
    .in("key", ["anonymous_scan_limit", "registered_scan_limit"]);

  const config: Record<string, number> = {
    anonymous_scan_limit: ANONYMOUS_SCAN_LIMIT_DEFAULT,
    registered_scan_limit: REGISTERED_SCAN_LIMIT_DEFAULT,
  };

  for (const row of (data || []) as { key: string; value: string }[]) {
    const n = parseInt(row.value, 10);
    if (!isNaN(n)) config[row.key] = n;
  }

  return NextResponse.json(config);
}

export async function POST(req: NextRequest) {
  if (!(await requireAdmin(req))) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const body = await req.json().catch(() => null);
  if (!body) return NextResponse.json({ error: "Invalid body" }, { status: 400 });

  const { anonymous_scan_limit, registered_scan_limit } = body as {
    anonymous_scan_limit?: number;
    registered_scan_limit?: number;
  };

  const db = createServiceRoleClient();
  const updates: Array<{ key: string; value: string }> = [];

  if (typeof anonymous_scan_limit === "number" && anonymous_scan_limit > 0) {
    updates.push({ key: "anonymous_scan_limit", value: String(anonymous_scan_limit) });
  }
  if (typeof registered_scan_limit === "number" && registered_scan_limit > 0) {
    updates.push({ key: "registered_scan_limit", value: String(registered_scan_limit) });
  }

  if (updates.length === 0) {
    return NextResponse.json({ error: "No valid values provided" }, { status: 400 });
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const dbAny = db as any;
  for (const update of updates) {
    await dbAny.from("app_config").upsert(update, { onConflict: "key" });
  }

  return NextResponse.json({ success: true });
}
