// ============================================================================
// GET /api/admin/users — List all users with scan stats (admin only)
// DELETE /api/admin/users?id=xxx — Delete a user
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { createServiceRoleClient } from "@/lib/supabase/client";

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

  // Get all users with scan counts
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data: users, error } = await (db as any)
    .from("users")
    .select("id, email, plan, scan_count_today, scan_count_total, created_at, updated_at")
    .order("created_at", { ascending: false });

  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  // Get today's scans per user
  const today = new Date();
  today.setUTCHours(0, 0, 0, 0);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data: todayScans } = await (db as any)
    .from("scans")
    .select("user_id")
    .gte("created_at", today.toISOString())
    .not("user_id", "is", null);

  const todayCountMap: Record<string, number> = {};
  for (const s of (todayScans || []) as { user_id: string }[]) {
    todayCountMap[s.user_id] = (todayCountMap[s.user_id] || 0) + 1;
  }

  type UserRow = { id: string; email: string; plan: string; scan_count_today: number; scan_count_total: number; created_at: string; updated_at: string };
  const enriched = ((users || []) as UserRow[]).map((u) => ({
    ...u,
    scans_today_actual: todayCountMap[u.id] || 0,
  }));

  return NextResponse.json({ users: enriched });
}

export async function DELETE(req: NextRequest) {
  if (!(await requireAdmin(req))) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const { searchParams } = new URL(req.url);
  const userId = searchParams.get("id");
  if (!userId) {
    return NextResponse.json({ error: "Missing user id" }, { status: 400 });
  }

  const db = createServiceRoleClient();

  // Delete from auth (cascades to public.users via FK)
  const { error } = await db.auth.admin.deleteUser(userId);
  if (error) {
    return NextResponse.json({ error: error.message }, { status: 500 });
  }

  return NextResponse.json({ success: true });
}
