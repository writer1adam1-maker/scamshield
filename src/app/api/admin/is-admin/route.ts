// ============================================================================
// GET /api/admin/is-admin — Check if the current user is an admin
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";

export async function GET(req: NextRequest) {
  try {
    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
      { cookies: { getAll() { return req.cookies.getAll(); }, setAll() {} } }
    );

    const { data: { user } } = await supabase.auth.getUser();

    if (!user) {
      return NextResponse.json({ isAdmin: false, email: null });
    }

    const adminEmails = (process.env.ADMIN_EMAILS || "")
      .split(",")
      .map((e) => e.trim().toLowerCase())
      .filter(Boolean);

    const userEmail = (user.email || "").toLowerCase();
    const isAdmin = adminEmails.length > 0 && userEmail.length > 0 && adminEmails.includes(userEmail);

    return NextResponse.json({ isAdmin, email: user.email ?? null });
  } catch {
    return NextResponse.json({ isAdmin: false, email: null });
  }
}
