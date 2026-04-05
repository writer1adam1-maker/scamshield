// PATCH /api/gmail/settings — Update digest frequency preference
import { NextRequest, NextResponse } from "next/server";
import { getUserFromRequest } from "@/lib/auth-helpers";
import { createServiceRoleClient } from "@/lib/supabase/client";

const VALID_FREQUENCIES = ["hourly", "12h", "daily", "weekly", "never"];

export async function PATCH(req: NextRequest) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json();
  const frequency = body.frequency;

  if (!VALID_FREQUENCIES.includes(frequency)) {
    return NextResponse.json({ error: "Invalid frequency" }, { status: 400 });
  }

  const db = createServiceRoleClient();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { error } = await (db as any)
    .from("gmail_connections")
    .update({ digest_frequency: frequency })
    .eq("user_id", user.id)
    .eq("is_active", true);

  if (error) return NextResponse.json({ error: error.message }, { status: 500 });

  return NextResponse.json({ ok: true, frequency });
}
