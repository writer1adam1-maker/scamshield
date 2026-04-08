import { NextRequest, NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { createServiceRoleClient } from "@/lib/supabase/client";

async function checkAdmin(req: NextRequest): Promise<boolean> {
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    { cookies: { getAll() { return req.cookies.getAll(); }, setAll() {} } }
  );
  const { data: { user } } = await supabase.auth.getUser();
  if (!user?.email) return false;
  const adminEmails = (process.env.ADMIN_EMAILS || "").split(",").map(e => e.trim().toLowerCase()).filter(Boolean);
  return adminEmails.includes(user.email.toLowerCase());
}

export async function GET(req: NextRequest) {
  if (!await checkAdmin(req)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const db = createServiceRoleClient();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data, error } = await (db as any)
    .from("contact_messages")
    .select("*")
    .order("created_at", { ascending: false })
    .limit(100);

  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ messages: data ?? [] });
}

export async function PATCH(req: NextRequest) {
  if (!await checkAdmin(req)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const { id, read } = await req.json();
  if (!id) return NextResponse.json({ error: "Missing id" }, { status: 400 });

  const db = createServiceRoleClient();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { error } = await (db as any)
    .from("contact_messages")
    .update({ read: read ?? true })
    .eq("id", id);

  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ success: true });
}

export async function DELETE(req: NextRequest) {
  if (!await checkAdmin(req)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });

  const id = req.nextUrl.searchParams.get("id");
  if (!id) return NextResponse.json({ error: "Missing id" }, { status: 400 });

  const db = createServiceRoleClient();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { error } = await (db as any)
    .from("contact_messages")
    .delete()
    .eq("id", id);

  if (error) return NextResponse.json({ error: error.message }, { status: 500 });
  return NextResponse.json({ success: true });
}
