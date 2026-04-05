import { NextRequest, NextResponse } from "next/server";
import { getSubscriptionManagementUrl } from "@/lib/paddle";
import { cookies } from "next/headers";
import { createServerSupabaseClient } from "@/lib/supabase/client";

export async function POST(request: NextRequest) {
  try {
    const cookieStore = await cookies();
    const supabase = createServerSupabaseClient({
      getAll: () => cookieStore.getAll(),
      set: (name, value, options) =>
        cookieStore.set(name, value, options as Parameters<typeof cookieStore.set>[2]),
    });

    const { data: { user }, error: authError } = await supabase.auth.getUser();

    if (authError || !user) {
      return NextResponse.json({ error: "Authentication required" }, { status: 401 });
    }

    // Paddle uses a hosted subscription management page — no server-side session needed
    const url = getSubscriptionManagementUrl();

    return NextResponse.json({ url }, { status: 200 });
  } catch (error) {
    console.error("[Paddle Portal] Error:", error);
    return NextResponse.json({ error: "Failed to get subscription management URL" }, { status: 500 });
  }
}
