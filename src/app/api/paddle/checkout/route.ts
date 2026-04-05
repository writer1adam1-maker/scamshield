import { NextRequest, NextResponse } from "next/server";
import { createCheckoutUrl } from "@/lib/paddle";
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

    const priceId = process.env.PADDLE_PRICE_ID;
    if (!priceId) {
      return NextResponse.json({ error: "Paddle price ID is not configured" }, { status: 500 });
    }

    const url = await createCheckoutUrl({
      priceId,
      customerEmail: user.email,
      userId: user.id,
    });

    return NextResponse.json({ url }, { status: 200 });
  } catch (error) {
    console.error("[Paddle Checkout] Error creating checkout:", error);
    return NextResponse.json({ error: "Failed to create checkout" }, { status: 500 });
  }
}
