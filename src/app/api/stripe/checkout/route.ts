import { NextRequest, NextResponse } from "next/server";
import { createCheckoutSession } from "@/lib/stripe";
import { cookies } from "next/headers";
import { createServerSupabaseClient } from "@/lib/supabase/client";

export async function POST(request: NextRequest) {
  try {
    // Require authenticated session — userId and email come from the session, not the body
    const cookieStore = await cookies();
    const supabase = createServerSupabaseClient({
      getAll: () => cookieStore.getAll(),
      set: (name, value, options) => cookieStore.set(name, value, options as Parameters<typeof cookieStore.set>[2]),
    });

    const { data: { user }, error: authError } = await supabase.auth.getUser();

    if (authError || !user) {
      return NextResponse.json(
        { error: "Authentication required" },
        { status: 401 }
      );
    }

    const priceId = process.env.STRIPE_PRO_PRICE_ID;

    if (!priceId) {
      return NextResponse.json(
        { error: "Stripe price ID is not configured" },
        { status: 500 }
      );
    }

    const session = await createCheckoutSession({
      priceId,
      customerEmail: user.email,
      userId: user.id,
    });

    return NextResponse.json({ url: session.url }, { status: 200 });
  } catch (error) {
    console.error("[Stripe Checkout] Error creating session:", error);
    return NextResponse.json(
      { error: "Failed to create checkout session" },
      { status: 500 }
    );
  }
}
