import { NextRequest, NextResponse } from "next/server";
import { createPortalSession } from "@/lib/stripe";
import { createServiceRoleClient } from "@/lib/supabase/client";
import { cookies } from "next/headers";
import { createServerSupabaseClient } from "@/lib/supabase/client";

export async function POST(request: NextRequest) {
  try {
    // Require authenticated session — never accept customerId from the request body
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

    // Retrieve the customer ID from the database — never from the request body
    const db = createServiceRoleClient();
    const { data: dbUser, error: dbError } = await db
      .from("users")
      .select("stripe_customer_id")
      .eq("id", user.id)
      .single<{ stripe_customer_id: string | null }>();

    if (dbError || !dbUser?.stripe_customer_id) {
      return NextResponse.json(
        { error: "No billing account found. Please subscribe first." },
        { status: 404 }
      );
    }

    const session = await createPortalSession({ customerId: dbUser.stripe_customer_id });

    return NextResponse.json({ url: session.url }, { status: 200 });
  } catch (error) {
    console.error("[Stripe Portal] Error creating session:", error);
    return NextResponse.json(
      { error: "Failed to create portal session" },
      { status: 500 }
    );
  }
}
