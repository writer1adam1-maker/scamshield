// ============================================================================
// GET /auth/callback — Supabase OAuth & magic-link callback handler
// Exchanges a one-time code for a session, then redirects the user
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

export async function GET(request: NextRequest) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get("code");
  const next = searchParams.get("next") ?? "/dashboard";
  const error = searchParams.get("error");

  // Always redirect to the canonical domain, never to a Vercel preview URL
  const siteUrl = process.env.NEXT_PUBLIC_APP_URL || origin;

  if (error) {
    return NextResponse.redirect(`${siteUrl}/login?error=${encodeURIComponent(error)}`);
  }

  if (code) {
    const cookieStore = await cookies();

    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
      {
        cookies: {
          getAll() {
            return cookieStore.getAll();
          },
          setAll(cookiesToSet) {
            cookiesToSet.forEach(({ name, value, options }) =>
              cookieStore.set(name, value, options)
            );
          },
        },
      }
    );

    const { error: exchangeError } = await supabase.auth.exchangeCodeForSession(code);

    if (!exchangeError) {
      return NextResponse.redirect(`${siteUrl}${next}`);
    }

    console.error("[Auth Callback] Exchange error:", exchangeError.message);
  }

  return NextResponse.redirect(`${siteUrl}/login?error=auth_failed`);
}
