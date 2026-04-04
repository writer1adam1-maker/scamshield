// ============================================================================
// POST /api/referral/redeem — Redeem a referral code at signup
// Called once per new user after their account is created.
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { createServiceRoleClient } from "@/lib/supabase/client";
import { getReferralConfig } from "@/lib/plan-config";

export async function POST(req: NextRequest) {
  try {
    // Authenticate caller
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
    if (!user) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

    const body = await req.json().catch(() => null);
    const code = (body?.code || "").trim().toUpperCase();
    if (!code) return NextResponse.json({ error: "No referral code provided" }, { status: 400 });

    const db = createServiceRoleClient();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const dbAny = db as any;

    // Check this user hasn't already used a referral code
    const { data: selfRow } = await dbAny
      .from("users")
      .select("id, referred_by, referral_code")
      .eq("id", user.id)
      .single();

    if (selfRow?.referred_by) {
      return NextResponse.json({ error: "You have already used a referral code." }, { status: 409 });
    }

    // Find the referrer by code (not themselves)
    const { data: referrerRow } = await dbAny
      .from("users")
      .select("id, email, referral_count, scan_bonus_pool")
      .eq("referral_code", code)
      .neq("id", user.id)
      .single();

    if (!referrerRow) {
      return NextResponse.json({ error: "Invalid referral code." }, { status: 404 });
    }

    // Check daily referral limit for referrer
    const todayStart = new Date();
    todayStart.setUTCHours(0, 0, 0, 0);

    const { count: todayCount } = await dbAny
      .from("referrals")
      .select("id", { count: "exact", head: true })
      .eq("referrer_id", referrerRow.id)
      .gte("created_at", todayStart.toISOString());

    const refConfig = await getReferralConfig();

    if ((todayCount || 0) >= refConfig.maxPerDay) {
      return NextResponse.json(
        { error: "This referral code has reached its daily limit. Try again tomorrow." },
        { status: 429 }
      );
    }

    // Atomically claim the referral: update referred_by only if it's still null
    // This prevents race conditions where two concurrent requests both pass the check above
    const { count: claimCount } = await dbAny
      .from("users")
      .update({ referred_by: code, scan_bonus_pool: refConfig.referredBonus })
      .eq("id", user.id)
      .is("referred_by", null)
      .select("id", { count: "exact", head: true });

    if (!claimCount || claimCount === 0) {
      // Another concurrent request already claimed a referral for this user
      return NextResponse.json({ error: "You have already used a referral code." }, { status: 409 });
    }

    // Insert referral record (UNIQUE constraint on referred_id prevents duplicates at DB level)
    const { error: insertError } = await dbAny.from("referrals").insert({
      referrer_id: referrerRow.id,
      referred_id: user.id,
      referral_code: code,
      scans_awarded: refConfig.referredBonus,
    });

    if (insertError) {
      // Rollback the referred_by claim if referral insert fails
      await dbAny.from("users").update({ referred_by: null, scan_bonus_pool: 0 }).eq("id", user.id);
      return NextResponse.json({ error: "You have already used a referral code." }, { status: 409 });
    }

    // Award bonus scans to referrer
    await dbAny
      .from("users")
      .update({ scan_bonus_pool: (referrerRow.scan_bonus_pool || 0) + refConfig.referrerBonus })
      .eq("id", referrerRow.id);

    return NextResponse.json({
      success: true,
      bonusScans: refConfig.referredBonus,
      message: `You received ${refConfig.referredBonus} bonus scans!`,
    });
  } catch (err) {
    console.error("[referral/redeem]", err);
    return NextResponse.json({ error: "Internal error" }, { status: 500 });
  }
}
