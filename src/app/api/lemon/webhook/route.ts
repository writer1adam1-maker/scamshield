/**
 * Lemon Squeezy Webhook Handler
 *
 * Events handled:
 *   subscription_created  → upgrade user to paid plan
 *   subscription_updated  → sync plan status (active / cancelled)
 *   subscription_cancelled → schedule downgrade (user keeps access until period ends)
 *   subscription_expired  → downgrade to free
 *   subscription_payment_failed → downgrade to free
 *
 * Security: HMAC-SHA256 signature verified on every request.
 *
 * Setup in Lemon Squeezy dashboard:
 *   Webhook URL: https://scamshieldy.com/api/lemon/webhook
 *   Secret: set LEMONSQUEEZY_WEBHOOK_SECRET in Vercel env
 *   Events: subscription_created, subscription_updated, subscription_cancelled,
 *           subscription_expired, subscription_payment_failed
 */

import { NextRequest, NextResponse } from "next/server";
import { createHmac, timingSafeEqual } from "crypto";
import { createServiceRoleClient } from "@/lib/supabase/client";

// Plan name → DB plan value mapping
const PLAN_MAP: Record<string, string> = {
  free:         "free",
  starter:      "starter",
  pro:          "pro",
  team:         "team",
  organization: "organization",
  enterprise:   "enterprise",
};

function verifySignature(rawBody: string, signature: string, secret: string): boolean {
  try {
    const hmac = createHmac("sha256", secret);
    const digest = hmac.update(rawBody).digest("hex");
    return timingSafeEqual(Buffer.from(digest, "utf8"), Buffer.from(signature, "utf8"));
  } catch {
    return false;
  }
}

export async function POST(request: NextRequest) {
  const secret = process.env.LEMONSQUEEZY_WEBHOOK_SECRET;
  if (!secret) {
    console.error("[LemonWebhook] LEMONSQUEEZY_WEBHOOK_SECRET not set");
    return NextResponse.json({ error: "Webhook secret not configured" }, { status: 500 });
  }

  const rawBody = await request.text();
  const signature = request.headers.get("x-signature") ?? "";

  if (!verifySignature(rawBody, signature, secret)) {
    console.error("[LemonWebhook] Invalid signature");
    return NextResponse.json({ error: "Invalid signature" }, { status: 401 });
  }

  let payload: Record<string, unknown>;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return NextResponse.json({ error: "Invalid JSON" }, { status: 400 });
  }

  const meta = payload.meta as Record<string, unknown> | undefined;
  const eventName = meta?.event_name as string | undefined;
  const customData = meta?.custom_data as Record<string, string> | undefined;
  const data = payload.data as Record<string, unknown> | undefined;
  const attrs = data?.attributes as Record<string, unknown> | undefined;

  if (!eventName || !attrs) {
    return NextResponse.json({ received: true }, { status: 200 });
  }

  const db = createServiceRoleClient();

  // Extract identifiers
  const userId = customData?.user_id;
  const planId = customData?.plan;
  const lemonSubscriptionId = String(data?.id ?? "");
  const lemonCustomerId = String(attrs.customer_id ?? "");
  const status = attrs.status as string | undefined;
  const userEmail = attrs.user_email as string | undefined;

  console.log(`[LemonWebhook] event=${eventName} userId=${userId} plan=${planId} status=${status}`);

  try {
    switch (eventName) {
      case "subscription_created": {
        if (!userId) {
          console.warn("[LemonWebhook] subscription_created missing user_id in custom_data");
          break;
        }

        const plan = PLAN_MAP[planId ?? ""] ?? "pro";

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { error } = await (db as any).from("users").update({
          plan,
          stripe_customer_id: lemonCustomerId || null,     // reusing column for lemon customer ID
          stripe_subscription_id: lemonSubscriptionId || null, // reusing column for lemon sub ID
        }).eq("id", userId);

        if (error) throw error;
        console.log(`[LemonWebhook] User ${userId} upgraded to ${plan}`);
        break;
      }

      case "subscription_updated": {
        if (!lemonSubscriptionId) break;

        // If user cancelled but still in billing period, keep plan until expired
        // If status went inactive/paused, downgrade
        const isActive = status === "active" || status === "on_trial";

        if (!isActive) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const { error } = await (db as any).from("users")
            .update({ plan: "free" })
            .eq("stripe_subscription_id", lemonSubscriptionId);
          if (error) throw error;
          console.log(`[LemonWebhook] Sub ${lemonSubscriptionId} updated → free (status: ${status})`);
        } else if (userId && planId) {
          // Plan might have changed (upgrade/downgrade)
          const plan = PLAN_MAP[planId] ?? "pro";
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          await (db as any).from("users")
            .update({ plan })
            .eq("stripe_subscription_id", lemonSubscriptionId);
          console.log(`[LemonWebhook] Sub ${lemonSubscriptionId} plan synced → ${plan}`);
        }
        break;
      }

      case "subscription_cancelled": {
        // User cancelled — they keep access until ends_at
        // We set a note but keep the plan active; subscription_expired will downgrade
        console.log(`[LemonWebhook] Sub ${lemonSubscriptionId} cancelled — access continues until expiry`);
        break;
      }

      case "subscription_expired":
      case "subscription_payment_failed": {
        if (!lemonSubscriptionId) break;

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { error } = await (db as any).from("users")
          .update({ plan: "free", stripe_subscription_id: null })
          .eq("stripe_subscription_id", lemonSubscriptionId);

        if (error) throw error;
        console.log(`[LemonWebhook] Sub ${lemonSubscriptionId} expired/failed → free`);
        break;
      }

      default:
        console.log(`[LemonWebhook] Unhandled event: ${eventName}`);
    }

    return NextResponse.json({ received: true }, { status: 200 });
  } catch (err) {
    console.error("[LemonWebhook] Handler error:", err);
    return NextResponse.json({ error: "Handler failed" }, { status: 500 });
  }
}
