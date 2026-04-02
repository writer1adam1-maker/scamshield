import { NextRequest, NextResponse } from "next/server";
import { getStripe } from "@/lib/stripe";
import { createServiceRoleClient } from "@/lib/supabase/client";
import type { DbUser } from "@/lib/supabase/client";
import Stripe from "stripe";

type UserUpdate = Partial<DbUser>;

const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

export async function POST(request: NextRequest) {
  if (!webhookSecret) {
    console.error("[Stripe Webhook] STRIPE_WEBHOOK_SECRET is not set");
    return NextResponse.json(
      { error: "Webhook secret not configured" },
      { status: 500 }
    );
  }

  const body = await request.text();
  const signature = request.headers.get("stripe-signature");

  if (!signature) {
    return NextResponse.json(
      { error: "Missing stripe-signature header" },
      { status: 400 }
    );
  }

  let event: Stripe.Event;

  try {
    event = getStripe().webhooks.constructEvent(body, signature, webhookSecret);
  } catch (error) {
    console.error("[Stripe Webhook] Signature verification failed:", error);
    return NextResponse.json(
      { error: "Invalid webhook signature" },
      { status: 400 }
    );
  }

  try {
    const db = createServiceRoleClient();

    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object as Stripe.Checkout.Session;
        const userId = session.metadata?.userId;

        if (!userId) {
          console.warn("[Stripe Webhook] checkout.session.completed missing userId in metadata");
          break;
        }

        const updatePayload: UserUpdate = {
          plan: "pro",
          stripe_customer_id: typeof session.customer === "string" ? session.customer : null,
          stripe_subscription_id: typeof session.subscription === "string" ? session.subscription : null,
        };
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { error } = await (db as any).from("users").update(updatePayload).eq("id", userId);

        if (error) {
          console.error("[Stripe Webhook] Failed to update user on checkout:", error);
          throw error;
        }

        console.log("[Stripe Webhook] User upgraded to pro:", userId);
        break;
      }

      case "customer.subscription.updated": {
        const subscription = event.data.object as Stripe.Subscription;

        const subUpdatePayload: UserUpdate = {
          plan: subscription.status === "active" ? "pro" : "free",
        };
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { error } = await (db as any).from("users").update(subUpdatePayload).eq("stripe_subscription_id", subscription.id);

        if (error) {
          console.error("[Stripe Webhook] Failed to update subscription status:", error);
          throw error;
        }

        console.log("[Stripe Webhook] Subscription updated:", subscription.id, subscription.status);
        break;
      }

      case "customer.subscription.deleted": {
        const subscription = event.data.object as Stripe.Subscription;

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { error } = await (db as any).from("users")
          .update({ plan: "free", stripe_subscription_id: null })
          .eq("stripe_subscription_id", subscription.id);

        if (error) {
          console.error("[Stripe Webhook] Failed to downgrade on cancellation:", error);
          throw error;
        }

        console.log("[Stripe Webhook] Subscription cancelled, user downgraded:", subscription.id);
        break;
      }

      case "invoice.payment_failed": {
        // Stripe v21: Invoice.parent contains subscription context
        const invoice = event.data.object as Stripe.Invoice & { parent?: { subscription_details?: { subscription?: string } } };
        const subId = invoice.parent?.subscription_details?.subscription ?? null;

        if (subId) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          await (db as any).from("users").update({ plan: "free" }).eq("stripe_subscription_id", subId);
          console.log("[Stripe Webhook] Payment failed, user downgraded:", subId);
        }
        break;
      }

      default:
        console.log(`[Stripe Webhook] Unhandled event type: ${event.type}`);
    }

    return NextResponse.json({ received: true }, { status: 200 });
  } catch (error) {
    console.error("[Stripe Webhook] Error processing event:", error);
    return NextResponse.json(
      { error: "Webhook handler failed" },
      { status: 500 }
    );
  }
}
