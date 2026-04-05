import { NextRequest, NextResponse } from "next/server";
import { getPaddle } from "@/lib/paddle";
import { createServiceRoleClient } from "@/lib/supabase/client";

const webhookSecret = process.env.PADDLE_WEBHOOK_SECRET;

export async function POST(request: NextRequest) {
  if (!webhookSecret) {
    console.error("[Paddle Webhook] PADDLE_WEBHOOK_SECRET is not set");
    return NextResponse.json({ error: "Webhook secret not configured" }, { status: 500 });
  }

  const body = await request.text();
  const signature = request.headers.get("paddle-signature");

  if (!signature) {
    return NextResponse.json({ error: "Missing paddle-signature header" }, { status: 400 });
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let event: any;

  try {
    const paddle = getPaddle();
    event = await paddle.webhooks.unmarshal(body, webhookSecret, signature);
  } catch (error) {
    console.error("[Paddle Webhook] Signature verification failed:", error);
    return NextResponse.json({ error: "Invalid webhook signature" }, { status: 400 });
  }

  try {
    const db = createServiceRoleClient();

    switch (event.eventType) {
      case "transaction.completed": {
        const txn = event.data as { customData?: { userId?: string }; customer?: { id?: string }; subscriptionId?: string };
        const userId = txn.customData?.userId;

        if (!userId) {
          console.warn("[Paddle Webhook] transaction.completed missing userId in customData");
          break;
        }

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { error } = await (db as any).from("users").update({
          plan: "pro",
          paddle_customer_id: txn.customer?.id ?? null,
          paddle_subscription_id: txn.subscriptionId ?? null,
        }).eq("id", userId);

        if (error) {
          console.error("[Paddle Webhook] Failed to upgrade user:", error);
          throw error;
        }

        console.log("[Paddle Webhook] User upgraded to pro:", userId);
        break;
      }

      case "subscription.updated": {
        const sub = event.data as { id: string; status: string };
        const isActive = sub.status === "active" || sub.status === "trialing";

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { error } = await (db as any).from("users")
          .update({ plan: isActive ? "pro" : "free" })
          .eq("paddle_subscription_id", sub.id);

        if (error) {
          console.error("[Paddle Webhook] Failed to update subscription status:", error);
          throw error;
        }

        console.log("[Paddle Webhook] Subscription updated:", sub.id, sub.status);
        break;
      }

      case "subscription.canceled": {
        const sub = event.data as { id: string };

        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const { error } = await (db as any).from("users")
          .update({ plan: "free", paddle_subscription_id: null })
          .eq("paddle_subscription_id", sub.id);

        if (error) {
          console.error("[Paddle Webhook] Failed to downgrade on cancellation:", error);
          throw error;
        }

        console.log("[Paddle Webhook] Subscription cancelled, user downgraded:", sub.id);
        break;
      }

      default:
        console.log(`[Paddle Webhook] Unhandled event type: ${event.eventType}`);
    }

    return NextResponse.json({ received: true }, { status: 200 });
  } catch (error) {
    console.error("[Paddle Webhook] Error processing event:", error);
    return NextResponse.json({ error: "Webhook handler failed" }, { status: 500 });
  }
}
