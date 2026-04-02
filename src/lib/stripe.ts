import Stripe from "stripe";

let _stripe: Stripe | null = null;

export function getStripe(): Stripe {
  if (!_stripe) {
    if (!process.env.STRIPE_SECRET_KEY) {
      throw new Error("STRIPE_SECRET_KEY is not set in environment variables");
    }
    _stripe = new Stripe(process.env.STRIPE_SECRET_KEY, {
      apiVersion: "2026-03-25.dahlia",
    });
  }
  return _stripe;
}

const APP_URL = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";

export async function createCheckoutSession({
  priceId,
  customerEmail,
  userId,
}: {
  priceId: string;
  customerEmail?: string;
  userId?: string;
}): Promise<Stripe.Checkout.Session> {
  const session = await getStripe().checkout.sessions.create({
    mode: "subscription",
    payment_method_types: ["card"],
    line_items: [
      {
        price: priceId,
        quantity: 1,
      },
    ],
    success_url: `${APP_URL}/dashboard?checkout=success&session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${APP_URL}/pricing?checkout=cancelled`,
    ...(customerEmail && { customer_email: customerEmail }),
    metadata: {
      ...(userId && { userId }),
    },
    subscription_data: {
      metadata: {
        ...(userId && { userId }),
      },
    },
  });

  return session;
}

export async function createPortalSession({
  customerId,
}: {
  customerId: string;
}): Promise<Stripe.BillingPortal.Session> {
  const session = await getStripe().billingPortal.sessions.create({
    customer: customerId,
    return_url: `${APP_URL}/dashboard`,
  });

  return session;
}
