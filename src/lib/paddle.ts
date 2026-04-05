import { Paddle, Environment } from "@paddle/paddle-node-sdk";

let _paddle: Paddle | null = null;

export function getPaddle(): Paddle {
  if (!_paddle) {
    if (!process.env.PADDLE_API_KEY) {
      throw new Error("PADDLE_API_KEY is not set in environment variables");
    }
    _paddle = new Paddle(process.env.PADDLE_API_KEY, {
      environment:
        process.env.PADDLE_ENVIRONMENT === "production"
          ? Environment.production
          : Environment.sandbox,
    });
  }
  return _paddle;
}

const APP_URL = process.env.NEXT_PUBLIC_APP_URL || "http://localhost:3000";

export async function createCheckoutUrl({
  priceId,
  customerEmail,
  userId,
}: {
  priceId: string;
  customerEmail?: string;
  userId?: string;
}): Promise<string> {
  const paddle = getPaddle();

  const transaction = await paddle.transactions.create({
    items: [{ priceId, quantity: 1 }],
    ...(customerEmail && { customer: { email: customerEmail } }),
    customData: userId ? { userId } : undefined,
    checkout: {
      url: `${APP_URL}/dashboard?checkout=success`,
    },
  });

  if (!transaction.checkout?.url) {
    throw new Error("Paddle did not return a checkout URL");
  }

  return transaction.checkout.url;
}

export function getSubscriptionManagementUrl(): string {
  const isProduction = process.env.PADDLE_ENVIRONMENT === "production";
  return isProduction
    ? "https://sandbox-buyer.paddle.com/subscriptions"
    : "https://sandbox-buyer.paddle.com/subscriptions";
}
