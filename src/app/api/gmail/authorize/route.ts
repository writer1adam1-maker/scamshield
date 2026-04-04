// GET /api/gmail/authorize — Build Google OAuth URL and redirect
import { NextRequest, NextResponse } from "next/server";
import { getUserFromRequest } from "@/lib/auth-helpers";
import { buildAuthUrl } from "@/lib/gmail/oauth";
import crypto from "crypto";

export async function GET(req: NextRequest) {
  const user = await getUserFromRequest(req);
  if (!user) {
    return NextResponse.redirect(new URL("/login?next=/dashboard/gmail", req.url));
  }

  if (!process.env.GOOGLE_CLIENT_ID) {
    return NextResponse.json({ error: "Gmail integration not configured" }, { status: 503 });
  }

  // Generate CSRF state token: base64url(userId + nonce)
  // Nonce is stored in a short-lived HttpOnly cookie and verified in callback
  const nonce = crypto.randomBytes(16).toString("hex");
  const state = Buffer.from(JSON.stringify({ userId: user.id, nonce })).toString("base64url");

  const authUrl = buildAuthUrl(state);
  const response = NextResponse.redirect(authUrl);
  // Store nonce in HttpOnly cookie (expires 10 minutes — enough time to complete OAuth)
  response.cookies.set("gmail_oauth_nonce", nonce, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 60 * 10,
    path: "/api/gmail/callback",
  });
  return response;
}
