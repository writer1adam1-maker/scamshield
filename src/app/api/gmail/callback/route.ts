// GET /api/gmail/callback — Handle OAuth code exchange and store tokens
import { NextRequest, NextResponse } from "next/server";
import { exchangeCode, extractEmailFromIdToken } from "@/lib/gmail/oauth";
import { encryptToken } from "@/lib/gmail/token-crypto";
import { createServiceRoleClient } from "@/lib/supabase/client";

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const code  = searchParams.get("code");
  const state = searchParams.get("state");
  const error = searchParams.get("error");

  if (error) {
    return NextResponse.redirect(new URL("/dashboard/gmail?error=" + encodeURIComponent(error), req.url));
  }

  if (!code || !state) {
    return NextResponse.redirect(new URL("/dashboard/gmail?error=missing_params", req.url));
  }

  // Decode state and verify CSRF nonce
  let userId: string;
  try {
    const decoded = JSON.parse(Buffer.from(state, "base64url").toString());
    userId = decoded.userId;
    const nonce = decoded.nonce;
    if (!userId || !nonce) throw new Error("missing fields");

    // UUID format check to prevent injection via state param
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(userId)) {
      throw new Error("invalid userId format");
    }

    // Verify nonce matches the one stored in cookie during authorize
    const expectedNonce = req.cookies.get("gmail_oauth_nonce")?.value;
    if (!expectedNonce || expectedNonce !== nonce) {
      throw new Error("nonce mismatch");
    }
  } catch {
    return NextResponse.redirect(new URL("/dashboard/gmail?error=invalid_state", req.url));
  }

  try {
    const tokens = await exchangeCode(code);

    if (!tokens.refresh_token) {
      // No refresh token — user already authorized, revoke and reconnect
      return NextResponse.redirect(new URL("/dashboard/gmail?error=no_refresh_token", req.url));
    }

    // Extract Google email from id_token
    const googleEmail = tokens.id_token
      ? extractEmailFromIdToken(tokens.id_token) ?? "unknown@gmail.com"
      : "unknown@gmail.com";

    // Encrypt refresh token before storage
    const encryptedRefreshToken = await encryptToken(tokens.refresh_token);

    const db = createServiceRoleClient();

    // Fetch the user's ScamShield account email for digest delivery
    const { data: userData } = await db.auth.admin.getUserById(userId);
    const userEmail = userData?.user?.email ?? null;

    // Try upsert with user_email (requires migration 009).
    // Fall back to base upsert if column doesn't exist yet.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const upsertResult = await (db as any).from("gmail_connections").upsert({
      user_id: userId,
      google_email: googleEmail,
      user_email: userEmail,
      encrypted_refresh_token: encryptedRefreshToken,
      history_id: null,
      is_active: true,
      connected_at: new Date().toISOString(),
    }, { onConflict: "user_id" });

    if (upsertResult.error) {
      // If user_email column missing, retry without it
      if (upsertResult.error.message?.includes("user_email") || upsertResult.error.message?.includes("column")) {
        await (db as any).from("gmail_connections").upsert({
          user_id: userId,
          google_email: googleEmail,
          encrypted_refresh_token: encryptedRefreshToken,
          history_id: null,
          is_active: true,
          connected_at: new Date().toISOString(),
        }, { onConflict: "user_id" });
      } else {
        throw new Error(upsertResult.error.message);
      }
    }

    const successResponse = NextResponse.redirect(new URL("/dashboard/gmail?connected=1", req.url));
    // Clear nonce cookie — single use only
    successResponse.cookies.delete("gmail_oauth_nonce");
    return successResponse;
  } catch (err) {
    console.error("[gmail/callback]", err);
    return NextResponse.redirect(new URL("/dashboard/gmail?error=token_exchange_failed", req.url));
  }
}
