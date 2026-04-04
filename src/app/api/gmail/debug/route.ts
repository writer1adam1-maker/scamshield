// GET /api/gmail/debug — Check what scopes the stored token actually has
// Temporary debug endpoint — remove after fixing the 403 issue
import { NextRequest, NextResponse } from "next/server";
import { getUserFromRequest } from "@/lib/auth-helpers";
import { createServiceRoleClient } from "@/lib/supabase/client";
import { decryptToken } from "@/lib/gmail/token-crypto";
import { refreshAccessToken } from "@/lib/gmail/oauth";

export async function GET(req: NextRequest) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Not authenticated" }, { status: 401 });

  const db = createServiceRoleClient();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data: conn } = await (db as any)
    .from("gmail_connections")
    .select("encrypted_refresh_token, is_active, google_email")
    .eq("user_id", user.id)
    .single();

  if (!conn) return NextResponse.json({ error: "No connection found" });

  try {
    // Decrypt and refresh token
    const refreshToken = await decryptToken(conn.encrypted_refresh_token);
    const { access_token } = await refreshAccessToken(refreshToken);

    // Call Google tokeninfo to see what scopes the access token has
    const infoRes = await fetch(
      `https://oauth2.googleapis.com/tokeninfo?access_token=${encodeURIComponent(access_token)}`
    );
    const info = await infoRes.json();

    // Also test messages.list directly
    const listRes = await fetch(
      "https://www.googleapis.com/gmail/v1/users/me/messages?maxResults=1",
      { headers: { Authorization: "Bearer " + access_token } }
    );
    const listStatus = listRes.status;
    const listBody = await listRes.text();

    return NextResponse.json({
      is_active: conn.is_active,
      google_email: conn.google_email,
      tokeninfo: info,
      messages_list_status: listStatus,
      messages_list_body: listBody.substring(0, 500),
    });
  } catch (err) {
    return NextResponse.json({ error: String(err) });
  }
}
