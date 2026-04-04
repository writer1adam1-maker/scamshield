// POST /api/gmail/disconnect — Revoke OAuth and delete connection
import { NextRequest, NextResponse } from "next/server";
import { getUserFromRequest } from "@/lib/auth-helpers";
import { createServiceRoleClient } from "@/lib/supabase/client";
import { decryptToken, } from "@/lib/gmail/token-crypto";
import { revokeToken } from "@/lib/gmail/oauth";

export async function POST(req: NextRequest) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const db = createServiceRoleClient();

  // Fetch connection to get refresh token for revocation
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data: conn } = await (db as any)
    .from("gmail_connections")
    .select("encrypted_refresh_token")
    .eq("user_id", user.id)
    .single();

  if (conn?.encrypted_refresh_token) {
    try {
      const refreshToken = await decryptToken(conn.encrypted_refresh_token);
      await revokeToken(refreshToken);
    } catch {
      // Revocation failure is non-fatal — still delete local record
    }
  }

  // Delete connection and all scan results for this user
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await (db as any).from("gmail_connections").delete().eq("user_id", user.id);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  await (db as any).from("gmail_scan_results").delete().eq("user_id", user.id);

  return NextResponse.json({ disconnected: true });
}
