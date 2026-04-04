// ============================================================================
// /api/extension/keys — Create and list API keys for browser extension use
// GET  → list user's active API keys (prefix + plan + created)
// POST → create a new API key for the authenticated user
// DELETE → revoke a key by prefix
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { getUserFromRequest } from "@/lib/auth-helpers";
import { createServiceRoleClient } from "@/lib/supabase/client";

// Generate a secure random API key: ss_live_<32 random chars>
function generateApiKey(): string {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "ss_live_";
  // Use crypto.getRandomValues for secure randomness
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  for (const b of bytes) {
    result += chars[b % chars.length];
  }
  return result;
}

export async function GET(req: NextRequest) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const db = createServiceRoleClient();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data, error } = await (db as any)
    .from("api_keys")
    .select("key_prefix, plan, label, created_at, last_used_at, requests_total, revoked_at")
    .eq("user_id", user.id)
    .is("revoked_at", null)
    .order("created_at", { ascending: false });

  if (error) {
    console.error("[/api/extension/keys GET]", error.message);
    return NextResponse.json({ error: "Failed to load keys" }, { status: 500 });
  }

  return NextResponse.json({ keys: data ?? [] });
}

export async function POST(req: NextRequest) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json().catch(() => null);
  const label = (body?.label as string | undefined)?.slice(0, 60) || "Browser Extension";
  const plan = user.plan === "pro" || user.plan === "team" || user.plan === "organization" || user.plan === "enterprise"
    ? "pro"
    : "free";

  const db = createServiceRoleClient();

  // Enforce max 5 active keys per user
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { count } = await (db as any)
    .from("api_keys")
    .select("id", { count: "exact", head: true })
    .eq("user_id", user.id)
    .is("revoked_at", null);

  if ((count ?? 0) >= 5) {
    return NextResponse.json({ error: "Maximum 5 active API keys. Revoke one first." }, { status: 400 });
  }

  const rawKey = generateApiKey();
  const keyPrefix = rawKey.substring(0, 16);

  // Store prefix + hash. In production we'd bcrypt the full key.
  // For now prefix is the lookup index; hash is the full key hash for validation.
  const keyHash = await hashKey(rawKey);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { error } = await (db as any).from("api_keys").insert({
    user_id: user.id,
    key_prefix: keyPrefix,
    key_hash: keyHash,
    plan,
    label,
    requests_today: 0,
    requests_total: 0,
  });

  if (error) {
    console.error("[/api/extension/keys POST]", error.message);
    return NextResponse.json({ error: "Failed to create key" }, { status: 500 });
  }

  // Return the full key ONCE — never stored in plaintext
  return NextResponse.json({
    key: rawKey,
    prefix: keyPrefix,
    plan,
    label,
    warning: "Copy this key now. It will not be shown again.",
  });
}

export async function DELETE(req: NextRequest) {
  const user = await getUserFromRequest(req);
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const body = await req.json().catch(() => null);
  const prefix = body?.prefix as string | undefined;
  if (!prefix) return NextResponse.json({ error: "prefix required" }, { status: 400 });

  const db = createServiceRoleClient();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { error } = await (db as any)
    .from("api_keys")
    .update({ revoked_at: new Date().toISOString() })
    .eq("key_prefix", prefix)
    .eq("user_id", user.id); // RLS: user can only revoke their own keys

  if (error) {
    console.error("[/api/extension/keys DELETE]", error.message);
    return NextResponse.json({ error: "Failed to revoke key" }, { status: 500 });
  }

  return NextResponse.json({ revoked: true });
}

async function hashKey(key: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(key));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}
