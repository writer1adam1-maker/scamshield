// ============================================================================
// GET /api/scan/history — Retrieve scan history for the authenticated user
// Returns paginated scan history from Supabase
// Query params: limit (default 20, max 100), offset (default 0), category, threatLevel
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { createServiceRoleClient } from "@/lib/supabase/client";
import { getUserFromRequest } from "@/lib/auth-helpers";

export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url);
    const limit = Math.min(100, Math.max(1, parseInt(searchParams.get("limit") ?? "20")));
    const offset = Math.max(0, parseInt(searchParams.get("offset") ?? "0"));
    const category = searchParams.get("category");
    const threatLevel = searchParams.get("threatLevel");

    // Extract userId from session (authenticated users only)
    const authUser = await getUserFromRequest(req);
    if (!authUser) {
      return NextResponse.json(
        { error: "Authentication required to retrieve scan history." },
        { status: 401 }
      );
    }

    const userId = authUser.id;

    const db = createServiceRoleClient();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let query = (db as any)
      .from("scans")
      .select("id, input_type, input_preview, score, threat_level, category, created_at", { count: "exact" })
      .eq("user_id", userId)
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (category) query = query.eq("category", category);
    if (threatLevel) query = query.eq("threat_level", threatLevel);

    const { data, count, error } = await query;

    if (error) {
      console.error("[Scan History] Supabase error:", error);
      return NextResponse.json({ error: "Failed to retrieve scan history" }, { status: 500 });
    }

    return NextResponse.json({
      scans: data ?? [],
      total: count ?? 0,
      limit,
      offset,
      hasMore: (offset + limit) < (count ?? 0),
    });
  } catch (error) {
    console.error("[Scan History] Error:", error);
    return NextResponse.json({ error: "Failed to retrieve scan history" }, { status: 500 });
  }
}

// ---------------------------------------------------------------------------
// POST: Save a scan result to history (called internally after each scan)
// ---------------------------------------------------------------------------

export async function POST(req: NextRequest) {
  try {
    const body = await req.json().catch(() => null);
    if (!body) return NextResponse.json({ error: "Invalid body" }, { status: 400 });

    const { userId, inputType, inputPreview, score, threatLevel, category, resultJson, ipAddress } = body as {
      userId: string | null;
      inputType: "url" | "text" | "screenshot";
      inputPreview: string;
      score: number;
      threatLevel: string;
      category: string;
      resultJson: Record<string, unknown>;
      ipAddress: string | null;
    };

    const db = createServiceRoleClient();

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { error } = await (db as any).from("scans").insert({
      user_id: userId ?? null,
      input_type: inputType,
      input_preview: (inputPreview ?? "").substring(0, 200),
      score,
      threat_level: threatLevel,
      category,
      result_json: resultJson,
      ip_address: ipAddress ?? null,
      created_at: new Date().toISOString(),
    });

    if (error) {
      console.error("[Scan History] Insert error:", error);
      return NextResponse.json({ error: "Failed to save scan" }, { status: 500 });
    }

    return NextResponse.json({ saved: true }, { status: 201 });
  } catch (error) {
    console.error("[Scan History] POST error:", error);
    return NextResponse.json({ error: "Failed to save scan" }, { status: 500 });
  }
}
