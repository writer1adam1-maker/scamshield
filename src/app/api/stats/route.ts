import { NextResponse } from "next/server";
import { createServiceRoleClient } from "@/lib/supabase/client";

// Cached for 5 minutes to avoid hammering the DB on every page load
export const revalidate = 300;

export async function GET() {
  try {
    const db = createServiceRoleClient();

    // Total scans today
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { count: scansToday } = await (db as any)
      .from("scans")
      .select("*", { count: "exact", head: true })
      .gte("created_at", today.toISOString());

    // Total threats detected today (score >= 40)
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { count: threatsToday } = await (db as any)
      .from("scans")
      .select("*", { count: "exact", head: true })
      .gte("created_at", today.toISOString())
      .gte("score", 40);

    // Top threat category today
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data: categoryRows } = await (db as any)
      .from("scans")
      .select("category")
      .gte("created_at", today.toISOString())
      .gte("score", 40)
      .limit(500);

    let topThreat = "Phishing";
    let topThreatPct = 0;

    if (categoryRows && categoryRows.length > 0) {
      const counts: Record<string, number> = {};
      for (const row of categoryRows) {
        if (row.category) counts[row.category] = (counts[row.category] || 0) + 1;
      }
      const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
      if (sorted[0]) {
        topThreat = sorted[0][0].replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
        topThreatPct = Math.round((sorted[0][1] / categoryRows.length) * 100);
      }
    }

    // Average score today
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data: scoreRows } = await (db as any)
      .from("scans")
      .select("score")
      .gte("created_at", today.toISOString())
      .limit(1000);

    let avgScore = 0;
    if (scoreRows && scoreRows.length > 0) {
      avgScore = scoreRows.reduce((sum: number, r: { score: number }) => sum + (r.score || 0), 0) / scoreRows.length;
    }

    return NextResponse.json({
      scansToday: scansToday ?? 0,
      threatsToday: threatsToday ?? 0,
      topThreat,
      topThreatPct,
      avgScore: Math.round(avgScore * 10) / 10,
    });
  } catch (error) {
    console.error("[Stats API] Error fetching stats:", error);
    // Return zeros on error rather than crashing the page
    return NextResponse.json({
      scansToday: 0,
      threatsToday: 0,
      topThreat: "Phishing",
      topThreatPct: 0,
      avgScore: 0,
    });
  }
}
