// ============================================================================
// GET /api/threat-intel — Threat Intelligence dashboard data
// Runs analyzeTrends + detectOutbreak + predictNextWave on recent global
// scan data (last 7 days, up to 500 rows) using the service-role client.
// Returns: trending categories, emerging patterns, outbreaks, predictions.
// No auth required — data is aggregated and de-identified.
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { createServiceRoleClient } from "@/lib/supabase/client";
import { generateThreatIntelligence } from "@/lib/algorithms/threat-intelligence";
import type { TrendDataPoint } from "@/lib/algorithms/types";
import { ThreatCategory } from "@/lib/algorithms/types";
import { checkRateLimit } from "@/lib/rate-limit";
import { getClientIp } from "@/lib/utils";

// 5-minute in-memory cache
let cache: { data: unknown; ts: number } | null = null;
const CACHE_TTL_MS = 5 * 60 * 1000;

// Map DB category strings → ThreatCategory enum
const CATEGORY_MAP: Record<string, ThreatCategory> = {
  PHISHING:         ThreatCategory.PHISHING,
  ADVANCE_FEE:      ThreatCategory.ADVANCE_FEE,
  TECH_SUPPORT:     ThreatCategory.TECH_SUPPORT,
  ROMANCE:          ThreatCategory.ROMANCE,
  CRYPTO:           ThreatCategory.CRYPTO,
  IRS_GOV:          ThreatCategory.IRS_GOV,
  PACKAGE_DELIVERY: ThreatCategory.PACKAGE_DELIVERY,
  SOCIAL_MEDIA:     ThreatCategory.SOCIAL_MEDIA,
  SUBSCRIPTION_TRAP:ThreatCategory.SUBSCRIPTION_TRAP,
  FAKE_CHARITY:     ThreatCategory.FAKE_CHARITY,
  RENTAL_HOUSING:   ThreatCategory.RENTAL_HOUSING,
  STUDENT_LOAN:     ThreatCategory.STUDENT_LOAN,
  MARKETPLACE_FRAUD:ThreatCategory.MARKETPLACE_FRAUD,
  ELDER_SCAM:       ThreatCategory.ELDER_SCAM,
  TICKET_SCAM:      ThreatCategory.TICKET_SCAM,
  INVESTMENT_FRAUD: ThreatCategory.INVESTMENT_FRAUD,
  EMPLOYMENT_SCAM:  ThreatCategory.EMPLOYMENT_SCAM,
  BANK_OTP:         ThreatCategory.BANK_OTP,
  GENERIC:          ThreatCategory.GENERIC,
};

export async function GET(req: NextRequest) {
  try {
    // Rate limit: same as anonymous scan limit (prevents scraping)
    const ip = getClientIp(req);
    const rateLimit = checkRateLimit(ip, false);
    if (!rateLimit.allowed) {
      return NextResponse.json(
        { error: "Rate limit exceeded." },
        { status: 429, headers: { "Retry-After": String(Math.ceil((rateLimit.resetAt - Date.now()) / 1000)) } },
      );
    }

    // Serve from cache if fresh
    if (cache && Date.now() - cache.ts < CACHE_TTL_MS) {
      return NextResponse.json(cache.data, {
        headers: { "X-Cache": "HIT", "Cache-Control": "public, max-age=300" },
      });
    }

    const supabase = createServiceRoleClient();

    // Pull last 7 days of scans, high-threat only (score >= 40), max 500
    const cutoff = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
    const { data: rawRows, error } = await supabase
      .from("scans")
      .select("created_at, category, score, threat_level")
      .gte("created_at", cutoff)
      .gte("score", 30)
      .order("created_at", { ascending: true })
      .limit(500);

    if (error) {
      console.error("[/api/threat-intel] DB error:", error.message);
      return NextResponse.json({ error: "Failed to load scan data" }, { status: 500 });
    }

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const rows = (rawRows ?? []) as any[];

    const dataPoints: TrendDataPoint[] = rows
      .filter((r) => r.category && CATEGORY_MAP[r.category as string])
      .map((r) => ({
        timestamp: new Date(r.created_at as string).getTime(),
        category: CATEGORY_MAP[r.category as string],
        pattern: (r.category as string).toLowerCase().replace(/_/g, "-"),
        signals: [(r.threat_level as string | null) ?? "MEDIUM"],
      }));

    if (dataPoints.length < 3) {
      // Not enough data yet — return empty structure
      return NextResponse.json({
        trendingCategories: [],
        emergingPatterns: [],
        outbreaks: [],
        predictions: [],
        dataPointCount: dataPoints.length,
        generatedAt: Date.now(),
        message: "Not enough scan data yet. Run more scans to see trends.",
      });
    }

    const intel = generateThreatIntelligence(dataPoints);
    const response = {
      ...intel,
      // Limit arrays to keep response small
      trendingCategories: intel.trendingCategories.slice(0, 8),
      emergingPatterns: intel.emergingPatterns.slice(0, 6).map((p) => ({
        pattern: p.pattern,
        category: p.category,
        velocity: Math.round(p.velocity * 100) / 100,
        isOutbreak: p.isOutbreak,
        zScore: Math.round(p.zScore * 100) / 100,
      })),
      outbreaks: intel.outbreaks.slice(0, 4).map((o) => ({
        pattern: o.pattern,
        category: o.category,
        velocity: Math.round(o.velocity * 100) / 100,
        zScore: Math.round(o.zScore * 100) / 100,
        isOutbreak: true,
      })),
      predictions: intel.predictions.slice(0, 4),
    };

    cache = { data: response, ts: Date.now() };

    return NextResponse.json(response, {
      headers: { "X-Cache": "MISS", "Cache-Control": "public, max-age=300" },
    });
  } catch (err) {
    console.error("[/api/threat-intel] Error:", err);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
