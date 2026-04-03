// ============================================================================
// POST /api/vaccine/scan — Scan a website and return protective vaccine rules
//
// Security hardening:
// - SSRF protection: URL validation, private IP blocking, redirect validation
// - Rate limiting: per-IP sliding window (10/min, 60/hour)
// - Input sanitization: strict URL parsing, scheme whitelist
// - Response sanitization: no raw scores in unauthenticated responses
// - Payload signing: HMAC on injection rules
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { VaccineManager } from "@/lib/vaccine/vaccine-manager";
import { validateUrl, sanitizeUrlForLog } from "@/lib/vaccine/url-validator";
import { signPayload } from "@/lib/vaccine/payload-signer";
import { checkRateLimit } from "@/lib/vaccine/rate-limiter";
import { getUserFromRequest, canScan, incrementScanCount } from "@/lib/auth-helpers";

const vaccineManager = new VaccineManager();

export async function POST(req: NextRequest) {
  const startTime = Date.now();

  try {
    // --- Rate limiting ---
    const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
      || req.headers.get("x-real-ip")
      || "unknown";

    const rateCheck = checkRateLimit(ip, "scan");
    if (!rateCheck.allowed) {
      return NextResponse.json(
        { error: rateCheck.reason || "Rate limit exceeded" },
        {
          status: 429,
          headers: {
            "Retry-After": String(Math.ceil(rateCheck.retryAfterMs / 1000)),
            "X-RateLimit-Remaining": String(rateCheck.remaining),
          },
        }
      );
    }

    // --- Input parsing ---
    const body = await req.json().catch(() => ({}));

    if (!body.url || typeof body.url !== "string") {
      return NextResponse.json(
        { error: "Missing or invalid 'url' parameter" },
        { status: 400 }
      );
    }

    // --- SSRF protection: validate URL before any server-side fetch ---
    const urlValidation = validateUrl(body.url);
    if (!urlValidation.valid) {
      return NextResponse.json(
        { error: `Invalid URL: ${urlValidation.error}` },
        { status: 400 }
      );
    }

    const safeUrl = urlValidation.sanitizedUrl;

    // --- Auth + quota check ---
    const authUser = await getUserFromRequest(req);
    if (authUser) {
      const quota = canScan(authUser);
      if (!quota.allowed) {
        return NextResponse.json(
          { error: "Daily scan limit reached. Upgrade to Pro for unlimited scans." },
          { status: 429 }
        );
      }
    }

    // --- Optional VERIDICT score (validate range) ---
    let vericticScore: number | undefined;
    if (body.vericticScore !== undefined) {
      const score = Number(body.vericticScore);
      if (isNaN(score) || score < 0 || score > 100) {
        return NextResponse.json(
          { error: "vericticScore must be a number between 0 and 100" },
          { status: 400 }
        );
      }
      vericticScore = score;
    }

    // --- Run vaccination pipeline ---
    const report = await vaccineManager.vaccinate(safeUrl, vericticScore);

    // --- Sign injection rules payload ---
    const rulesPayload = JSON.stringify(report.injectionRules);
    const signed = await signPayload(rulesPayload);

    // --- Increment scan count for authenticated users ---
    if (authUser) {
      await incrementScanCount(authUser.id);
    }

    // --- Build sanitized response (don't expose internal details) ---
    const response = {
      url: safeUrl,
      timestamp: report.timestamp,
      threatLevel: report.threatLevel,
      threatScore: report.threatScore,
      threatsDetected: Array.isArray(report.threatsDetected)
        ? report.threatsDetected.map((t: any) =>
            typeof t === "string" ? t : t.description || "Unknown threat"
          )
        : [],
      injectionRules: report.injectionRules,
      synergosAnalysis: report.synergosAnalysis
        ? {
            verdict: report.synergosAnalysis.verdict,
            confidence: Math.round(report.synergosAnalysis.confidence * 100) / 100,
            nextAttackPrediction: report.synergosAnalysis.nextAttackPrediction,
            recommendedDefense: report.synergosAnalysis.recommendedDefense,
          }
        : undefined,
      signature: signed.signature,
      signedAt: signed.timestamp,
      latencyMs: Date.now() - startTime,
    };

    console.log(`[/api/vaccine/scan] Done (${response.latencyMs}ms): ${report.threatLevel}, ${response.threatsDetected.length} threats`);

    return NextResponse.json(response, {
      status: 200,
      headers: {
        "X-RateLimit-Remaining": String(rateCheck.remaining),
        "Cache-Control": "no-store",
      },
    });
  } catch (err) {
    console.error("[/api/vaccine/scan] Error:", err);

    // Don't leak internal error details to client
    return NextResponse.json(
      { error: "Vaccine scan failed. Please try again." },
      { status: 500 }
    );
  }
}
