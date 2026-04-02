// ============================================================================
// POST /api/scan — Main scan endpoint
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { checkRateLimit } from "@/lib/rate-limit";
import { runVERIDICT } from "@/lib/algorithms/veridict-engine";
import { getClientIp } from "@/lib/utils";
import { createServiceRoleClient } from "@/lib/supabase/client";
import { enrichUrlWithWhoisSsl } from "@/lib/whois-ssl";
import { analyzeUrlIp } from "@/lib/ip-intelligence";
import type { AnalysisInput } from "@/lib/algorithms/types";

interface ScanRequest {
  type: "url" | "text" | "screenshot";
  content: string;
}

function validateRequest(body: unknown): body is ScanRequest {
  if (!body || typeof body !== "object") return false;
  const b = body as Record<string, unknown>;
  if (!["url", "text", "screenshot"].includes(b.type as string)) return false;
  if (typeof b.content !== "string" || b.content.trim().length === 0) return false;
  if (b.content.length > 10_000) return false;
  return true;
}

function buildAnalysisInput(type: ScanRequest["type"], content: string): AnalysisInput {
  switch (type) {
    case "url":
      return { url: content, text: content };
    case "text": {
      // Try to detect if the text contains URLs
      const urlMatch = content.match(/https?:\/\/[^\s]+/);
      return {
        text: content,
        url: urlMatch ? urlMatch[0] : undefined,
        smsBody: content.length < 500 ? content : undefined,
        emailBody: content.length >= 500 ? content : undefined,
      };
    }
    case "screenshot":
      return { screenshotOcrText: content, text: content };
    default:
      return { text: content };
  }
}

export async function POST(req: NextRequest) {
  const startTime = performance.now();
  console.log("[/api/scan] Request received");

  try {
    // --- Rate limiting ---
    const ip = getClientIp(req);
    console.log("[/api/scan] Client IP:", ip);
    // TODO: Integrate with Supabase auth to check user session, then look up
    // the user's plan (free/pro) from the users table or Stripe subscription status.
    const isPro = false;
    const rateLimit = checkRateLimit(ip, isPro);
    console.log("[/api/scan] Rate limit check — allowed:", rateLimit.allowed, "remaining:", rateLimit.remaining);

    if (!rateLimit.allowed) {
      return NextResponse.json(
        {
          error: "Rate limit exceeded. Upgrade to Pro for unlimited scans.",
          remaining: rateLimit.remaining,
          resetAt: new Date(rateLimit.resetAt).toISOString(),
        },
        {
          status: 429,
          headers: {
            "X-RateLimit-Limit": String(rateLimit.limit),
            "X-RateLimit-Remaining": String(rateLimit.remaining),
            "X-RateLimit-Reset": String(rateLimit.resetAt),
            "Retry-After": String(Math.ceil((rateLimit.resetAt - Date.now()) / 1000)),
          },
        },
      );
    }

    // --- Parse and validate body ---
    const body = await req.json().catch(() => null);

    if (!validateRequest(body)) {
      return NextResponse.json(
        { error: "Invalid request. Provide { type: 'url'|'text'|'screenshot', content: string }." },
        { status: 400 },
      );
    }

    // --- Build analysis input ---
    const analysisInput = buildAnalysisInput(body.type, body.content.trim());

    // --- Run VERIDICT + WHOIS/SSL enrichment in parallel ---
    const isUrl = body.type === "url" || (body.type === "text" && /https?:\/\//.test(body.content));
    const urlForWhois = body.type === "url"
      ? body.content.trim()
      : body.content.match(/https?:\/\/[^\s]+/)?.[0] ?? null;

    console.log("[/api/scan] Running analysis — isUrl:", isUrl, "urlForWhois:", urlForWhois?.slice(0, 60));

    const [verdictResult, whoisResult, ipResult] = await Promise.allSettled([
      runVERIDICT(analysisInput),
      isUrl && urlForWhois ? enrichUrlWithWhoisSsl(urlForWhois) : Promise.resolve(null),
      isUrl && urlForWhois ? analyzeUrlIp(urlForWhois) : Promise.resolve(null),
    ]);

    if (verdictResult.status === "rejected") {
      console.error("[/api/scan] VERIDICT engine failed:", verdictResult.reason);
      throw verdictResult.reason;
    }

    const result = verdictResult.value;
    const whois = whoisResult.status === "fulfilled" ? whoisResult.value : null;
    const ipIntel = ipResult.status === "fulfilled" ? ipResult.value : null;

    if (whoisResult.status === "rejected") console.warn("[/api/scan] WHOIS enrichment failed:", whoisResult.reason);
    if (ipResult.status === "rejected") console.warn("[/api/scan] IP intelligence failed:", ipResult.reason);

    console.log("[/api/scan] Analysis complete — score:", result.score, "evidence:", result.evidence?.length);

    // Merge WHOIS/SSL evidence and score boost into result
    if (whois && whois.evidence.length > 0) {
      const boostedScore = Math.min(100, result.score + whois.scoreBoost);
      const whoisEvidence = whois.evidence.map((e) => ({
        type: "whois_ssl" as const,
        finding: e.finding,
        severity: e.severity,
        confidence: 0.9,
      }));
      Object.assign(result, {
        score: boostedScore,
        evidence: [...whoisEvidence, ...result.evidence],
        whoisSsl: {
          domainAge: whois.domainAge,
          sslValid: whois.sslValid,
          registrar: whois.registrar,
        },
      });
    }

    // Merge IP intelligence evidence and score boost
    if (ipIntel && ipIntel.evidence.length > 0) {
      const boostedScore = Math.min(100, result.score + ipIntel.scoreBoost);
      const ipEvidence = ipIntel.evidence.map((e) => ({
        type: "whois_ssl" as const,
        finding: e.finding,
        severity: e.severity,
        confidence: 0.85,
      }));
      Object.assign(result, {
        score: boostedScore,
        evidence: [...ipEvidence, ...result.evidence],
        ipIntelligence: {
          ip: ipIntel.ip,
          country: ipIntel.country,
          countryCode: ipIntel.countryCode,
          city: ipIntel.city,
          isp: ipIntel.isp,
          org: ipIntel.org,
          asn: ipIntel.asn,
          hostingCategory: ipIntel.hostingCategory,
          isDatacenter: ipIntel.isDatacenter,
          isVpnOrProxy: ipIntel.isVpnOrProxy,
          countryRiskLevel: ipIntel.countryRiskLevel,
          flags: ipIntel.flags,
        },
      });
    }

    const processingTimeMs = Math.round(performance.now() - startTime);

    // --- Persist scan result (fire and forget) ---
    try {
      const db = createServiceRoleClient();
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      await (db as any).from("scans").insert({
        user_id: null, // TODO: populate from session when auth is wired
        input_type: body.type,
        input_preview: body.content.trim().substring(0, 200),
        score: result.score,
        threat_level: result.threatLevel,
        category: result.category,
        result_json: result,
        ip_address: ip ?? null,
        created_at: new Date().toISOString(),
      });
    } catch {
      // Non-blocking — scan result still returned even if persistence fails
    }

    return NextResponse.json(
      { ...result, processingTimeMs },
      {
        status: 200,
        headers: {
          "X-RateLimit-Limit": String(rateLimit.limit),
          "X-RateLimit-Remaining": String(rateLimit.remaining),
          "X-Processing-Time": `${processingTimeMs}ms`,
        },
      },
    );
  } catch (err) {
    console.error("[/api/scan] Unexpected error:", err);
    return NextResponse.json(
      { error: "Internal server error. Please try again." },
      { status: 500 },
    );
  }
}
