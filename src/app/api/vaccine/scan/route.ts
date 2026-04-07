// ============================================================================
// POST /api/vaccine/scan — Analyze a URL for threats using VERIDICT engine
// Uses the same 13k+ pattern engine as the main scan — no live scraping.
// Returns threats + suggested injection rules for the "Vaccinate" step.
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { runVERIDICT } from "@/lib/algorithms/veridict-engine";
import { validateUrl } from "@/lib/vaccine/url-validator";
import { signPayload } from "@/lib/vaccine/payload-signer";
import { checkRateLimit } from "@/lib/vaccine/rate-limiter";
import { getUserFromRequest, canScan, incrementScanCount } from "@/lib/auth-helpers";
import type { InjectionRule } from "@/lib/vaccine/types";
import type { EvidenceItem } from "@/lib/algorithms/types";

const SEV_WEIGHT: Record<string, number> = { low: 5, medium: 12, high: 20, critical: 28 };

// Map VERIDICT evidence → injection rules
function evidenceToRules(evidence: EvidenceItem[]): InjectionRule[] {
  const rules: InjectionRule[] = [];
  const seen = new Set<string>();

  for (const e of evidence) {
    const key = e.finding.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);

    const w = SEV_WEIGHT[e.severity] ?? 10;
    let type: InjectionRule["type"] = "monitor";
    if (w >= 20 || key.includes("phishing") || key.includes("credential") || key.includes("malware")) type = "block";
    else if (w >= 12 || key.includes("urgency") || key.includes("spoof")) type = "warn";
    else if (key.includes("iframe") || key.includes("script")) type = "sandbox";

    rules.push({
      id: `v-${key.replace(/[^a-z0-9]/g, "-").substring(0, 40)}-${rules.length}`,
      type,
      message: `${e.finding}: ${e.detail}`.substring(0, 300),
      expiresAt: Date.now() + 24 * 60 * 60 * 1000,
    });
  }

  return rules;
}

// Map VERIDICT evidence → threat description strings
function evidenceToThreats(evidence: EvidenceItem[]): string[] {
  const seen = new Set<string>();
  return evidence
    .filter(e => {
      if (seen.has(e.finding)) return false;
      seen.add(e.finding);
      return true;
    })
    .map(e => `[${e.layer}] ${e.finding}: ${e.detail}`);
}

function scoreToLevel(score: number): string {
  if (score >= 75) return "critical";
  if (score >= 55) return "high";
  if (score >= 30) return "medium";
  if (score >= 10) return "low";
  return "safe";
}

export async function POST(req: NextRequest) {
  const startTime = Date.now();

  try {
    const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";

    const rateCheck = checkRateLimit(ip, "scan");
    if (!rateCheck.allowed) {
      return NextResponse.json(
        { error: rateCheck.reason || "Rate limit exceeded" },
        { status: 429, headers: { "Retry-After": String(Math.ceil(rateCheck.retryAfterMs / 1000)) } }
      );
    }

    const body = await req.json().catch(() => ({}));
    if (!body.url || typeof body.url !== "string") {
      return NextResponse.json({ error: "Missing 'url' parameter" }, { status: 400 });
    }

    const urlValidation = validateUrl(body.url);
    if (!urlValidation.valid) {
      return NextResponse.json({ error: `Invalid URL: ${urlValidation.error}` }, { status: 400 });
    }

    const safeUrl = urlValidation.sanitizedUrl;

    // Auth + quota
    const authUser = await getUserFromRequest(req);
    if (authUser) {
      const quota = await canScan(authUser);
      if (!quota.allowed) {
        return NextResponse.json({ error: "Daily scan limit reached. Upgrade to Pro." }, { status: 429 });
      }
    }

    // Run VERIDICT engine (same as main scan — 13k+ patterns, Fisher cascade, all layers)
    const verdict = await runVERIDICT({ url: safeUrl, text: safeUrl });

    // Convert evidence → threats + injection rules
    const threats = evidenceToThreats(verdict.evidence);
    const rules = evidenceToRules(verdict.evidence);

    // Sign
    const signed = await signPayload(JSON.stringify(rules));

    if (authUser) {
      await incrementScanCount(authUser.id);
    }

    return NextResponse.json({
      url: safeUrl,
      timestamp: Date.now(),
      threatLevel: scoreToLevel(verdict.score),
      threatScore: Math.round(verdict.score),
      threatsDetected: threats,
      injectionRules: rules,
      signature: signed.signature,
      signedAt: signed.timestamp,
      latencyMs: Date.now() - startTime,
    }, {
      headers: { "Cache-Control": "no-store" },
    });
  } catch (err) {
    console.error("[/api/vaccine/scan] Error:", err);
    return NextResponse.json({ error: "Vaccine scan failed. Please try again." }, { status: 500 });
  }
}
