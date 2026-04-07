// ============================================================================
// POST /api/vaccine/protect
// Builds and returns a real JavaScript protection script for a given URL
// based on its previously detected threats + injection rules.
// The script is safe to paste in the browser console or auto-inject via extension.
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { buildProtectionScript, getScriptSummary } from "@/lib/vaccine/protection-script-builder";
import { validateUrl } from "@/lib/vaccine/url-validator";
import { checkRateLimit } from "@/lib/vaccine/rate-limiter";
import type { InjectionRule } from "@/lib/vaccine/types";

export async function POST(req: NextRequest) {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
  const rateCheck = checkRateLimit(ip, "inject");
  if (!rateCheck.allowed) {
    return NextResponse.json({ error: "Rate limit exceeded" }, { status: 429 });
  }

  let body: { url?: string; threats?: string[]; rules?: InjectionRule[] };
  try { body = await req.json(); }
  catch { return NextResponse.json({ error: "Invalid body" }, { status: 400 }); }

  if (!body.url) return NextResponse.json({ error: "url required" }, { status: 400 });

  const validation = validateUrl(body.url);
  if (!validation.valid) return NextResponse.json({ error: validation.error }, { status: 400 });

  const threats = Array.isArray(body.threats) ? body.threats.slice(0, 50) : [];
  const rules: InjectionRule[] = Array.isArray(body.rules) ? body.rules.slice(0, 50) : [];

  const script = buildProtectionScript(rules, validation.sanitizedUrl, threats);
  const summary = getScriptSummary(threats, rules);

  return NextResponse.json({
    script,
    url: validation.sanitizedUrl,
    modules: summary,
    moduleCount: summary.length,
    generatedAt: Date.now(),
  });
}
