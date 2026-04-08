/**
 * GET /api/gmail/debug-scan?domain=example.com
 * Tests VERIDICT scoring on a domain in email mode.
 * Admin only.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { runVERIDICT } from "@/lib/algorithms/veridict-engine";
import { deepAnalyzeUrl } from "@/lib/algorithms/url-deep-analyzer";

export async function GET(req: NextRequest) {
  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    { cookies: { getAll() { return req.cookies.getAll(); }, setAll() {} } }
  );
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  const adminEmails = (process.env.ADMIN_EMAILS || "").split(",").map(e => e.trim().toLowerCase());
  if (!adminEmails.includes((user.email ?? "").toLowerCase())) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const domain = req.nextUrl.searchParams.get("domain");
  if (!domain) return NextResponse.json({ error: "Missing ?domain=" }, { status: 400 });

  const url = `https://${domain}`;
  const urlAnalysis = deepAnalyzeUrl(url);
  const result = await runVERIDICT({ url, emailMode: true });

  return NextResponse.json({
    domain,
    url,
    urlRiskScore: urlAnalysis.overallRiskScore,
    urlFlags: urlAnalysis.flags,
    urlBrands: urlAnalysis.detectedBrands,
    finalScore: result.score,
    threatLevel: result.threatLevel,
    category: result.category,
    evidence: result.evidence?.slice(0, 5),
  });
}
