// ============================================================================
// POST /api/admin/patterns/sync
// Fetches live threat intel from free public feeds, extracts domain/path patterns,
// deduplicates against existing custom_patterns.json, and appends new ones.
//
// Sources (all free, no API key required):
//   URLhaus  — https://urlhaus.abuse.ch/downloads/text_recent/
//   OpenPhish — https://openphish.com/feed.txt
//   PhishStats — https://phishstats.info:2096/api/phishing?_where=(score,gt,5)&_size=200
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { readPatterns, writePatterns } from "@/lib/pattern-ingestion/patterns-store";
import type { ExtractedPattern } from "@/lib/pattern-ingestion/pattern-extractor";

// ---------------------------------------------------------------------------
// Admin auth
// ---------------------------------------------------------------------------
async function requireAdmin(req: NextRequest): Promise<boolean> {
  try {
    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
      { cookies: { getAll() { return req.cookies.getAll(); }, setAll() {} } }
    );
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return false;
    const adminEmails = (process.env.ADMIN_EMAILS || "").split(",").map(e => e.trim().toLowerCase()).filter(Boolean);
    return adminEmails.includes((user.email || "").toLowerCase());
  } catch { return false; }
}

// Storage is handled by Supabase (patterns-store.ts) — no filesystem writes

// ---------------------------------------------------------------------------
// Severity rank for upgrade comparison
// ---------------------------------------------------------------------------
const SEV_RANK: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };

// ---------------------------------------------------------------------------
// Extract meaningful patterns from a raw URL
// Returns 0-3 patterns per URL (domain keywords, path keywords, TLD)
// ---------------------------------------------------------------------------

const KNOWN_LEGIT_DOMAINS = new Set([
  "google.com","microsoft.com","apple.com","amazon.com","github.com",
  "facebook.com","twitter.com","instagram.com","linkedin.com","youtube.com",
  "cloudflare.com","akamai.com","fastly.com","cdn.jsdelivr.net",
  "googleapis.com","gstatic.com","ajax.googleapis.com",
]);

const HIGH_RISK_TLDS = new Set([
  ".buzz",".wang",".host",".icu",".live",".tk",".gq",".cf",".ga",".info",
  ".xin",".top",".ml",".xyz",".online",".cn",".us",".sbs",".cfd",".rest",
  ".bond",".ru",".pw",".cc",".ws",".su",".club",".site",".biz",
]);

function extractPatternsFromUrl(rawUrl: string): ExtractedPattern[] {
  const patterns: ExtractedPattern[] = [];

  let parsed: URL;
  try {
    parsed = new URL(rawUrl.trim().startsWith("http") ? rawUrl.trim() : "https://" + rawUrl.trim());
  } catch { return []; }

  const hostname = parsed.hostname.toLowerCase().replace(/^www\./, "");
  const parts = hostname.split(".");
  const tld = "." + parts[parts.length - 1];
  const sld = parts.length >= 2 ? parts[parts.length - 2] : hostname;
  const pathLower = parsed.pathname.toLowerCase();

  // Skip legit domains
  if (KNOWN_LEGIT_DOMAINS.has(hostname)) return [];

  // --- Pattern 1: suspicious domain keyword pairs ---
  const domainWords = sld.replace(/[-_]/g, " ").split(/\s+/).filter(w => w.length > 3);
  const SCAM_KEYWORDS = new Set([
    "login","secure","verify","update","account","confirm","billing","payment",
    "auth","signin","password","recover","support","official","alert","notice",
    "bank","paypal","amazon","microsoft","google","apple","netflix","coinbase",
    "crypto","wallet","bitcoin","nft","prize","winner","lottery","lucky",
    "claim","reward","gift","free","bonus","refund","tax","irs","fbi",
    "mail","delivery","parcel","tracking","customs","package","order",
    "phish","scam","fraud","hack","steal","fake","copy","clone",
  ]);

  const scamWords = domainWords.filter(w => SCAM_KEYWORDS.has(w));
  if (scamWords.length >= 2) {
    patterns.push({
      text: scamWords.slice(0, 3).join(" "),
      category: "PHISHING",
      frequency: 1,
      specificityScore: 0.82,
      suggestedWeight: 18,
      suggestedSeverity: "high",
      sourceExamples: [`From live URLhaus/OpenPhish feed: ${hostname}`],
    });
  }

  // --- Pattern 2: malicious path component ---
  const pathSegments = pathLower.split("/").filter(s => s.length > 3 && s.length < 40);
  const MALICIOUS_PATH_KEYWORDS = new Set([
    "login","signin","verify","confirm","update","secure","account","billing",
    "payment","credential","gate","payload","beacon","c2","rat","drop","loader",
    "stager","panel","upload","backdoor","shell","exploit","inject","overflow",
    "download","setup","install","crack","keygen","serial","patch","warez",
    "phish","steal","grab","dump","spread","propagate","infect","execute",
  ]);

  for (const seg of pathSegments) {
    const cleanSeg = seg.replace(/[^a-z]/g, "");
    if (MALICIOUS_PATH_KEYWORDS.has(cleanSeg) && cleanSeg.length > 4) {
      patterns.push({
        text: cleanSeg + " path phishing",
        category: "PHISHING",
        frequency: 1,
        specificityScore: 0.72,
        suggestedWeight: 14,
        suggestedSeverity: "high",
        sourceExamples: [`Path: ${parsed.pathname} from ${hostname}`],
      });
      break; // one path pattern per URL
    }
  }

  // --- Pattern 3: high-risk TLD combined with scam SLD word ---
  if (HIGH_RISK_TLDS.has(tld) && scamWords.length >= 1) {
    const patText = scamWords[0] + tld;
    patterns.push({
      text: patText,
      category: "DOMAIN_SQUATTING",
      frequency: 1,
      specificityScore: 0.78,
      suggestedWeight: 16,
      suggestedSeverity: "high",
      sourceExamples: [`Domain: ${hostname}`],
    });
  }

  return patterns;
}

// ---------------------------------------------------------------------------
// Fetch URLhaus recent text list (plain text, one URL per line)
// ---------------------------------------------------------------------------
async function fetchUrlhaus(): Promise<string[]> {
  try {
    const res = await fetch("https://urlhaus.abuse.ch/downloads/text_recent/", {
      headers: { "User-Agent": "ScamShield-ThreatIntel/1.0" },
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return [];
    const text = await res.text();
    return text.split("\n").filter(l => l.trim() && !l.startsWith("#")).slice(0, 500);
  } catch { return []; }
}

// ---------------------------------------------------------------------------
// Fetch OpenPhish feed (plain text, one URL per line)
// ---------------------------------------------------------------------------
async function fetchOpenPhish(): Promise<string[]> {
  try {
    const res = await fetch("https://openphish.com/feed.txt", {
      headers: { "User-Agent": "ScamShield-ThreatIntel/1.0" },
      signal: AbortSignal.timeout(10000),
    });
    if (!res.ok) return [];
    const text = await res.text();
    return text.split("\n").filter(l => l.trim() && !l.startsWith("#")).slice(0, 500);
  } catch { return []; }
}

// ---------------------------------------------------------------------------
// POST handler
// ---------------------------------------------------------------------------
export async function POST(req: NextRequest) {
  if (!(await requireAdmin(req))) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  try {
    // Fetch both feeds concurrently
    const [urlhausUrls, openPhishUrls] = await Promise.all([
      fetchUrlhaus(),
      fetchOpenPhish(),
    ]);

    const allUrls = [...new Set([...urlhausUrls, ...openPhishUrls])];
    const fetchedCount = { urlhaus: urlhausUrls.length, openphish: openPhishUrls.length };

    if (allUrls.length === 0) {
      return NextResponse.json({
        success: false,
        error: "Could not reach threat intel feeds. They may be temporarily down.",
        fetchedCount,
      });
    }

    // Extract patterns from all URLs
    const rawPatterns: ExtractedPattern[] = [];
    for (const url of allUrls) {
      rawPatterns.push(...extractPatternsFromUrl(url));
    }

    // Deduplicate extracted patterns by text
    const seenTexts = new Set<string>();
    const deduped = rawPatterns.filter(p => {
      const key = p.text.toLowerCase();
      if (seenTexts.has(key)) return false;
      seenTexts.add(key);
      return true;
    });

    // Load existing and merge (skip dups, upgrade if better)
    const existing = await readPatterns();
    const existingMap = new Map<string, { index: number; pattern: ExtractedPattern }>();
    existing.forEach((p, i) => existingMap.set(p.text.toLowerCase(), { index: i, pattern: p }));

    let added = 0, upgraded = 0, duplicatesSkipped = 0;
    const merged = [...existing];

    for (const incoming of deduped) {
      const key = incoming.text.toLowerCase();
      if (key.length < 4) continue;

      const existingEntry = existingMap.get(key);
      if (!existingEntry) {
        merged.push(incoming);
        existingMap.set(key, { index: merged.length - 1, pattern: incoming });
        added++;
      } else {
        const existRank = SEV_RANK[existingEntry.pattern.suggestedSeverity] ?? 0;
        const inRank = SEV_RANK[incoming.suggestedSeverity] ?? 0;
        if (incoming.suggestedWeight > existingEntry.pattern.suggestedWeight || inRank > existRank) {
          merged[existingEntry.index] = {
            ...existingEntry.pattern,
            suggestedWeight: Math.max(existingEntry.pattern.suggestedWeight, incoming.suggestedWeight),
            suggestedSeverity: inRank >= existRank ? incoming.suggestedSeverity : existingEntry.pattern.suggestedSeverity,
          };
          upgraded++;
        } else {
          duplicatesSkipped++;
        }
      }
    }

    await writePatterns(merged);

    return NextResponse.json({
      success: true,
      sources: fetchedCount,
      urlsProcessed: allUrls.length,
      patternsExtracted: deduped.length,
      added,
      upgraded,
      duplicatesSkipped,
      total: merged.length,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
