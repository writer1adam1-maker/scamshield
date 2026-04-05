// ============================================================================
// LLM Prompt Template — Pre-built prompt for any LLM to extract scam patterns
// Admins can copy-paste this prompt + raw fraud text into ChatGPT, Claude, etc.
// Then paste the JSON output back to import into ScamShieldy.
// ============================================================================

import type { ExtractedPattern } from "./pattern-extractor";

// ---------------------------------------------------------------------------
// The prompt template that admins copy into any LLM
// Includes a timestamp so each call generates fresh, unique results
// ---------------------------------------------------------------------------

export function buildLlmExtractionPrompt(fraudText?: string): string {
  const now = new Date();
  const sessionId = `SS-${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}-${Math.random().toString(36).slice(2,8).toUpperCase()}`;

  const textBlock = fraudText?.trim()
    ? fraudText.trim()
    : `[PASTE THE FRAUD REPORT, PHISHING EMAIL, SCAM MESSAGE, OR THREAT INTEL TEXT HERE — then send this entire message]`;

  return `You are a threat intelligence analyst for ScamShield, an AI-powered fraud detection system. Your job is to extract detection patterns from fraud/scam/malware text so they can be added to a real-time scam detector used by thousands of people.

Analysis session: ${sessionId} — ${now.toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
YOUR TASK
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Read the fraud text below and extract every short phrase (2–7 words) that a scam detection system could use to flag similar attacks in the future. Think like a forensic analyst: what specific language does this attacker use that other scammers also use? What phrases would betray this scam if it landed in someone's inbox?

Before writing any output, mentally go through these 6 lenses:

1. URGENCY — What time pressure or threat language is used?
2. AUTHORITY — What fake official or brand identity is claimed?
3. ACTION — What specific action does the attacker want the victim to take?
4. PAYMENT — What payment method or financial transfer is requested?
5. TECHNICAL — Are there URL tricks, file names, or technical pretexts?
6. WHAT DID I MISS? — Re-read for any pattern you haven't captured yet.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CATEGORIES — pick the most specific one per pattern:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

URGENCY                  — deadlines, threats, countdown, "act now"
FINANCIAL                — payment, wire, invoice, fees, gift cards
ROMANCE                  — love bombing, trust building, pig butchering setup
PHISHING                 — fake login, credential harvest, account verify
CRYPTO_INVESTMENT        — guaranteed returns, fake platforms, pig butchering
GOVERNMENT_IMPERSONATION — IRS, FBI, SSA, HMRC, ATO, law enforcement
TECH_SUPPORT             — fake virus, remote access, fake Microsoft/Apple
PACKAGE_DELIVERY         — fake DHL/FedEx/USPS, customs fee, tracking
LOTTERY_PRIZE            — fake winnings, advance fee, prize claim
EMPLOYMENT               — fake job, reshipping mule, money mule recruitment
MALWARE_DISTRIBUTION     — download triggers, fake software, trojan delivery
DRIVE_BY_DOWNLOAD        — silent install pretexts, "click to view" traps
RANSOMWARE_DELIVERY      — fake invoices with macros, file encryption threats
EXPLOIT_KIT              — fake plugin/update prompts, vulnerability pretexts
SPYWARE_STALKERWARE      — monitoring app, keylogger, RAT delivery
FAKE_ANTIVIRUS           — scareware, fake security alert, rogue AV
MALVERTISING             — ad redirect, malicious popup, "you've been selected"
CREDENTIAL_STEALER       — info-stealer, browser hijack, form grabbing
BOTNET_C2                — bot recruitment, zombie network, DDoS-for-hire
URL_OBFUSCATION          — encoded URLs, redirect chains, link shortener abuse
DOMAIN_SQUATTING         — typosquat, homoglyph, brand look-alike domain
SEO_POISONING            — fake search results, cloaked pages
SOCIAL_ENGINEERING       — manipulation not covered above
BRAND_IMPERSONATION      — fake brand page, logo abuse, look-alike design
GENERIC                  — use only if nothing else fits

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
SEVERITY & WEIGHT GUIDE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

"low"      weight 1–8   — also appears in legitimate content (e.g., "your account")
"medium"   weight 9–15  — somewhat specific to scams (e.g., "verify your identity now")
"high"     weight 16–22 — rarely in legitimate messages (e.g., "gift card payment required")
"critical" weight 23–30 — almost exclusively in scams (e.g., "send bitcoin to wallet address")

specificityScore: 0.0 = common in normal text, 1.0 = only ever seen in scam/fraud content

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
QUALITY RULES:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

✓ Extract 2–7 word phrases specific to fraud/malware contexts
✓ Include brand impersonation fragments (e.g., "microsoft security alert team")
✓ Include crypto/payment patterns (e.g., "send bitcoin to this address")
✓ Include fake authority language (e.g., "federal case number assigned")
✓ Extract 20–80 patterns depending on text length — be generous, not selective
✗ Skip generic filler: "please note", "thank you", "dear valued customer"
✗ Skip patterns that appear constantly in legitimate emails/websites
✗ Skip near-duplicates — keep only the most specific version

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
OUTPUT — JSON ARRAY ONLY (no markdown, no explanation):
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Start your response with [ and end with ]. Nothing before [, nothing after ].

Each item must follow this exact structure:
{
  "text": "the scam phrase in lowercase (2-7 words)",
  "category": "CATEGORY_NAME",
  "frequency": 1,
  "specificityScore": 0.88,
  "suggestedWeight": 18,
  "suggestedSeverity": "high",
  "sourceExamples": ["Exact sentence from the source text containing this phrase"]
}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
FRAUD TEXT TO ANALYZE:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

${textBlock}`;
}

// Keep a static export for backward compatibility — but the function above
// should always be used in UI so each copy gets a fresh session ID.
export const LLM_EXTRACTION_PROMPT = buildLlmExtractionPrompt();

// ---------------------------------------------------------------------------
// JSON schema the LLM should output (for reference / validation)
// ---------------------------------------------------------------------------

export const LLM_OUTPUT_SCHEMA = `{
  "type": "array",
  "items": {
    "type": "object",
    "required": ["text", "category", "frequency", "specificityScore", "suggestedWeight", "suggestedSeverity", "sourceExamples"],
    "properties": {
      "text": {
        "type": "string",
        "description": "The scam phrase/pattern, 2-8 words, lowercase"
      },
      "category": {
        "type": "string",
        "enum": [
          "URGENCY","FINANCIAL","ROMANCE","PHISHING","CRYPTO_INVESTMENT",
          "GOVERNMENT_IMPERSONATION","TECH_SUPPORT","PACKAGE_DELIVERY",
          "LOTTERY_PRIZE","EMPLOYMENT","MALWARE_DISTRIBUTION","DRIVE_BY_DOWNLOAD",
          "RANSOMWARE_DELIVERY","EXPLOIT_KIT","SPYWARE_STALKERWARE",
          "FAKE_ANTIVIRUS","MALVERTISING","CREDENTIAL_STEALER","BOTNET_C2",
          "URL_OBFUSCATION","DOMAIN_SQUATTING","SEO_POISONING",
          "SOCIAL_ENGINEERING","BRAND_IMPERSONATION","GENERIC"
        ]
      },
      "frequency": { "type": "number" },
      "specificityScore": { "type": "number", "minimum": 0, "maximum": 1 },
      "suggestedWeight": { "type": "number", "minimum": 1, "maximum": 30 },
      "suggestedSeverity": { "type": "string", "enum": ["low","medium","high","critical"] },
      "sourceExamples": { "type": "array", "items": { "type": "string" }, "minItems": 1, "maxItems": 3 }
    }
  }
}`;

// ---------------------------------------------------------------------------
// Parse raw LLM JSON output into ExtractedPattern[]
// ---------------------------------------------------------------------------

const VALID_CATEGORIES = new Set([
  "URGENCY", "FINANCIAL", "ROMANCE", "PHISHING", "CRYPTO_INVESTMENT",
  "GOVERNMENT_IMPERSONATION", "TECH_SUPPORT", "PACKAGE_DELIVERY",
  "LOTTERY_PRIZE", "EMPLOYMENT",
  // New malware/web categories
  "MALWARE_DISTRIBUTION", "DRIVE_BY_DOWNLOAD", "RANSOMWARE_DELIVERY",
  "EXPLOIT_KIT", "SPYWARE_STALKERWARE", "FAKE_ANTIVIRUS", "MALVERTISING",
  "CREDENTIAL_STEALER", "BOTNET_C2", "URL_OBFUSCATION", "DOMAIN_SQUATTING",
  "SEO_POISONING", "SOCIAL_ENGINEERING", "BRAND_IMPERSONATION", "GENERIC",
]);

const VALID_SEVERITIES = new Set(["low", "medium", "high", "critical"]);

/**
 * Parse the raw JSON output from any LLM into validated ExtractedPattern[].
 * Handles common LLM quirks: markdown code fences, trailing commas, explanatory text.
 */
export function parseLlmOutput(raw: string): ExtractedPattern[] {
  // Strip markdown code fences if present
  let cleaned = raw.trim();
  cleaned = cleaned.replace(/^```(?:json)?\s*/i, "").replace(/\s*```$/i, "");

  // Strip session header comment if present
  cleaned = cleaned.replace(/^\/\/.*\n/gm, "").trim();

  // Try to find the JSON array in the output
  const arrayStart = cleaned.indexOf("[");
  const arrayEnd = cleaned.lastIndexOf("]");
  if (arrayStart === -1 || arrayEnd === -1 || arrayEnd <= arrayStart) {
    throw new Error("Could not find a JSON array in the LLM output. Expected output starting with [ and ending with ].");
  }

  const jsonStr = cleaned.slice(arrayStart, arrayEnd + 1);

  let parsed: unknown;
  try {
    parsed = JSON.parse(jsonStr);
  } catch {
    // Try removing trailing commas (common LLM mistake)
    const fixedJson = jsonStr.replace(/,\s*([}\]])/g, "$1");
    try {
      parsed = JSON.parse(fixedJson);
    } catch {
      throw new Error("Failed to parse LLM output as JSON. Ensure the output is a valid JSON array.");
    }
  }

  if (!Array.isArray(parsed)) {
    throw new Error("LLM output is not an array. Expected a JSON array of patterns.");
  }

  const results: ExtractedPattern[] = [];

  for (const item of parsed) {
    if (typeof item !== "object" || item === null) continue;

    const obj = item as Record<string, unknown>;

    // Validate required fields
    const text = typeof obj.text === "string" ? obj.text.trim().toLowerCase() : "";
    if (text.length < 2) continue;

    const category = typeof obj.category === "string" && VALID_CATEGORIES.has(obj.category)
      ? obj.category
      : "GENERIC";

    const frequency = typeof obj.frequency === "number" && obj.frequency > 0
      ? Math.round(obj.frequency)
      : 1;

    const specificityScore = typeof obj.specificityScore === "number"
      ? Math.max(0, Math.min(1, obj.specificityScore))
      : 0.5;

    const suggestedWeight = typeof obj.suggestedWeight === "number"
      ? Math.max(1, Math.min(30, Math.round(obj.suggestedWeight)))
      : 10;

    const suggestedSeverity = typeof obj.suggestedSeverity === "string" && VALID_SEVERITIES.has(obj.suggestedSeverity)
      ? obj.suggestedSeverity as "low" | "medium" | "high" | "critical"
      : "medium";

    const sourceExamples = Array.isArray(obj.sourceExamples)
      ? (obj.sourceExamples as unknown[])
          .filter((e): e is string => typeof e === "string" && e.length > 0)
          .slice(0, 3)
      : [];

    results.push({
      text,
      category,
      frequency,
      specificityScore,
      suggestedWeight,
      suggestedSeverity,
      sourceExamples,
    });
  }

  return results;
}
