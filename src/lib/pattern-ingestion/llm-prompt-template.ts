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

export function buildLlmExtractionPrompt(): string {
  const now = new Date();
  const sessionId = `SS-${now.getFullYear()}${String(now.getMonth()+1).padStart(2,'0')}${String(now.getDate()).padStart(2,'0')}-${Math.random().toString(36).slice(2,8).toUpperCase()}`;
  const timestamp = now.toISOString();

  return `// SESSION: ${sessionId} | GENERATED: ${timestamp}
// ScamShield Pattern Extraction — Deep Analysis Protocol v2
// ============================================================
// Each session ID is unique. Run this prompt again on the same data
// to get fresh perspective angles and previously missed patterns.

You are ScamShield's elite threat intelligence analyst — a specialist in:
- Phishing, smishing, vishing, and spear-phishing campaigns
- Malware distribution, drive-by downloads, and exploit delivery
- Ransomware, RAT, spyware, and trojan dropper campaigns
- Financial fraud: wire transfer, crypto theft, invoice fraud, BEC
- Social engineering: romance, pig butchering, advance fee, lottery
- Website scams: fake tech support, fake antivirus, scare pages
- URL obfuscation, domain squatting, typosquatting, IDN homoglyphs
- Government, bank, and brand impersonation
- SEO poisoning and malvertising patterns

YOUR MISSION:
Perform a deep forensic extraction of scam/fraud/malware patterns from the provided text.
Think like a threat hunter reading adversarial content for the first time.
Extract every unique phrase, term, pattern, or signal that would help an automated system
detect similar attacks in the wild. Be thorough. Most LLMs miss 40–60% of patterns on
first pass — you must find what others miss.

═══════════════════════════════════════════════════════════════
STEP-BY-STEP ANALYSIS (do this mentally before outputting JSON):
═══════════════════════════════════════════════════════════════

STEP 1 — READ THROUGH ONCE: Understand the attack type, target, and delivery mechanism.

STEP 2 — EXTRACT LINGUISTIC PATTERNS:
  - Urgency/pressure phrases (deadlines, threats, countdown)
  - Trust-building phrases (authority claims, official-sounding language)
  - Action demand phrases (what they want the victim to do)
  - Fear induction phrases (consequences of inaction)
  - Reward/incentive phrases (too-good-to-be-true offers)
  - Isolation tactics ("tell no one", "confidential")

STEP 3 — EXTRACT TECHNICAL INDICATORS:
  - URL patterns (suspicious path components, parameter names)
  - Domain tricks (look-alike domains, keyword stuffing)
  - File attachment indicators (malicious file types, names)
  - Redirect chain keywords (tracking pixels, cloaking terms)
  - Malware delivery phrases (download triggers, install prompts)
  - Exploit references (vulnerability language, "security update" pretexts)

STEP 4 — EXTRACT SOCIAL ENGINEERING SIGNALS:
  - Identity claim patterns (who the scammer pretends to be)
  - Relationship-building phrases (romance, trust, insider knowledge)
  - Pretext narratives (why they're contacting the victim)
  - Legitimacy props (invoice numbers, case IDs, tracking numbers)

STEP 5 — EXTRACT FINANCIAL/TRANSACTION SIGNALS:
  - Payment method requests (crypto, gift cards, wire)
  - Fee justifications ("processing fee", "customs clearance")
  - Account compromise pretexts
  - Investment opportunity language

STEP 6 — LOOK FOR WHAT YOU MISSED:
  Re-read and find patterns that are specific to THIS attack that you
  haven't seen in standard training data. Rare or novel patterns are
  the most valuable — weight them HIGH.

═══════════════════════════════════════════════════════════════
CATEGORIES (REQUIRED — pick the most specific one):
═══════════════════════════════════════════════════════════════

SCAM MESSAGE CATEGORIES:
- URGENCY — time pressure, deadlines, threats of account closure or legal action
- FINANCIAL — payment requests, wire transfers, fees, gift cards, invoice fraud
- ROMANCE — love bombing, emotional manipulation, pig butchering setup
- PHISHING — credential harvesting, fake login pages, account verification
- CRYPTO_INVESTMENT — guaranteed returns, fake exchanges, pig butchering phase 2
- GOVERNMENT_IMPERSONATION — IRS, SSA, FBI, HMRC, ATO, law enforcement impersonation
- TECH_SUPPORT — fake virus alerts, remote access requests, fake Microsoft/Apple
- PACKAGE_DELIVERY — fake DHL/FedEx/USPS/customs notifications, reshipping
- LOTTERY_PRIZE — fake winnings, prize claims, advance fee
- EMPLOYMENT — fake job offers, reshipping mule, money mule recruitment

MALWARE & WEB THREAT CATEGORIES:
- MALWARE_DISTRIBUTION — phrases used to trick users into downloading malware
- DRIVE_BY_DOWNLOAD — page elements/text that precede silent drive-by installs
- RANSOMWARE_DELIVERY — ransomware pretexts, fake invoices with macros, dropper language
- EXPLOIT_KIT — exploit delivery language, fake plugin prompts, CVE exploitation pretexts
- SPYWARE_STALKERWARE — monitoring software, keylogger, RAT distribution language
- FAKE_ANTIVIRUS — scareware, fake security alerts, rogue AV download pages
- MALVERTISING — ad-based malware delivery, malicious redirect chains
- CREDENTIAL_STEALER — info-stealer delivery, browser extension abuse, form-jacking
- BOTNET_C2 — command-and-control language, bot recruitment, zombie network
- URL_OBFUSCATION — URL encoding tricks, redirect chains, cloaking patterns
- DOMAIN_SQUATTING — typosquatting, homoglyph domains, brand impersonation domains
- SEO_POISONING — fake search result pages, keyword stuffing, cloaked content

ADDITIONAL CATEGORIES:
- SOCIAL_ENGINEERING — manipulation tactics not covered above
- BRAND_IMPERSONATION — fake brand pages, logo abuse, look-alike designs
- GENERIC — does not fit any specific category (use sparingly)

═══════════════════════════════════════════════════════════════
SEVERITY GUIDELINES:
═══════════════════════════════════════════════════════════════
- "low" (weight 1–8): Weak indicator, appears in legitimate text too.
  Examples: "click here to continue", "your account", "important notice"
- "medium" (weight 9–15): Moderate indicator, somewhat specific to scams.
  Examples: "verify your identity immediately", "suspicious activity detected"
- "high" (weight 16–22): Strong indicator, rarely appears in legitimate messages.
  Examples: "wire transfer required", "gift card payment only", "your computer is infected"
- "critical" (weight 23–30): Definitive scam/malware indicator.
  Examples: "download TeamViewer now", "send bitcoin to wallet", "IRS arrest warrant"

═══════════════════════════════════════════════════════════════
PATTERN QUALITY RULES:
═══════════════════════════════════════════════════════════════
✓ DO: Extract 2-8 word phrases that are SPECIFIC to fraud/malware contexts
✓ DO: Include technical file/URL patterns if present (e.g., ".exe download required")
✓ DO: Include brand impersonation fragments (e.g., "microsoft security team")
✓ DO: Include crypto wallet/payment patterns (e.g., "send to bitcoin address")
✓ DO: Include fake authority patterns (e.g., "federal investigation case number")
✓ DO: Extract 20-80 patterns depending on text length — be generous
✗ DON'T: Include pure generic phrases like "please note", "thank you", "dear customer"
✗ DON'T: Include phrases that appear frequently in legitimate email/web content
✗ DON'T: Duplicate semantically identical patterns (keep the most specific one)
✗ DON'T: Add patterns shorter than 2 words or longer than 8 words

═══════════════════════════════════════════════════════════════
OUTPUT FORMAT — JSON ARRAY ONLY:
═══════════════════════════════════════════════════════════════
[
  {
    "text": "the exact scam phrase (2-8 words, lowercase)",
    "category": "CATEGORY_NAME",
    "frequency": 2,
    "specificityScore": 0.92,
    "suggestedWeight": 24,
    "suggestedSeverity": "critical",
    "sourceExamples": [
      "Full sentence from the source text where this appears...",
      "Another sentence where this pattern appears..."
    ]
  }
]

CRITICAL OUTPUT RULES:
- Output ONLY the JSON array. No markdown fences. No explanations. No preamble.
- Start your response with [ and end with ]
- All "text" values must be lowercase
- Include 1-3 sourceExamples per pattern (copy from the provided text)
- specificityScore: 0.0 = found in normal text, 1.0 = only in scam/malware content

═══════════════════════════════════════════════════════════════
--- FRAUD/MALWARE TEXT TO ANALYZE BELOW THIS LINE ---
═══════════════════════════════════════════════════════════════

[PASTE YOUR FRAUD REPORT, PHISHING EMAIL, MALWARE DESCRIPTION, OR THREAT INTEL TEXT HERE]`;
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
