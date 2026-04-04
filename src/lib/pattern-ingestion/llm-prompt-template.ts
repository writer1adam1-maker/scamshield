// ============================================================================
// LLM Prompt Template — Pre-built prompt for any LLM to extract scam patterns
// Admins can copy-paste this prompt + raw fraud text into ChatGPT, Claude, etc.
// Then paste the JSON output back to import into ScamShieldy.
// ============================================================================

import type { ExtractedPattern } from "./pattern-extractor";

// ---------------------------------------------------------------------------
// The prompt template that admins copy into any LLM
// ---------------------------------------------------------------------------

export const LLM_EXTRACTION_PROMPT = `You are a fraud pattern analyst. Your job is to read the provided fraud report text and extract unique scam phrases/patterns that can be used to detect similar scams in the future.

INSTRUCTIONS:
1. Read all the fraud text carefully.
2. Identify unique scam phrases and patterns (2-6 words each) that are characteristic of scam/fraud messages.
3. Focus on phrases that would NOT appear in legitimate messages — the more specific to scams, the better.
4. Classify each pattern by category (see list below).
5. Rate the severity and suggest a detection weight.
6. Include 2 example source sentences for each pattern (from the provided text).
7. Output ONLY a JSON array matching the schema below. No other text.

CATEGORIES (pick one per pattern):
- URGENCY — time pressure, deadlines, threats of action
- FINANCIAL — payment requests, wire transfers, fees
- ROMANCE — emotional manipulation, love bombing
- PHISHING — credential harvesting, fake logins, verification requests
- CRYPTO_INVESTMENT — crypto/investment fraud, guaranteed returns
- GOVERNMENT_IMPERSONATION — IRS, SSA, law enforcement impersonation
- TECH_SUPPORT — fake virus alerts, remote access requests
- PACKAGE_DELIVERY — fake shipping/tracking/customs notifications
- LOTTERY_PRIZE — fake winnings, prize claims
- EMPLOYMENT — fake job offers, reshipping scams
- GENERIC — does not fit any specific category

SEVERITY GUIDELINES:
- "low" — common but weak indicator, often appears in legitimate text too
- "medium" — moderate indicator, somewhat specific to scams
- "high" — strong indicator, rarely appears in legitimate messages
- "critical" — definitive scam indicator, almost never legitimate

WEIGHT GUIDELINES (1-30):
- 1-5: Weak signal, common words used in scammy context
- 6-15: Moderate signal, notable scam phrasing
- 16-25: Strong signal, highly characteristic of scams
- 26-30: Definitive signal, essentially guarantees scam content

OUTPUT FORMAT (JSON array):
[
  {
    "text": "the exact scam phrase (2-6 words)",
    "category": "CATEGORY_NAME",
    "frequency": 1,
    "specificityScore": 0.85,
    "suggestedWeight": 20,
    "suggestedSeverity": "high",
    "sourceExamples": [
      "Full sentence where this pattern appears...",
      "Another sentence where this pattern appears..."
    ]
  }
]

IMPORTANT:
- Extract 10-50 patterns depending on how much text is provided.
- Each pattern should be 2-6 words.
- Do NOT include generic phrases like "click here" or "please note".
- Focus on phrases that are SPECIFIC to scam/fraud contexts.
- Output ONLY the JSON array. No markdown, no explanations, no code fences.

--- FRAUD TEXT BELOW ---

[PASTE YOUR FRAUD REPORT TEXT HERE]`;

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
        "description": "The scam phrase/pattern, 2-6 words"
      },
      "category": {
        "type": "string",
        "enum": ["URGENCY", "FINANCIAL", "ROMANCE", "PHISHING", "CRYPTO_INVESTMENT", "GOVERNMENT_IMPERSONATION", "TECH_SUPPORT", "PACKAGE_DELIVERY", "LOTTERY_PRIZE", "EMPLOYMENT", "GENERIC"]
      },
      "frequency": {
        "type": "number",
        "description": "How many times this pattern was seen in the provided text"
      },
      "specificityScore": {
        "type": "number",
        "minimum": 0,
        "maximum": 1,
        "description": "How specific this phrase is to scams (0=generic, 1=definitive scam indicator)"
      },
      "suggestedWeight": {
        "type": "number",
        "minimum": 1,
        "maximum": 30,
        "description": "Detection weight for the pattern engine"
      },
      "suggestedSeverity": {
        "type": "string",
        "enum": ["low", "medium", "high", "critical"]
      },
      "sourceExamples": {
        "type": "array",
        "items": { "type": "string" },
        "minItems": 1,
        "maxItems": 3,
        "description": "Example sentences from the source text where this pattern appears"
      }
    }
  }
}`;

// ---------------------------------------------------------------------------
// Parse raw LLM JSON output into ExtractedPattern[]
// ---------------------------------------------------------------------------

const VALID_CATEGORIES = new Set([
  "URGENCY", "FINANCIAL", "ROMANCE", "PHISHING", "CRYPTO_INVESTMENT",
  "GOVERNMENT_IMPERSONATION", "TECH_SUPPORT", "PACKAGE_DELIVERY",
  "LOTTERY_PRIZE", "EMPLOYMENT", "GENERIC",
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
    const text = typeof obj.text === "string" ? obj.text.trim() : "";
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
