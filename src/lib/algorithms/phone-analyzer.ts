// ============================================================================
// ScamShield Phone Number Scam Analyzer
// Extracts phone numbers from text and scores them for scam risk based on:
// - Premium rate prefixes
// - Known scam area codes
// - VoIP indicators
// - Context proximity (urgency words near phone numbers)
// ============================================================================

import { PhoneAnalysisResult, PhoneMatch } from './types';

// ---------------------------------------------------------------------------
// US Premium-rate / known-abuse area codes
// ---------------------------------------------------------------------------

/** International premium-rate prefixes (caller pays high per-minute fee) */
const PREMIUM_RATE_PREFIXES = new Set([
  '900', '976',   // US 900/976 premium services
  '+44-9', '44-9', // UK premium rate
  '+267', '+268',  // Botswana (high-abuse, used for prize/lottery scams)
  '+225', '+226',  // West Africa
  '+509', '+232',  // Haiti, Sierra Leone (documented scam hubs)
]);

/** US area codes with documented high scam call rates (FTC/FCC data 2024-2025) */
const HIGH_SCAM_AREA_CODES = new Set([
  // Caribbean / US territory codes widely spoofed
  '242', '246', '268', '284', '345', '441', '473', '649',
  '664', '721', '758', '767', '784', '809', '829', '849',
  '868', '869', '876',
  // US area codes with high robocall/scam rates (YouMail 2025)
  '202', '310', '404', '702', '786', '305', '347', '646', '917',
]);

/** US toll-free prefixes */
const TOLL_FREE_PREFIXES = new Set(['800', '888', '877', '866', '855', '844', '833', '822']);

// ---------------------------------------------------------------------------
// Known scam call center numbers (partial prefixes — real data)
// ---------------------------------------------------------------------------

const KNOWN_SCAM_PARTIAL_PREFIXES = [
  // Microsoft/tech support scam call centers (India)
  /^\+?91[-\s]?[6-9]\d{9}$/,
  // Nigerian advance fee scam numbers
  /^\+?234[-\s]?\d{10}$/,
  // UK-spoofed numbers used in HMRC scams
  /^\+?44[-\s]?20[-\s]?\d{8}$/,
];

// ---------------------------------------------------------------------------
// Phone number extraction regexes
// ---------------------------------------------------------------------------

const PHONE_PATTERNS = [
  // US/Canada: (XXX) XXX-XXXX or XXX-XXX-XXXX or +1XXXXXXXXXX
  /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}/g,
  // International: +CC XXXXXXXXXX
  /\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}/g,
  // Compact: 10-digit run
  /\b\d{10}\b/g,
];

// ---------------------------------------------------------------------------
// Context danger signals — urgency words near phone numbers
// ---------------------------------------------------------------------------

const CONTEXT_DANGER_PATTERN = /\b(call\s*(now|immediately|asap|urgent)|contact\s*(us|immediately|asap)|dial|reach\s*us|helpline|support\s*(line|number)|toll[- ]?free)\b/i;

// ---------------------------------------------------------------------------
// Number normalization
// ---------------------------------------------------------------------------

function normalizePhone(raw: string): string {
  return raw.replace(/[^\d+]/g, '');
}

function extractAreaCode(normalized: string): string {
  const digits = normalized.replace(/^\+?1/, '');
  return digits.substring(0, 3);
}

function detectCountry(normalized: string): string {
  if (normalized.startsWith('+91') || normalized.startsWith('91') && normalized.length === 12) return 'India';
  if (normalized.startsWith('+234') || normalized.startsWith('234')) return 'Nigeria';
  if (normalized.startsWith('+44') || normalized.startsWith('44') && normalized.length === 12) return 'UK';
  if (normalized.startsWith('+1') || normalized.length === 10 || normalized.length === 11) return 'US/Canada';
  if (normalized.startsWith('+33')) return 'France';
  if (normalized.startsWith('+49')) return 'Germany';
  if (normalized.startsWith('+55')) return 'Brazil';
  if (normalized.startsWith('+52')) return 'Mexico';
  return 'Unknown';
}

// ---------------------------------------------------------------------------
// Score a single phone number
// ---------------------------------------------------------------------------

function scorePhone(raw: string, fullText: string): PhoneMatch {
  const normalized = normalizePhone(raw);
  const areaCode = extractAreaCode(normalized);
  const country = detectCountry(normalized);
  const flags: string[] = [];

  let scamScore = 0;

  // Premium rate check
  const isPremiumRate = PREMIUM_RATE_PREFIXES.has(areaCode) ||
    PREMIUM_RATE_PREFIXES.has(normalized.substring(0, 6));
  if (isPremiumRate) { scamScore += 0.35; flags.push('Premium-rate number'); }

  // Toll-free check — toll-free alone is NOT suspicious (legit businesses use them)
  // Only informational; score boost removed to avoid flagging customer service numbers
  const isTollFree = TOLL_FREE_PREFIXES.has(areaCode);
  if (isTollFree) { flags.push('Toll-free number'); }

  // High-scam area code
  const isSuspiciousAreaCode = HIGH_SCAM_AREA_CODES.has(areaCode);
  if (isSuspiciousAreaCode) { scamScore += 0.20; flags.push(`Area code ${areaCode} has elevated scam rate`); }

  // Known scam call center prefix
  const isKnownScamPrefix = KNOWN_SCAM_PARTIAL_PREFIXES.some((rx) => rx.test(normalized));
  if (isKnownScamPrefix) { scamScore += 0.30; flags.push('Number matches known scam call center origin'); }

  // VoIP indicator: 10-digit numbers starting with 1-970, 1-202, 1-206, 1-332 area codes
  const voipAreaCodes = new Set(['206', '332', '650', '510', '726', '531']);
  const isVoIP = voipAreaCodes.has(areaCode) ||
    (country === 'US/Canada' && normalized.length === 10 && voipAreaCodes.has(normalized.substring(0, 3)));
  if (isVoIP) { scamScore += 0.05; flags.push('Possible VoIP number'); }

  // Context check: dangerous words near phone number
  const rawIndex = fullText.indexOf(raw.substring(0, 8));
  if (rawIndex !== -1) {
    const surrounding = fullText.substring(
      Math.max(0, rawIndex - 100),
      Math.min(fullText.length, rawIndex + raw.length + 100)
    );
    if (CONTEXT_DANGER_PATTERN.test(surrounding)) {
      scamScore += 0.15;
      flags.push('Urgency language near phone number');
    }
  }

  // India origin in scam context (tech support / investment scam hubs)
  if (country === 'India') { scamScore += 0.15; flags.push('India-originating number (common tech support / investment scam origin)'); }
  if (country === 'Nigeria') { scamScore += 0.25; flags.push('Nigeria-originating number (common advance-fee scam origin)'); }

  return {
    number: raw,
    normalizedNumber: normalized,
    country,
    isPremiumRate,
    isTollFree,
    isVoIP,
    isSuspiciousAreaCode,
    scamAssociationScore: Math.min(1, scamScore),
    flags,
  };
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export function analyzePhoneNumbers(text: string): PhoneAnalysisResult {
  const startTime = performance.now();
  const rawNumbers = new Set<string>();

  for (const pattern of PHONE_PATTERNS) {
    const matches = text.match(pattern) || [];
    for (const m of matches) {
      rawNumbers.add(m.trim());
    }
  }

  if (rawNumbers.size === 0) {
    return {
      detected: false,
      phones: [],
      highestRisk: 0,
      flags: [],
      processingTimeMs: Math.round((performance.now() - startTime) * 100) / 100,
    };
  }

  const phones: PhoneMatch[] = [];
  for (const raw of rawNumbers) {
    // Skip very short / likely false positives
    if (normalizePhone(raw).replace(/^\+?1/, '').length < 9) continue;
    phones.push(scorePhone(raw, text));
  }

  const highestRisk = phones.length > 0
    ? Math.max(...phones.map((p) => p.scamAssociationScore))
    : 0;

  const allFlags = Array.from(new Set(phones.flatMap((p) => p.flags)));

  return {
    detected: phones.length > 0 && highestRisk > 0.15,
    phones,
    highestRisk,
    flags: allFlags,
    processingTimeMs: Math.round((performance.now() - startTime) * 100) / 100,
  };
}
