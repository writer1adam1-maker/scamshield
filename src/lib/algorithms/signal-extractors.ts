// ============================================================================
// VERIDICT Signal Extraction Utilities
// ============================================================================

import {
  Signal,
  SignalType,
  UrlAnalysis,
  WhoisData,
  SslData,
  PhoneAnalysis,
  CryptoWalletDetection,
  EmailHeaderAnomaly,
} from './types';

// ---------------------------------------------------------------------------
// URL shortener domains — tiered by real-world abuse rates
// ---------------------------------------------------------------------------

/** HIGH_ABUSE shorteners: documented malware/phishing delivery rates ≥ 49% */
const URL_SHORTENERS_HIGH_ABUSE = new Set([
  'goo.su',   // 89% malware delivery rate (SpamHaus 2024)
  'is.gd',    // 49% abuse rate
]);

/** MEDIUM_ABUSE shorteners: 10–17% abuse rate */
const URL_SHORTENERS_MEDIUM_ABUSE = new Set([
  'tinyurl.com', // 17%
  't.ly',        // 15%
  'rebrand.ly',  // 10%
]);

/** LOW_ABUSE shorteners: < 10% abuse rate — flag but low confidence */
const URL_SHORTENERS_LOW_ABUSE = new Set([
  'qrco.de', 'bit.ly', 't.co', 'ow.ly', 'buff.ly', 'shorturl.at',
  'cutt.ly', 'tiny.cc', 'lnkd.in', 'rb.gy', 's.id', 'v.gd', 'clck.ru',
  'u.to', 'shorte.st', 'adf.ly', 'bc.vc', 'j.mp',
  // legacy / still in circulation
  'goo.gl', 'dlvr.it', 'db.tt', 'qr.ae', 'trib.al', 'soo.gd',
  'budurl.com', 'yourls.org', 'bl.ink', 'short.io', 'linktr.ee',
  'han.gl', 'surl.li',
]);

/** Combined set for fast membership tests */
const URL_SHORTENERS = new Set([
  ...URL_SHORTENERS_HIGH_ABUSE,
  ...URL_SHORTENERS_MEDIUM_ABUSE,
  ...URL_SHORTENERS_LOW_ABUSE,
]);

/** Resolve a shortener's abuse tier for score weighting */
function getShortenerAbuseTier(hostname: string): 'high' | 'medium' | 'low' | null {
  if (URL_SHORTENERS_HIGH_ABUSE.has(hostname)) return 'high';
  if (URL_SHORTENERS_MEDIUM_ABUSE.has(hostname)) return 'medium';
  if (URL_SHORTENERS_LOW_ABUSE.has(hostname)) return 'low';
  return null;
}

// ---------------------------------------------------------------------------
// Suspicious TLDs — tiered by real-world malicious-domain percentage
// Source: Spamhaus Domain Reputation Data, SURBL, URLhaus (2024–2025)
// ---------------------------------------------------------------------------

/**
 * Tier 1 — >80% of registered domains are malicious.
 * Each hit adds 25 confidence points to the TLD signal.
 */
const SUSPICIOUS_TLDS_TIER1 = new Set([
  '.buzz',  // 98.9% malicious
  '.wang',  // 98.7%
  '.host',  // 98.5%
  '.icu',   // 91.6%
  '.live',  // 91.3%
  '.tk',    // 88.5% (Freenom abuse; now ICANN-delegated but legacy abuse)
  '.gq',    // 87.6% (Freenom)
  '.cf',    // 85.4% (Freenom)
  '.ga',    // 84.9% (Freenom)
  '.info',  // 84.6%
  '.xin',   // 82%+
  '.top',   // 81.3%
  '.ml',    // 80.0% (Freenom)
]);

/**
 * Tier 2 — 50–80% malicious.
 * Each hit adds 18 confidence points.
 */
const SUSPICIOUS_TLDS_TIER2 = new Set([
  '.cn',     // 74.8%
  '.us',     // 69.1% (surprisingly high domestic abuse rate)
  '.xyz',    // 65.8%
  '.online', // 62.2%
  '.li',     // 57%
]);

/**
 * Tier 3 — Notable abuse (emerging or niche TLDs).
 * Each hit adds 12 confidence points.
 */
const SUSPICIOUS_TLDS_TIER3 = new Set([
  '.sbs', '.cfd', '.rest', '.bond', '.ru', '.dev',
  '.pw', '.cc', '.ws', '.su', '.club', '.site', '.biz',
]);

/**
 * Tier 4 — Moderate abuse or confusable-with-file-extension TLDs.
 * Each hit adds 8 confidence points.
 */
const SUSPICIOUS_TLDS_TIER4 = new Set([
  '.work', '.click', '.link', '.support',
  '.zip',    // confusable with .zip file extension
  '.mov',    // confusable with .mov video file extension
  '.qpon', '.locker',
  // legacy entries retained from original list
  '.website', '.space', '.fun', '.monster',
  '.cam', '.beauty', '.hair', '.quest',
  '.cyou', '.autos', '.boats', '.homes', '.motorcycles', '.yachts',
]);

/** Combined flat set for fast O(1) membership tests */
const SUSPICIOUS_TLDS = new Set([
  ...SUSPICIOUS_TLDS_TIER1,
  ...SUSPICIOUS_TLDS_TIER2,
  ...SUSPICIOUS_TLDS_TIER3,
  ...SUSPICIOUS_TLDS_TIER4,
]);

/** Returns the tier number (1–4) for a TLD, or null if not suspicious. */
function getTldTier(tld: string): 1 | 2 | 3 | 4 | null {
  const t = tld.toLowerCase();
  if (SUSPICIOUS_TLDS_TIER1.has(t)) return 1;
  if (SUSPICIOUS_TLDS_TIER2.has(t)) return 2;
  if (SUSPICIOUS_TLDS_TIER3.has(t)) return 3;
  if (SUSPICIOUS_TLDS_TIER4.has(t)) return 4;
  return null;
}

/** Maps tier to a confidence value for the generated signal. */
const TLD_TIER_CONFIDENCE: Record<number, number> = {
  1: 0.85,
  2: 0.70,
  3: 0.55,
  4: 0.40,
};

// ---------------------------------------------------------------------------
// Known legitimate brand domains for impersonation detection
// Brand market-share source: Check Point Brand Phishing Report Q4 2025
// Microsoft 22%, Google 13%, Amazon 9%, Apple 8%, Facebook 3%,
// PayPal 2%, Adobe 2%, Booking 2%, DHL 1%, LinkedIn 1%
// ---------------------------------------------------------------------------
const BRAND_DOMAINS: Record<string, string[]> = {
  // ── Tier A: Most-impersonated (Check Point Q4 2025 top 10) ──────────────
  microsoft: [
    'microsoft.com', 'live.com', 'outlook.com', 'office.com',
    'office365.com', 'onedrive.com', 'sharepoint.com', 'teams.microsoft.com',
    'microsoftonline.com', 'windows.com', 'xbox.com', 'azure.com',
  ],
  google: [
    'google.com', 'gmail.com', 'accounts.google.com', 'drive.google.com',
    'youtube.com', 'googlemail.com', 'workspace.google.com',
  ],
  amazon: [
    'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.ca',
    'amazon.co.jp', 'amazon.com.au', 'aws.amazon.com', 'prime.amazon.com',
    'amazonprime.com',
  ],
  apple: [
    'apple.com', 'icloud.com', 'itunes.com', 'appleid.apple.com',
    'support.apple.com',
  ],
  facebook: ['facebook.com', 'fb.com', 'meta.com', 'messenger.com'],
  paypal: ['paypal.com', 'paypal.me'],
  adobe: ['adobe.com', 'adobeacrobat.com', 'creativecloud.com'],
  booking: ['booking.com'],
  dhl: ['dhl.com', 'dhl.de', 'dhl.co.uk'],
  linkedin: ['linkedin.com', 'lnkd.in'],

  // ── Tier B: Frequently impersonated ─────────────────────────────────────
  instagram: ['instagram.com'],
  whatsapp: ['whatsapp.com', 'wa.me'],
  netflix: ['netflix.com'],
  spotify: ['spotify.com'],
  dropbox: ['dropbox.com'],
  docusign: ['docusign.com', 'docusign.net'],

  // ── Financial institutions ───────────────────────────────────────────────
  chase: ['chase.com', 'jpmorgan.com'],
  wellsfargo: ['wellsfargo.com'],
  bankofamerica: ['bankofamerica.com', 'bofa.com', 'ml.com'],
  citibank: ['citibank.com', 'citi.com'],
  hsbc: ['hsbc.com', 'hsbc.co.uk'],

  // ── Crypto exchanges (high fraud velocity) ──────────────────────────────
  coinbase: ['coinbase.com', 'coinbase.pro'],
  binance: ['binance.com', 'binance.us'],
  metamask: ['metamask.io'],

  // ── Shipping / Government ────────────────────────────────────────────────
  usps: ['usps.com'],
  fedex: ['fedex.com'],
  ups: ['ups.com'],
  irs: ['irs.gov'],
  ssa: ['ssa.gov'],

  // ── Retail ──────────────────────────────────────────────────────────────
  costco: ['costco.com'],
  walmart: ['walmart.com'],
};

// ---------------------------------------------------------------------------
// Homoglyph mapping (characters that look like Latin letters)
// Extended with confirmed real-world attack data (Unicode Confusables 15.1)
// ---------------------------------------------------------------------------
const HOMOGLYPH_MAP: Record<string, string> = {
  // ── Cyrillic → Latin (confirmed attack vectors) ─────────────────────────
  // Core substitutions used in IDN homograph attacks
  '\u0430': 'a',  // Cyrillic Small Letter A  (U+0430) → a
  '\u0441': 'c',  // Cyrillic Small Letter Es (U+0441) → c
  '\u0435': 'e',  // Cyrillic Small Letter Ie (U+0435) → e
  '\u043E': 'o',  // Cyrillic Small Letter O  (U+043E) → o
  '\u0440': 'p',  // Cyrillic Small Letter Er (U+0440) → p
  '\u0445': 'x',  // Cyrillic Small Letter Ha (U+0445) → x
  '\u0443': 'y',  // Cyrillic Small Letter U  (U+0443) → y
  '\u0455': 's',  // Cyrillic Small Letter Dze (U+0455) → s
  '\u0456': 'i',  // Cyrillic Small Letter Byelorussian-Ukrainian I (U+0456) → i
  '\u0458': 'j',  // Cyrillic Small Letter Je (U+0458) → j
  '\u04BB': 'h',  // Cyrillic Small Letter Shha (U+04BB) → h
  '\u0501': 'd', '\u051B': 'q', '\u051D': 'w',
  '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041A': 'K', '\u041C': 'M',
  '\u041D': 'H', '\u041E': 'O', '\u0420': 'P', '\u0421': 'C', '\u0422': 'T',
  '\u0425': 'X', '\u0433': 'r', '\u043D': 'h', '\u0442': 't',
  '\u0457': 'i', '\u0491': 'r',
  // ── Greek → Latin ────────────────────────────────────────────────────────
  '\u03BF': 'o',  // Greek Small Letter Omicron (U+03BF) → o
  '\u03BD': 'v',  // Greek Small Letter Nu      (U+03BD) → v
  '\u03C1': 'p',  // Greek Small Letter Rho     (U+03C1) → p
  '\u03B1': 'a', '\u03B5': 'e', '\u03B9': 'i',
  '\u03C5': 'u', '\u03BA': 'k', '\u03C9': 'w', '\u03C4': 't',
  '\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0396': 'Z', '\u0397': 'H',
  '\u0399': 'I', '\u039A': 'K', '\u039C': 'M', '\u039D': 'N', '\u039F': 'O',
  '\u03A1': 'P', '\u03A4': 'T', '\u03A7': 'X', '\u03A5': 'Y',
  // Latin extended / IPA
  '\u0261': 'g', '\u026A': 'i', '\u0131': 'i',
  '\u01C0': 'l', '\u0142': 'l', '\u0127': 'h', '\u0111': 'd',
  '\u0180': 'b', '\u0188': 'c', '\u0199': 'k', '\u019A': 'l',
  '\u01A5': 'p', '\u0253': 'b', '\u0256': 'd', '\u0260': 'g',
  '\u026B': 'l', '\u0271': 'm', '\u0272': 'n', '\u027D': 'r',
  // Fullwidth Latin
  '\uFF41': 'a', '\uFF42': 'b', '\uFF43': 'c', '\uFF44': 'd', '\uFF45': 'e',
  '\uFF46': 'f', '\uFF47': 'g', '\uFF48': 'h', '\uFF49': 'i', '\uFF4A': 'j',
  '\uFF4B': 'k', '\uFF4C': 'l', '\uFF4D': 'm', '\uFF4E': 'n', '\uFF4F': 'o',
  '\uFF50': 'p', '\uFF51': 'q', '\uFF52': 'r', '\uFF53': 's', '\uFF54': 't',
  '\uFF55': 'u', '\uFF56': 'v', '\uFF57': 'w', '\uFF58': 'x', '\uFF59': 'y', '\uFF5A': 'z',
  // Accented Latin
  '\u00E0': 'a', '\u00E1': 'a', '\u00E2': 'a', '\u00E3': 'a', '\u00E4': 'a', '\u00E5': 'a',
  '\u00E8': 'e', '\u00E9': 'e', '\u00EA': 'e', '\u00EB': 'e',
  '\u00EC': 'i', '\u00ED': 'i', '\u00EE': 'i', '\u00EF': 'i',
  '\u00F2': 'o', '\u00F3': 'o', '\u00F4': 'o', '\u00F5': 'o', '\u00F6': 'o', '\u00F8': 'o',
  '\u00F9': 'u', '\u00FA': 'u', '\u00FB': 'u', '\u00FC': 'u',
  '\u00FD': 'y', '\u00FF': 'y', '\u00F1': 'n', '\u00E7': 'c', '\u00DF': 'ss',
  '\u0101': 'a', '\u0113': 'e', '\u012B': 'i', '\u014D': 'o', '\u016B': 'u',
  // ── Number/symbol substitutions used in leet-speak domain spoofing ───────
  // These are ASCII characters deliberately substituted for look-alikes:
  // l (lowercase L) → 1 (one), O (uppercase O) → 0 (zero),
  // I (uppercase i) → l (lowercase L), a → @, e → 3, s → $, b → 6, g → 9
  // NOTE: these are tracked as string patterns, not Unicode code points.
  // The regex-based check below handles them at the string level.

  // ── Mathematical / special ───────────────────────────────────────────────
  '\u2070': '0', '\u00B9': '1', '\u00B2': '2', '\u00B3': '3',
  '\u2074': '4', '\u2075': '5', '\u2076': '6', '\u2077': '7', '\u2078': '8', '\u2079': '9',
  '\u2010': '-', '\u2011': '-', '\u2012': '-', '\u2013': '-', '\u2014': '-',
  '\u2024': '.', '\u2025': '..', '\u2026': '...',
};

/**
 * ASCII leet-speak substitutions used in domain spoofing.
 * Key = leet character, Value = canonical Latin character it replaces.
 * Examples: "rn" visually reads as "m" (rnicrosoft), "1" replaces "l" (paypa1),
 * capital "I" replaces lowercase "l" (paypaI).
 */
const LEET_SUBSTITUTION_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  { pattern: /rn(?=[a-z])/i,           description: 'rn→m digraph (e.g. "rnicrosoft")' },
  { pattern: /vv(?=[a-z])/i,           description: 'vv→w digraph' },
  { pattern: /[0O](?=[a-zA-Z])/,       description: '0→O substitution in domain' },
  { pattern: /[1lI](?=[a-zA-Z]{2})/,   description: '1/I→l substitution (e.g. "paypaI", "paypa1")' },
  { pattern: /[3@](?=[a-zA-Z])/,       description: '3→e or @→a substitution' },
  { pattern: /\$(?=[a-zA-Z])/,         description: '$→s substitution' },
];

/**
 * Known real-world homograph attack brand targets.
 * Detects specific visually-identical spoofs that have appeared in the wild.
 */
const KNOWN_HOMOGRAPH_ATTACKS: Array<{ spoof: RegExp; brand: string }> = [
  { spoof: /rnicrosoft/i,    brand: 'microsoft' },  // rn=m
  { spoof: /micros0ft/i,     brand: 'microsoft' },  // 0=o
  { spoof: /paypa[lI1]/i,    brand: 'paypal' },      // I or 1 = l
  { spoof: /g[o0]{2}gle/i,   brand: 'google' },      // 0=o
  { spoof: /amaz[o0]n/i,     brand: 'amazon' },      // 0=o
  { spoof: /app1e/i,         brand: 'apple' },       // 1=l
  { spoof: /netf1ix/i,       brand: 'netflix' },     // 1=l
  { spoof: /faceb[o0]{2}k/i, brand: 'facebook' },   // 0=o
];

// ---------------------------------------------------------------------------
// Suspicious registrars frequently used for malicious domains
// ---------------------------------------------------------------------------
const SUSPICIOUS_REGISTRARS = new Set([
  'namecheap', 'namesilo', 'dynadot', 'porkbun', 'nicenic',
  'alibaba', 'west263', 'webnic', 'regtons', 'r01',
]);

// ---------------------------------------------------------------------------
// Urgency / threat / financial language patterns
// ---------------------------------------------------------------------------
// Source: FTC Consumer Sentinel scam complaint data + Anti-Phishing Working Group (APWG) 2024
const URGENCY_PATTERNS: Array<{ pattern: RegExp; label: string; weight: number }> = [
  { pattern: /\b(act now|immediate(ly)?|urgent(ly)?|right away|asap|don'?t delay)\b/i, label: 'urgency_time_pressure', weight: 0.7 },
  { pattern: /\b(expires?\s+(today|soon|in\s+\d+\s+(hours?|minutes?|days?)))\b/i, label: 'urgency_expiration', weight: 0.75 },
  { pattern: /\b(last chance|final (notice|warning|attempt)|only\s+\d+\s+(left|remaining))\b/i, label: 'urgency_scarcity', weight: 0.8 },
  { pattern: /\b(account\s+(will be|has been)\s+(suspend|clos|lock|deactivat|terminat))/i, label: 'urgency_threat_account', weight: 0.85 },
  { pattern: /\b(legal action|law enforcement|arrest warrant|police|fbi)\b/i, label: 'urgency_legal_threat', weight: 0.9 },
  { pattern: /\b(within\s+(24|48|72)\s*hours?|today only|limited time)\b/i, label: 'urgency_deadline', weight: 0.7 },
  { pattern: /\b(respond immediately|call (us\s+)?immediately|contact us (urgently|immediately))\b/i, label: 'urgency_response_demand', weight: 0.75 },
  { pattern: /\b(time\s+(is\s+)?running\s+out|clock\s+is\s+ticking|every\s+minute\s+counts)\b/i, label: 'urgency_countdown', weight: 0.75 },
  { pattern: /\b(before\s+it'?s?\s+too\s+late|while\s+you\s+still\s+can|now\s+or\s+never)\b/i, label: 'urgency_finality', weight: 0.8 },
  { pattern: /\b(failure\s+to\s+(respond|act|comply|verify)|if\s+(no|not)\s+(action|response))\b/i, label: 'urgency_consequence', weight: 0.85 },
  { pattern: /\b(this\s+(offer|deal|opportunity)\s+(expires?|ends?|won'?t\s+last))\b/i, label: 'urgency_offer_expiry', weight: 0.7 },
  { pattern: /\b(do\s+(this|it)\s+(right\s+)?now|take\s+action\s+(now|today|immediately))\b/i, label: 'urgency_action_now', weight: 0.7 },
  { pattern: /\b(only\s+\d+\s+(hours?|minutes?|days?)\s+(left|remaining|to\s+(act|respond|claim)))\b/i, label: 'urgency_countdown_specific', weight: 0.8 },
  { pattern: /\b(your\s+account\s+(is\s+)?at\s+risk|security\s+(breach|alert|warning))\b/i, label: 'urgency_security_risk', weight: 0.8 },
  // ── Real FTC-documented urgency phrases ────────────────────────────────
  { pattern: /\bimmediate\s+action\s+required\b/i, label: 'urgency_ftc_immediate_action', weight: 0.85 },
  { pattern: /\bexpires\s+today\b/i, label: 'urgency_ftc_expires_today', weight: 0.8 },
  { pattern: /\bfinal\s+warning\b/i, label: 'urgency_ftc_final_warning', weight: 0.85 },
  { pattern: /\btime[- ]sensitive\b/i, label: 'urgency_ftc_time_sensitive', weight: 0.75 },
  { pattern: /\b(deadline\s+approaching|hours?\s+remaining)\b/i, label: 'urgency_ftc_deadline', weight: 0.75 },
  { pattern: /\byour\s+account\s+will\s+be\s+(suspended|locked)\b/i, label: 'urgency_ftc_account_suspension', weight: 0.9 },
];

const FINANCIAL_PATTERNS: Array<{ pattern: RegExp; label: string; weight: number }> = [
  { pattern: /\b(wire transfer|western union|moneygram|zelle|cashapp|venmo)\b/i, label: 'finance_wire_transfer', weight: 0.8 },
  { pattern: /\b(gift\s*cards?|itunes?\s*cards?|google\s*play\s*cards?|steam\s*cards?)\b/i, label: 'finance_gift_card', weight: 0.9 },
  { pattern: /\b(bitcoin|btc|ethereum|eth|crypto\s*(currency|wallet)|usdt|tether)\b/i, label: 'finance_crypto', weight: 0.7 },
  { pattern: /\b(bank\s*account|routing\s*number|account\s*number|sort\s*code|iban)\b/i, label: 'finance_bank_details', weight: 0.8 },
  { pattern: /\b(ssn|social\s*security\s*(number)?|tax\s*id|ein)\b/i, label: 'finance_ssn', weight: 0.9 },
  { pattern: /\b(credit\s*card|debit\s*card|card\s*number|cvv|expir(y|ation)\s*date)\b/i, label: 'finance_card', weight: 0.85 },
  { pattern: /\b(processing\s*fee|advance\s*fee|upfront\s*(payment|fee)|handling\s*(charge|fee))\b/i, label: 'finance_advance_fee', weight: 0.85 },
  { pattern: /\b(guaranteed\s*(return|profit|income)|risk[- ]free|no[- ]risk)\b/i, label: 'finance_guaranteed_returns', weight: 0.9 },
  { pattern: /\$\s*[\d,]+[,.]?\d*\s*(million|thousand|usd)?/i, label: 'finance_large_amount', weight: 0.5 },
  { pattern: /\b(inheritance|beneficiary|next[- ]of[- ]kin|unclaimed\s*funds?)\b/i, label: 'finance_inheritance', weight: 0.85 },
  { pattern: /\b(money\s*order|cashier'?s?\s*check|certified\s*check)\b/i, label: 'finance_money_order', weight: 0.7 },
  { pattern: /\b(prepaid\s*(card|debit)|reload\s*(pack|card)|green\s*dot)\b/i, label: 'finance_prepaid', weight: 0.85 },
  { pattern: /\b(seed\s*phrase|private\s*key|wallet\s*recovery|connect\s*wallet)\b/i, label: 'finance_crypto_keys', weight: 0.9 },
  { pattern: /\b(swift\s*code|bic|intermediary\s*bank|correspondent\s*bank)\b/i, label: 'finance_intl_transfer', weight: 0.7 },
  { pattern: /\b(tax\s*(refund|return|rebate)|stimulus\s*(check|payment))\b/i, label: 'finance_tax_refund', weight: 0.75 },
  { pattern: /\b(pay\s*(us|me|them)\s*(back|now|today|immediately))\b/i, label: 'finance_pay_demand', weight: 0.75 },
  { pattern: /\b(monthly\s*(fee|charge|subscription)|recurring\s*(charge|payment|billing))\b/i, label: 'finance_subscription', weight: 0.5 },
  { pattern: /\b(clearance\s*fee|release\s*fee|customs?\s*(fee|duty|charge)|delivery\s*fee)\b/i, label: 'finance_hidden_fees', weight: 0.8 },
  { pattern: /\b(100%\s*money\s*back|full\s*refund\s*guarantee|satisfaction\s*guaranteed)\b/i, label: 'finance_false_guarantee', weight: 0.6 },
  { pattern: /\b(passive\s*income|financial\s*freedom|be\s*your\s*own\s*boss|quit\s*your\s*job)\b/i, label: 'finance_income_promise', weight: 0.75 },
];

const IMPERSONATION_PATTERNS: Array<{ pattern: RegExp; label: string; weight: number }> = [
  { pattern: /\b(dear\s*(valued\s*)?(customer|user|member|account\s*holder|client))\b/i, label: 'impersonation_generic_greeting', weight: 0.6 },
  // Brand mentions — expanded with Check Point Q4 2025 top-impersonated brands
  // Microsoft (22%), Google (13%), Amazon (9%), Apple (8%), Facebook (3%),
  // PayPal (2%), Adobe (2%), Booking (2%), DHL (1%), LinkedIn (1%)
  { pattern: /\b(paypal|amazon|apple|google|microsoft|netflix|facebook|instagram|office\s*365|outlook|onedrive|sharepoint|teams|gmail|google\s*drive|youtube|aws|amazon\s*prime|icloud|itunes|meta|whatsapp|adobe|acrobat|booking\.?com|fedex|ups|usps|spotify|dropbox|docusign|coinbase|binance|metamask|linkedin|dhl)\b/i, label: 'impersonation_brand_mention', weight: 0.3 },
  { pattern: /\b(verify\s*(your\s*)?(identity|account|information|details))\b/i, label: 'impersonation_verify_demand', weight: 0.75 },
  { pattern: /\b(unusual\s*(activity|login|sign[- ]in|transaction)|suspicious\s*(activity|login))\b/i, label: 'impersonation_unusual_activity', weight: 0.8 },
  { pattern: /\b(confirm\s*(your\s*)?(identity|payment|details)|update\s*(your\s*)?(billing|payment|account)\s*(info|information|details))\b/i, label: 'impersonation_confirm_demand', weight: 0.75 },
  { pattern: /\b(security\s*(team|department|center|alert)|fraud\s*(department|team|prevention))\b/i, label: 'impersonation_security_team', weight: 0.65 },
  { pattern: /\b(official\s*(notice|communication|letter)|this is (a |an )?(official|automated)\s*(message|notice|email))\b/i, label: 'impersonation_official_claim', weight: 0.7 },
  { pattern: /\b(account\s*(recovery|restoration|reactivation)\s*(team|department|center))\b/i, label: 'impersonation_recovery_team', weight: 0.7 },
  { pattern: /\b(we('ve|\s+have)\s+(noticed|detected|identified|found)\s+(a\s+)?(suspicious|unusual|unauthorized))\b/i, label: 'impersonation_detection_claim', weight: 0.75 },
  { pattern: /\b(your\s+(account|profile|identity)\s+(has\s+been\s+)?(flagged|marked|reported))\b/i, label: 'impersonation_flagged_account', weight: 0.8 },
  { pattern: /\b(for\s+(your|account)\s+(security|protection|safety))\b/i, label: 'impersonation_safety_framing', weight: 0.6 },
  { pattern: /\b(our\s+(system|records?|database)\s+(shows?|indicates?|detected))\b/i, label: 'impersonation_system_claim', weight: 0.65 },
  { pattern: /\b(re-?verify|re-?confirm|re-?validate|re-?authenticate)\b/i, label: 'impersonation_reverify', weight: 0.7 },
  { pattern: /\b(authorized\s+representative|certified\s+agent|official\s+agent)\b/i, label: 'impersonation_agent_claim', weight: 0.7 },
];

const TOO_GOOD_PATTERNS: Array<{ pattern: RegExp; label: string; weight: number }> = [
  { pattern: /\b(you('ve| have)\s*(been\s*)?selected|congratulations|you('re| are)\s*(a\s*)?winner)\b/i, label: 'tgtbt_winner', weight: 0.85 },
  { pattern: /\b(free\s*(gift|money|iphone|macbook|samsung|prize)|claim\s*(your\s*)?(prize|reward|gift))\b/i, label: 'tgtbt_free_prize', weight: 0.9 },
  { pattern: /\b(lottery|sweepstakes|jackpot|grand\s*prize)\b/i, label: 'tgtbt_lottery', weight: 0.85 },
  { pattern: /\b(make\s*\$?\d+[kK]?\s*(per|a|each)\s*(day|week|month|hour))\b/i, label: 'tgtbt_income_promise', weight: 0.9 },
  { pattern: /\b(double\s*your\s*(money|investment|bitcoin)|1000%\s*return|10x\s*(your|return))\b/i, label: 'tgtbt_multiplier', weight: 0.95 },
  { pattern: /\b(work\s*from\s*home.{0,30}(earn|make|income))/i, label: 'tgtbt_wfh_income', weight: 0.65 },
  { pattern: /\b(secret\s*(method|system|formula|trick)|they\s*don'?t\s*want\s*you\s*to\s*know)\b/i, label: 'tgtbt_secret', weight: 0.8 },
  { pattern: /\b(earn\s*(up\s*to\s*)?\$[\d,.]+\s*(daily|weekly|monthly|per\s*(day|week|month)))\b/i, label: 'tgtbt_earnings_claim', weight: 0.85 },
  { pattern: /\b(no\s*(experience|skills?|degree|investment)\s*(needed|required|necessary))\b/i, label: 'tgtbt_no_requirements', weight: 0.7 },
  { pattern: /\b(limited\s*(spots?|positions?|openings?)\s*(available|remaining|left))\b/i, label: 'tgtbt_limited_spots', weight: 0.7 },
  { pattern: /\b(life[- ]changing\s*(opportunity|income|offer)|change\s*your\s*life)\b/i, label: 'tgtbt_life_changing', weight: 0.75 },
  { pattern: /\b(exclusive\s*(access|invitation|offer|deal|membership))\b/i, label: 'tgtbt_exclusive', weight: 0.65 },
  { pattern: /\b(approved\s*for\s*\$[\d,.]+|pre[- ]?approved\s*(loan|credit|mortgage))\b/i, label: 'tgtbt_pre_approved', weight: 0.8 },
  { pattern: /\b(zero\s*(down|cost|fee|investment)|completely\s*free|totally\s*free)\b/i, label: 'tgtbt_zero_cost', weight: 0.7 },
];

const THREAT_PATTERNS: Array<{ pattern: RegExp; label: string; weight: number }> = [
  { pattern: /\b(your\s*(account|computer|device)\s*(has been|is)\s*(hack|compromise|infect))/i, label: 'threat_compromised', weight: 0.85 },
  { pattern: /\b(virus|malware|trojan|ransomware)\s*(detect|found|infect)/i, label: 'threat_malware', weight: 0.8 },
  { pattern: /\b(we\s*(have|got)\s*(your\s*)?(photos?|videos?|data|files?|browsing\s*history))\b/i, label: 'threat_extortion', weight: 0.9 },
  { pattern: /\b(send\s*(to\s*)?all\s*(your\s*)?(contacts?|friends?|family))\b/i, label: 'threat_exposure', weight: 0.85 },
  { pattern: /\b(recorded\s*(you|your\s*(screen|webcam|camera)))\b/i, label: 'threat_recording', weight: 0.9 },
  { pattern: /\b(owe\s*(the\s*)?(irs|government|taxes?)|tax\s*(debt|lien|levy))\b/i, label: 'threat_tax', weight: 0.8 },
  { pattern: /\b(warrant\s*(for\s*your\s*arrest|issued)|facing\s*(charges|prosecution|arrest))\b/i, label: 'threat_arrest', weight: 0.9 },
  { pattern: /\b(your\s*(personal|private)\s*(data|information|details)\s*(has\s*been|will\s*be)\s*(leak|expos|releas|publish|sold))/i, label: 'threat_data_leak', weight: 0.9 },
  { pattern: /\b(we\s*will\s*(report|notify)\s*(the\s*)?(authorities|police|fbi|irs))\b/i, label: 'threat_report_authorities', weight: 0.8 },
  { pattern: /\b(your\s*(credit\s*score|rating)\s*(will|may)\s*(be\s+)?(damaged|affected|ruined))\b/i, label: 'threat_credit_score', weight: 0.75 },
  { pattern: /\b(blacklist|block\s*list|banned?\s*(from|permanently))\b/i, label: 'threat_blacklist', weight: 0.7 },
  { pattern: /\b(collections?\s*(agency|department)|sent?\s*to\s*collections?|debt\s*collector)\b/i, label: 'threat_collections', weight: 0.75 },
  { pattern: /\b(permanent(ly)?\s*(delete|remove|suspend|ban|lock))\b/i, label: 'threat_permanent_action', weight: 0.8 },
  { pattern: /\b(identity\s*(theft|stolen|compromised)|someone\s*(is\s+)?using\s+your\s+identity)\b/i, label: 'threat_identity_theft', weight: 0.85 },
  // ── Real FTC-documented fear phrases ────────────────────────────────────
  { pattern: /\bunauthorized\s+access\s+detected\b/i, label: 'fear_unauthorized_access', weight: 0.85 },
  { pattern: /\bsuspicious\s+activity\s+(detected|found|on\s+your\s+account)\b/i, label: 'fear_suspicious_activity', weight: 0.8 },
  { pattern: /\bsecurity\s+breach\b/i, label: 'fear_security_breach', weight: 0.8 },
  { pattern: /\b(your\s+(account\s+has\s+been\s+)?compromised)\b/i, label: 'fear_compromised', weight: 0.85 },
  { pattern: /\b(you('ve|\s+have)\s+been\s+hacked)\b/i, label: 'fear_hacked', weight: 0.9 },
  { pattern: /\bvirus\s+detected\b/i, label: 'fear_virus_detected', weight: 0.8 },
  { pattern: /\bmalware\s+(found|detected)\b/i, label: 'fear_malware_found', weight: 0.8 },
  { pattern: /\baccount\s+terminated\b/i, label: 'fear_account_terminated', weight: 0.85 },
  { pattern: /\bpermanently\s+banned\b/i, label: 'fear_permanently_banned', weight: 0.8 },
  { pattern: /\bdata\s+loss\b/i, label: 'fear_data_loss', weight: 0.65 },
  { pattern: /\b(payment\s+declined|overdue\s+balance)\b/i, label: 'fear_payment_issue', weight: 0.7 },
];

// ---------------------------------------------------------------------------
// Payment method patterns — scam-associated payment instructions
// Gift cards and wire transfers are the #1 and #2 scam payment methods (FTC 2024)
// ---------------------------------------------------------------------------
const PAYMENT_METHOD_PATTERNS: Array<{ pattern: RegExp; label: string; weight: number }> = [
  // Gift card scams — top-reported payment method in FTC fraud reports
  { pattern: /\b(gift\s*card)\b/i, label: 'payment_gift_card_generic', weight: 0.85 },
  { pattern: /\b(google\s*play\s*(card|gift\s*card))\b/i, label: 'payment_google_play_card', weight: 0.92 },
  { pattern: /\b(apple\s*(gift\s*card|itunes?\s*card))\b/i, label: 'payment_apple_gift_card', weight: 0.92 },
  { pattern: /\b(amazon\s*(gift\s*card|e-?gift))\b/i, label: 'payment_amazon_gift_card', weight: 0.9 },
  { pattern: /\b(steam\s*(gift\s*card|wallet\s*code))\b/i, label: 'payment_steam_gift_card', weight: 0.88 },

  // Wire / money transfer
  { pattern: /\b(wire\s*transfer|telegraphic\s*transfer|swift\s*transfer)\b/i, label: 'payment_wire_transfer', weight: 0.8 },
  { pattern: /\b(western\s*union)\b/i, label: 'payment_western_union', weight: 0.85 },
  { pattern: /\b(moneygram)\b/i, label: 'payment_moneygram', weight: 0.85 },

  // P2P apps — increasingly used in scams (FTC 2024: Zelle #3)
  { pattern: /\b(zelle)\b/i, label: 'payment_zelle', weight: 0.75 },
  { pattern: /\b(cash\s*app|cashapp)\b/i, label: 'payment_cashapp', weight: 0.75 },
  { pattern: /\b(venmo)\b/i, label: 'payment_venmo', weight: 0.65 },

  // Crypto payments in non-crypto contexts
  { pattern: /\b(cryptocurrency|crypto\s*wallet|send\s*(bitcoin|btc|ethereum|eth|usdt))\b/i, label: 'payment_crypto_demand', weight: 0.85 },
  { pattern: /\b(bitcoin\s*(payment|address|wallet))\b/i, label: 'payment_bitcoin', weight: 0.8 },
  { pattern: /\bsend\s+payment\s+to\b/i, label: 'payment_send_instruction', weight: 0.75 },

  // Prepaid / reloadable cards
  { pattern: /\b(prepaid\s*(card|debit|visa|mastercard))\b/i, label: 'payment_prepaid_card', weight: 0.82 },
  { pattern: /\b(reload\s*(pack|card)|green\s*dot|vanilla\s*(gift|visa|prepaid))\b/i, label: 'payment_prepaid_reload', weight: 0.85 },
];

// ---------------------------------------------------------------------------
// Shannon entropy calculator
// ---------------------------------------------------------------------------
function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq: Record<string, number> = {};
  for (const ch of str) {
    freq[ch] = (freq[ch] || 0) + 1;
  }
  const len = str.length;
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return entropy;
}

// ---------------------------------------------------------------------------
// Detect homoglyphs in a string
// ---------------------------------------------------------------------------
function containsHomoglyphs(str: string): boolean {
  for (const ch of str) {
    if (HOMOGLYPH_MAP[ch]) return true;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Detect brand impersonation in hostname
// ---------------------------------------------------------------------------
function detectBrandImpersonation(hostname: string): { brand: string; legitimate: boolean } | null {
  const lowerHost = hostname.toLowerCase();
  for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
    if (lowerHost.includes(brand)) {
      const isLegit = domains.some(d => lowerHost === d || lowerHost.endsWith('.' + d));
      return { brand, legitimate: isLegit };
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// extractUrlSignals
// ---------------------------------------------------------------------------
export function extractUrlSignals(url: string): Signal[] {
  const signals: Signal[] = [];

  let parsed: URL;
  try {
    parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
  } catch {
    signals.push({
      type: SignalType.URL,
      value: url,
      confidence: 0.9,
      rawData: { error: 'invalid_url' },
      label: 'Malformed or invalid URL',
      cost: 0,
    });
    return signals;
  }

  const hostname = parsed.hostname;
  const parts = hostname.split('.');
  const tld = '.' + parts[parts.length - 1];
  const subdomains = parts.slice(0, -2);

  // --- URL analysis object ---
  const analysis: UrlAnalysis = {
    protocol: parsed.protocol,
    hostname,
    path: parsed.pathname,
    query: parsed.search,
    tld,
    subdomains,
    hasIpAddress: /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || /\[.*\]/.test(hostname),
    entropy: shannonEntropy(hostname),
    length: url.length,
    hasEncodedChars: /%[0-9a-fA-F]{2}/.test(url),
    isShortener: URL_SHORTENERS.has(hostname.toLowerCase()),
    hasSuspiciousTld: SUSPICIOUS_TLDS.has(tld.toLowerCase()),
    hasHomoglyphs: containsHomoglyphs(hostname),
    excessiveSubdomains: subdomains.length >= 3,
  };

  // 1) IP address in URL
  if (analysis.hasIpAddress) {
    signals.push({
      type: SignalType.URL,
      value: hostname,
      confidence: 0.85,
      rawData: { check: 'ip_in_url', analysis },
      label: 'URL uses raw IP address instead of domain name',
      cost: 0,
    });
  }

  // 2) Suspicious TLD — tiered confidence based on real malicious-domain rates
  if (analysis.hasSuspiciousTld) {
    const tier = getTldTier(tld);
    const tldConfidence = tier ? TLD_TIER_CONFIDENCE[tier] : 0.6;
    const tierLabel = tier ? ` (Tier ${tier})` : '';
    signals.push({
      type: SignalType.URL,
      value: tld,
      confidence: tldConfidence,
      rawData: { check: 'suspicious_tld', tier, analysis },
      label: `Suspicious TLD${tierLabel}: ${tld}`,
      cost: 0,
    });
  }

  // 3) URL shortener — tiered confidence based on real abuse rates
  if (analysis.isShortener) {
    const abuseTier = getShortenerAbuseTier(hostname.toLowerCase());
    const shortenerConfidence = abuseTier === 'high' ? 0.85 : abuseTier === 'medium' ? 0.65 : 0.45;
    const shortenerLabel = abuseTier === 'high'
      ? `High-abuse URL shortener (${hostname}) — documented malware delivery`
      : abuseTier === 'medium'
        ? `Medium-abuse URL shortener (${hostname})`
        : `URL shortener detected: ${hostname}`;
    signals.push({
      type: SignalType.URL,
      value: hostname,
      confidence: shortenerConfidence,
      rawData: { check: 'url_shortener', abuseTier, analysis },
      label: shortenerLabel,
      cost: 0,
    });
  }

  // 4) Excessive subdomains
  if (analysis.excessiveSubdomains) {
    signals.push({
      type: SignalType.URL,
      value: hostname,
      confidence: 0.7,
      rawData: { check: 'excessive_subdomains', count: subdomains.length, analysis },
      label: `Excessive subdomains (${subdomains.length}): ${hostname}`,
      cost: 0,
    });
  }

  // 5) Homoglyphs
  if (analysis.hasHomoglyphs) {
    signals.push({
      type: SignalType.URL,
      value: hostname,
      confidence: 0.9,
      rawData: { check: 'homoglyphs', analysis },
      label: 'Hostname contains homoglyph characters (lookalike letters)',
      cost: 0,
    });
  }

  // 6) High entropy hostname (randomized domain)
  if (analysis.entropy > 3.8 && hostname.length > 12) {
    signals.push({
      type: SignalType.URL,
      value: hostname,
      confidence: 0.65,
      rawData: { check: 'high_entropy', entropy: analysis.entropy, analysis },
      label: `High-entropy hostname (${analysis.entropy.toFixed(2)} bits) suggests randomized domain`,
      cost: 0,
    });
  }

  // 7) Encoded characters in URL
  if (analysis.hasEncodedChars) {
    const encodedCount = (url.match(/%[0-9a-fA-F]{2}/g) || []).length;
    if (encodedCount > 3) {
      signals.push({
        type: SignalType.URL,
        value: url,
        confidence: 0.6,
        rawData: { check: 'encoded_chars', count: encodedCount, analysis },
        label: `Excessive URL-encoded characters (${encodedCount})`,
        cost: 0,
      });
    }
  }

  // 8) Very long URL
  if (analysis.length > 200) {
    signals.push({
      type: SignalType.URL,
      value: `length: ${analysis.length}`,
      confidence: 0.5,
      rawData: { check: 'long_url', length: analysis.length, analysis },
      label: `Unusually long URL (${analysis.length} characters)`,
      cost: 0,
    });
  }

  // 9) HTTP (no TLS)
  if (parsed.protocol === 'http:') {
    signals.push({
      type: SignalType.URL,
      value: parsed.protocol,
      confidence: 0.55,
      rawData: { check: 'no_tls', analysis },
      label: 'URL uses HTTP without encryption',
      cost: 0,
    });
  }

  // 10) Brand impersonation
  const brandCheck = detectBrandImpersonation(hostname);
  if (brandCheck && !brandCheck.legitimate) {
    signals.push({
      type: SignalType.URL,
      value: hostname,
      confidence: 0.9,
      rawData: { check: 'brand_impersonation', brand: brandCheck.brand, analysis },
      label: `Possible ${brandCheck.brand} impersonation: ${hostname}`,
      cost: 0,
    });
  }

  // 11a) Suspicious path patterns — credential harvesting & phishing kit paths
  // Includes real phishing kit signatures: /webscr (PayPal), WordPress core paths
  // used by malicious plugins, and generic credential-capture routes
  const suspiciousPathPatterns = /(login|signin|verify|secure|account|update|confirm|billing|password|credential|webscr|wp-content\/.*\.php|wp-includes\/|\.well-known\/|cgi-bin\/|\/tmp\/|login\.php|signin\.html)/i;
  if (suspiciousPathPatterns.test(parsed.pathname)) {
    signals.push({
      type: SignalType.URL,
      value: parsed.pathname,
      confidence: 0.55,
      rawData: { check: 'suspicious_path', analysis },
      label: `Suspicious path keywords in URL: ${parsed.pathname}`,
      cost: 0,
    });
  }

  // 11b) Suspicious query parameters — open-redirect and command-injection indicators
  const suspiciousParamPatterns = /[?&](cmd|action|redirect|return|next|url)=/i;
  if (suspiciousParamPatterns.test(parsed.search)) {
    signals.push({
      type: SignalType.URL,
      value: parsed.search,
      confidence: 0.65,
      rawData: { check: 'suspicious_params', query: parsed.search, analysis },
      label: `Suspicious URL parameter (possible open redirect or command injection): ${parsed.search}`,
      cost: 0,
    });
  }

  // 11c) Known leet-speak / homograph spoofs in hostname
  for (const { spoof, brand } of KNOWN_HOMOGRAPH_ATTACKS) {
    if (spoof.test(hostname)) {
      signals.push({
        type: SignalType.URL,
        value: hostname,
        confidence: 0.95,
        rawData: { check: 'known_homograph_attack', brand, analysis },
        label: `Known homograph spoof of "${brand}" detected in hostname: ${hostname}`,
        cost: 0,
      });
      break;
    }
  }

  // 12) @ symbol in URL (credential-style redirect)
  if (url.includes('@') && !url.startsWith('mailto:')) {
    signals.push({
      type: SignalType.URL,
      value: url,
      confidence: 0.85,
      rawData: { check: 'at_symbol_redirect', analysis },
      label: 'URL contains @ symbol — possible credential-style redirect attack',
      cost: 0,
    });
  }

  // 13) Data URI
  if (url.startsWith('data:')) {
    signals.push({
      type: SignalType.URL,
      value: url.substring(0, 50),
      confidence: 0.8,
      rawData: { check: 'data_uri' },
      label: 'Data URI detected — may contain obfuscated content',
      cost: 0,
    });
  }

  return signals;
}

// ---------------------------------------------------------------------------
// extractTextSignals
// ---------------------------------------------------------------------------
export function extractTextSignals(text: string): Signal[] {
  const signals: Signal[] = [];

  const allPatternGroups = [
    { group: 'urgency', patterns: URGENCY_PATTERNS },
    { group: 'financial', patterns: FINANCIAL_PATTERNS },
    { group: 'impersonation', patterns: IMPERSONATION_PATTERNS },
    { group: 'too_good_to_be_true', patterns: TOO_GOOD_PATTERNS },
    { group: 'threat', patterns: THREAT_PATTERNS },
    { group: 'payment_method', patterns: PAYMENT_METHOD_PATTERNS },
    { group: 'qr_code', patterns: QR_CODE_PATTERNS },
    { group: 'social_media', patterns: SOCIAL_MEDIA_PATTERNS },
  ];

  for (const { group, patterns } of allPatternGroups) {
    for (const { pattern, label, weight } of patterns) {
      const match = text.match(pattern);
      if (match) {
        signals.push({
          type: SignalType.TEXT,
          value: match[0],
          confidence: weight,
          rawData: { group, label, matchIndex: match.index },
          label: `[${group}] ${label}: "${match[0]}"`,
          cost: 1,
        });
      }
    }
  }

  // Check for ALL-CAPS abuse
  const words = text.split(/\s+/).filter(w => w.length > 2);
  const capsWords = words.filter(w => w === w.toUpperCase() && /[A-Z]/.test(w));
  const capsRatio = words.length > 0 ? capsWords.length / words.length : 0;
  if (capsRatio > 0.3 && words.length > 5) {
    signals.push({
      type: SignalType.TEXT,
      value: `${(capsRatio * 100).toFixed(0)}% caps`,
      confidence: 0.5,
      rawData: { check: 'excessive_caps', capsRatio, capsWords: capsWords.length, totalWords: words.length },
      label: `Excessive capitalization (${(capsRatio * 100).toFixed(0)}% of words)`,
      cost: 1,
    });
  }

  // Check for excessive exclamation/question marks
  const exclamationCount = (text.match(/!/g) || []).length;
  const questionCount = (text.match(/\?/g) || []).length;
  if (exclamationCount > 3) {
    signals.push({
      type: SignalType.TEXT,
      value: `${exclamationCount} exclamation marks`,
      confidence: 0.4,
      rawData: { check: 'excessive_punctuation', exclamationCount },
      label: `Excessive exclamation marks (${exclamationCount})`,
      cost: 1,
    });
  }

  // Check for spelling/grammar mistakes common in scams
  const scamMisspellings = /\b(recieve|verifiy|informaton|accout|securty|pasword|updae|suspenion|notifcation|acount|comfirm|immedately)\b/i;
  const misspellingMatch = text.match(scamMisspellings);
  if (misspellingMatch) {
    signals.push({
      type: SignalType.TEXT,
      value: misspellingMatch[0],
      confidence: 0.6,
      rawData: { check: 'scam_misspelling' },
      label: `Common scam misspelling detected: "${misspellingMatch[0]}"`,
      cost: 1,
    });
  }

  // Check for embedded links in text
  const urlInText = text.match(/https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi);
  if (urlInText) {
    for (const foundUrl of urlInText) {
      const urlSignals = extractUrlSignals(foundUrl);
      signals.push(...urlSignals);
    }
  }

  // Phone number analysis
  const phoneSignals = extractPhoneSignals(text);
  signals.push(...phoneSignals);

  // Cryptocurrency wallet detection
  const cryptoSignals = extractCryptoSignals(text);
  signals.push(...cryptoSignals);

  return signals;
}

// ---------------------------------------------------------------------------
// extractEmailSignals
// ---------------------------------------------------------------------------
export function extractEmailSignals(
  headers: Record<string, string>,
  body: string,
): Signal[] {
  const signals: Signal[] = [];

  const from = headers['from'] || headers['From'] || '';
  const replyTo = headers['reply-to'] || headers['Reply-To'] || '';
  const returnPath = headers['return-path'] || headers['Return-Path'] || '';
  const receivedSpf = headers['received-spf'] || headers['Received-SPF'] || '';
  const dkim = headers['dkim-signature'] || headers['DKIM-Signature'] || '';
  const subject = headers['subject'] || headers['Subject'] || '';

  // Extract email addresses
  const emailRegex = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
  const fromEmails = from.match(emailRegex) || [];
  const replyToEmails = replyTo.match(emailRegex) || [];
  const returnPathEmails = returnPath.match(emailRegex) || [];

  // 1) From/Reply-To mismatch
  if (fromEmails.length > 0 && replyToEmails.length > 0) {
    const fromDomain = (fromEmails[0]!.split('@')[1] ?? '').toLowerCase();
    const replyDomain = (replyToEmails[0]!.split('@')[1] ?? '').toLowerCase();
    if (fromDomain && replyDomain && fromDomain !== replyDomain) {
      signals.push({
        type: SignalType.EMAIL,
        value: `From: ${fromDomain}, Reply-To: ${replyDomain}`,
        confidence: 0.8,
        rawData: { check: 'from_reply_mismatch', fromDomain, replyDomain },
        label: `From domain (${fromDomain}) does not match Reply-To domain (${replyDomain})`,
        cost: 1,
      });
    }
  }

  // 2) From/Return-Path mismatch
  if (fromEmails.length > 0 && returnPathEmails.length > 0) {
    const fromDomain = (fromEmails[0]!.split('@')[1] ?? '').toLowerCase();
    const returnDomain = (returnPathEmails[0]!.split('@')[1] ?? '').toLowerCase();
    if (fromDomain && returnDomain && fromDomain !== returnDomain) {
      signals.push({
        type: SignalType.EMAIL,
        value: `From: ${fromDomain}, Return-Path: ${returnDomain}`,
        confidence: 0.7,
        rawData: { check: 'from_return_path_mismatch', fromDomain, returnDomain },
        label: `From domain (${fromDomain}) does not match Return-Path domain (${returnDomain})`,
        cost: 1,
      });
    }
  }

  // 3) Display name spoofing (display name contains email-like string different from actual sender)
  const displayNameEmail = from.match(/^"?([^"<]*@[^"<>]*)"?\s*</);
  if (displayNameEmail && displayNameEmail[1] && fromEmails.length > 0) {
    const displayEmail = displayNameEmail[1].trim().toLowerCase();
    const actualEmail = fromEmails[0]!.toLowerCase();
    if (displayEmail !== actualEmail && displayEmail.includes('@')) {
      signals.push({
        type: SignalType.EMAIL,
        value: `Display: ${displayEmail}, Actual: ${actualEmail}`,
        confidence: 0.85,
        rawData: { check: 'display_name_spoofing', displayEmail, actualEmail },
        label: 'Display name contains different email address — possible spoofing',
        cost: 1,
      });
    }
  }

  // 4) SPF fail
  if (receivedSpf && /fail/i.test(receivedSpf) && !/softfail/i.test(receivedSpf)) {
    signals.push({
      type: SignalType.EMAIL,
      value: receivedSpf,
      confidence: 0.8,
      rawData: { check: 'spf_fail' },
      label: 'SPF authentication failed — sender may be forged',
      cost: 2,
    });
  } else if (receivedSpf && /softfail/i.test(receivedSpf)) {
    signals.push({
      type: SignalType.EMAIL,
      value: receivedSpf,
      confidence: 0.5,
      rawData: { check: 'spf_softfail' },
      label: 'SPF soft-fail — sender domain does not fully authorize this server',
      cost: 2,
    });
  }

  // 5) No DKIM signature
  if (!dkim) {
    signals.push({
      type: SignalType.EMAIL,
      value: 'missing',
      confidence: 0.4,
      rawData: { check: 'no_dkim' },
      label: 'No DKIM signature found — email authenticity cannot be verified',
      cost: 2,
    });
  }

  // 6) Free email provider pretending to be business
  const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'mail.com', 'protonmail.com', 'yandex.com', 'mail.ru'];
  if (fromEmails.length > 0) {
    const fromDomain = (fromEmails[0]!.split('@')[1] ?? '').toLowerCase();
    if (fromDomain && freeProviders.includes(fromDomain)) {
      // Check if the display name suggests a business
      const businessHints = /\b(support|billing|security|admin|service|team|helpdesk|noreply|no-reply|notification|alert)\b/i;
      if (businessHints.test(from) || businessHints.test(fromEmails[0] ?? '')) {
        signals.push({
          type: SignalType.EMAIL,
          value: from,
          confidence: 0.75,
          rawData: { check: 'free_provider_business_pretense', fromDomain },
          label: `Sender uses free provider (${fromDomain}) but claims to be a business/service`,
          cost: 1,
        });
      }
    }
  }

  // 7) Subject line analysis
  if (subject) {
    const urgentSubjectPatterns = [
      /^(RE|FW|FWD):\s*(RE|FW|FWD):/i,  // Fake forwarding chain
      /urgent|immediate|action\s*required|verify\s*now|suspended|locked|compromised/i,
      /winner|congratulations|selected|prize|lottery/i,
      /invoice|payment\s*(due|failed|declined)|billing\s*error/i,
    ];
    for (const pattern of urgentSubjectPatterns) {
      const subMatch = subject.match(pattern);
      if (subMatch) {
        signals.push({
          type: SignalType.EMAIL,
          value: subject,
          confidence: 0.6,
          rawData: { check: 'suspicious_subject', matched: subMatch[0] },
          label: `Suspicious email subject: "${subject}"`,
          cost: 1,
        });
      }
    }
  }

  // 8) Email header anomaly detection
  const headerAnomalySignals = extractHeaderAnomalySignals(headers);
  signals.push(...headerAnomalySignals);

  // 9) Analyze body text
  const bodySignals = extractTextSignals(body);
  signals.push(...bodySignals);

  return signals;
}

// ---------------------------------------------------------------------------
// extractDomainSignals
// ---------------------------------------------------------------------------
export function extractDomainSignals(whoisData: WhoisData): Signal[] {
  const signals: Signal[] = [];

  // 1) Domain age
  if (whoisData.creationDate) {
    const created = new Date(whoisData.creationDate);
    const now = new Date();
    const ageDays = (now.getTime() - created.getTime()) / (1000 * 60 * 60 * 24);

    if (ageDays < 30) {
      signals.push({
        type: SignalType.WHOIS,
        value: `${Math.floor(ageDays)} days`,
        confidence: 0.85,
        rawData: { check: 'domain_age', ageDays, creationDate: whoisData.creationDate },
        label: `Very new domain (${Math.floor(ageDays)} days old)`,
        cost: 3,
      });
    } else if (ageDays < 90) {
      signals.push({
        type: SignalType.WHOIS,
        value: `${Math.floor(ageDays)} days`,
        confidence: 0.65,
        rawData: { check: 'domain_age', ageDays, creationDate: whoisData.creationDate },
        label: `Recently registered domain (${Math.floor(ageDays)} days old)`,
        cost: 3,
      });
    } else if (ageDays < 365) {
      signals.push({
        type: SignalType.WHOIS,
        value: `${Math.floor(ageDays)} days`,
        confidence: 0.4,
        rawData: { check: 'domain_age', ageDays, creationDate: whoisData.creationDate },
        label: `Domain less than 1 year old (${Math.floor(ageDays)} days)`,
        cost: 3,
      });
    }
  }

  // 2) Short registration period
  if (whoisData.creationDate && whoisData.expirationDate) {
    const created = new Date(whoisData.creationDate);
    const expires = new Date(whoisData.expirationDate);
    const registrationYears = (expires.getTime() - created.getTime()) / (1000 * 60 * 60 * 24 * 365);
    if (registrationYears <= 1) {
      signals.push({
        type: SignalType.WHOIS,
        value: `${registrationYears.toFixed(1)} years`,
        confidence: 0.55,
        rawData: { check: 'short_registration', registrationYears },
        label: `Short registration period (${registrationYears.toFixed(1)} years) — scam domains are often registered for 1 year`,
        cost: 3,
      });
    }
  }

  // 3) Suspicious registrar
  if (whoisData.registrar) {
    const lowerRegistrar = whoisData.registrar.toLowerCase();
    for (const sus of SUSPICIOUS_REGISTRARS) {
      if (lowerRegistrar.includes(sus)) {
        signals.push({
          type: SignalType.WHOIS,
          value: whoisData.registrar,
          confidence: 0.4,
          rawData: { check: 'suspicious_registrar' },
          label: `Registrar "${whoisData.registrar}" is commonly used for malicious domains`,
          cost: 3,
        });
        break;
      }
    }
  }

  // 4) Privacy protection
  if (whoisData.privacyProtected) {
    signals.push({
      type: SignalType.WHOIS,
      value: 'privacy_protected',
      confidence: 0.3,
      rawData: { check: 'privacy_protection' },
      label: 'WHOIS privacy protection enabled — common for both legitimate and malicious domains',
      cost: 3,
    });
  }

  // 5) High-risk registration country
  const highRiskCountries = new Set(['RU', 'CN', 'NG', 'IN', 'PH', 'UA', 'RO', 'BR', 'VN', 'ID']);
  if (whoisData.registrantCountry && highRiskCountries.has(whoisData.registrantCountry.toUpperCase())) {
    signals.push({
      type: SignalType.WHOIS,
      value: whoisData.registrantCountry,
      confidence: 0.35,
      rawData: { check: 'high_risk_country', country: whoisData.registrantCountry },
      label: `Domain registered in higher-risk country: ${whoisData.registrantCountry}`,
      cost: 3,
    });
  }

  return signals;
}

// ---------------------------------------------------------------------------
// extractSslSignals
// ---------------------------------------------------------------------------
export function extractSslSignals(sslData: SslData): Signal[] {
  const signals: Signal[] = [];

  if (sslData.selfSigned) {
    signals.push({
      type: SignalType.SSL,
      value: 'self-signed',
      confidence: 0.75,
      rawData: { check: 'self_signed', issuer: sslData.issuer },
      label: 'SSL certificate is self-signed — not issued by trusted authority',
      cost: 2,
    });
  }

  if (sslData.expired) {
    signals.push({
      type: SignalType.SSL,
      value: 'expired',
      confidence: 0.7,
      rawData: { check: 'expired', validTo: sslData.validTo },
      label: `SSL certificate expired on ${sslData.validTo}`,
      cost: 2,
    });
  }

  // Free SSL issuer (not inherently bad, but scam sites rarely pay for DV/OV/EV certs)
  const freeSslIssuers = ["let's encrypt", 'letsencrypt', 'zerossl', 'buypass', 'ssl.com free'];
  if (sslData.issuer) {
    const lowerIssuer = sslData.issuer.toLowerCase();
    if (freeSslIssuers.some(f => lowerIssuer.includes(f))) {
      signals.push({
        type: SignalType.SSL,
        value: sslData.issuer,
        confidence: 0.2,
        rawData: { check: 'free_ssl', issuer: sslData.issuer },
        label: `Free SSL certificate from ${sslData.issuer} — not inherently suspicious but noted`,
        cost: 2,
      });
    }
  }

  // Short validity period
  if (sslData.validFrom && sslData.validTo) {
    const from = new Date(sslData.validFrom);
    const to = new Date(sslData.validTo);
    const days = (to.getTime() - from.getTime()) / (1000 * 60 * 60 * 24);
    if (days < 45) {
      signals.push({
        type: SignalType.SSL,
        value: `${Math.floor(days)} days validity`,
        confidence: 0.5,
        rawData: { check: 'short_validity', days },
        label: `Very short SSL validity period (${Math.floor(days)} days)`,
        cost: 2,
      });
    }
  }

  return signals;
}

// ---------------------------------------------------------------------------
// Phone number extraction and analysis
// Toll-free scam prefixes per FTC/FCC scam call data; 800/888/877/866/855/844/833
// are the most-spoofed prefixes in government-impersonation robocall scams.
// Premium-rate 900/976 are pay-per-call and used in prize/entertainment scams.
// ---------------------------------------------------------------------------
const TOLL_FREE_PREFIXES = ['800', '888', '877', '866', '855', '844', '833'];
const PREMIUM_RATE_PREFIXES = ['900', '976'];

/** Urgency phrases that dramatically increase phone scam probability when
 *  co-occurring with a toll-free number in the same message. */
const PHONE_URGENCY_COOCCURRENCE = /\b(act now|call immediately|call now|urgent|expires today|your account (will be|has been)|final warning|respond immediately|limited time|deadline|time-sensitive|last chance|24 hours?)\b/i;

function extractPhoneNumbers(text: string): PhoneAnalysis[] {
  const results: PhoneAnalysis[] = [];
  // Match various phone formats: (xxx) xxx-xxxx, xxx-xxx-xxxx, +1xxxxxxxxxx, etc.
  const phoneRegex = /(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g;
  const matches = text.match(phoneRegex) || [];

  // Evaluate urgency in the full message once for co-occurrence analysis
  const messageHasUrgency = PHONE_URGENCY_COOCCURRENCE.test(text);

  for (const raw of matches) {
    const digits = raw.replace(/\D/g, '');
    const areaCode = digits.length >= 10 ? digits.substring(digits.length - 10, digits.length - 7) : '';

    const isTollFree = TOLL_FREE_PREFIXES.includes(areaCode);
    const isPremiumRate = PREMIUM_RATE_PREFIXES.includes(areaCode);
    const isInternational = digits.length > 11;

    let suspicionLevel = 0;
    let reason = 'Standard phone number';

    if (isPremiumRate) {
      suspicionLevel = 0.9;
      reason = `Premium-rate number (${areaCode}) — callers are charged per-minute fees`;
    } else if (isTollFree) {
      suspicionLevel = 0.4;
      reason = `Toll-free number (${areaCode}) — commonly used in scam calls to appear legitimate`;
    }

    // Check for scam-associated call-to-action in context around the phone number
    const idx = text.indexOf(raw);
    const context = text.substring(Math.max(0, idx - 80), Math.min(text.length, idx + raw.length + 80));
    if (/\b(call\s*(now|immediately|today|us)|dial|phone|reach\s*us)\b/i.test(context)) {
      suspicionLevel = Math.min(1, suspicionLevel + 0.2);
      reason += '; paired with call-to-action';
    }

    // Urgency co-occurrence: phone + urgency in same message is a strong scam signal
    // (FTC: 90%+ of government impersonation scams combine toll-free + urgency)
    if (isTollFree && messageHasUrgency) {
      suspicionLevel = Math.min(1, suspicionLevel + 0.35);
      reason += '; toll-free number co-occurs with urgency language (high scam indicator)';
    }

    results.push({ number: raw, isTollFree, isPremiumRate, isInternational, suspicionLevel, reason });
  }
  return results;
}

// ---------------------------------------------------------------------------
// Cryptocurrency wallet address detection
// Regex patterns based on official address format specifications.
// Financial context detection: wallet address in a message that also contains
// payment-demand language dramatically increases scam probability.
// ---------------------------------------------------------------------------

/** Financial-context keywords that escalate wallet-detection confidence */
const CRYPTO_FINANCIAL_CONTEXT = /\b(send|transfer|deposit|pay|payment|wire|wallet|address|amount|owe|debt|fee|charge|invoice|scam|fraud|irs|police|arrest|fine|bail|ransom)\b/i;

function detectCryptoWallets(text: string): CryptoWalletDetection[] {
  const wallets: CryptoWalletDetection[] = [];

  // Evaluate whether the full message has financial context once
  const hasFinancialContext = CRYPTO_FINANCIAL_CONTEXT.test(text);

  /**
   * Bitcoin address validation:
   *   - Legacy P2PKH: starts with 1, 26–34 base58 chars (excluding 0/O/I/l)
   *   - P2SH:         starts with 3, same charset
   *   - Bech32/SegWit: starts with bc1, 14–74 alphanumeric chars (no b/i/o/1)
   * Source: BIP-0173, Bitcoin Wiki Address formats
   */
  const btcLegacy = text.match(/\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b/g) || [];
  const btcBech32 = text.match(/\bbc1[a-zA-HJ-NP-Z0-9]{25,62}\b/g) || [];
  for (const addr of [...btcLegacy, ...btcBech32]) {
    const baseConf = 0.85;
    wallets.push({
      type: 'BTC',
      address: addr,
      confidence: hasFinancialContext ? Math.min(0.97, baseConf + 0.1) : baseConf,
    });
  }

  /**
   * Ethereum address validation:
   *   - Starts with 0x followed by exactly 40 hex characters (20 bytes)
   *   - Total length: exactly 42 characters
   * Source: EIP-55, Ethereum Yellow Paper
   */
  const ethAddresses = text.match(/\b0x[0-9a-fA-F]{40}\b/g) || [];
  for (const addr of ethAddresses) {
    const baseConf = 0.9;
    wallets.push({
      type: 'ETH',
      address: addr,
      confidence: hasFinancialContext ? Math.min(0.98, baseConf + 0.08) : baseConf,
    });
  }

  // Monero (starts with 4, 95 chars — privacy coin, high use in ransomware)
  const xmrAddresses = text.match(/\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b/g) || [];
  for (const addr of xmrAddresses) {
    wallets.push({ type: 'XMR', address: addr, confidence: hasFinancialContext ? 0.95 : 0.85 });
  }

  // Litecoin (starts with L, M, or ltc1)
  const ltcAddresses = text.match(/\b[LM][a-km-zA-HJ-NP-Z1-9]{26,33}\b/g) || [];
  const ltcBech32 = text.match(/\bltc1[a-zA-HJ-NP-Z0-9]{25,62}\b/g) || [];
  for (const addr of [...ltcAddresses, ...ltcBech32]) {
    wallets.push({ type: 'LTC', address: addr, confidence: 0.8 });
  }

  // Solana (base58, 32-44 chars) — only flag with crypto context to avoid FP
  const solAddresses = text.match(/\b[1-9A-HJ-NP-Za-km-z]{32,44}\b/g) || [];
  for (const addr of solAddresses) {
    const idx = text.indexOf(addr);
    const context = text.substring(Math.max(0, idx - 100), Math.min(text.length, idx + addr.length + 100));
    if (/\b(sol(ana)?|crypto|wallet|send|transfer|deposit)\b/i.test(context) && addr.length >= 40) {
      wallets.push({ type: 'SOL', address: addr, confidence: 0.7 });
    }
  }

  return wallets;
}

// ---------------------------------------------------------------------------
// Email header anomaly detection
// ---------------------------------------------------------------------------
function detectEmailHeaderAnomalies(headers: Record<string, string>): EmailHeaderAnomaly[] {
  const anomalies: EmailHeaderAnomaly[] = [];

  // X-Mailer spoofing: check for unusual or known-spoofed X-Mailer values
  const xMailer = headers['x-mailer'] || headers['X-Mailer'] || '';
  if (xMailer) {
    const spoofedMailers = /\b(the\s*bat|microsoft\s*outlook\s*1[0-5]|outlook\s*express|eudora|foxmail\s*[1-5])\b/i;
    if (spoofedMailers.test(xMailer)) {
      anomalies.push({
        anomalyType: 'x_mailer_spoofing',
        description: `Suspicious X-Mailer: "${xMailer}" — outdated or commonly spoofed mail client`,
        severity: 0.7,
        evidence: xMailer,
      });
    }
    // Check for PHP mailer (often used in spam scripts)
    if (/phpmailer|swiftmailer|php\s*mail/i.test(xMailer)) {
      anomalies.push({
        anomalyType: 'x_mailer_script',
        description: `X-Mailer indicates script-based sending: "${xMailer}"`,
        severity: 0.6,
        evidence: xMailer,
      });
    }
  }

  // Received header chain analysis
  const receivedHeaders: string[] = [];
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === 'received') {
      receivedHeaders.push(value);
    }
  }
  // Multiple received headers as single string (comma or semicolon separated)
  const received = headers['received'] || headers['Received'] || '';
  if (received) {
    const hops = received.split(/;\s*(?=from\s)/i);
    // No received headers at all is suspicious
    if (hops.length === 0 || (hops.length === 1 && hops[0].trim().length < 10)) {
      anomalies.push({
        anomalyType: 'missing_received_chain',
        description: 'Missing or empty Received header chain — may indicate locally crafted email',
        severity: 0.7,
        evidence: 'No valid Received headers found',
      });
    }
    // Check for suspicious hops
    for (const hop of hops) {
      // Localhost/private IP as originator
      if (/from\s+(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)/i.test(hop)) {
        anomalies.push({
          anomalyType: 'private_ip_origin',
          description: 'Email originated from private/localhost IP — may be spoofed or from a compromised machine',
          severity: 0.6,
          evidence: hop.substring(0, 120),
        });
      }
    }
  }

  // Timezone consistency check
  const dateHeader = headers['date'] || headers['Date'] || '';
  if (dateHeader && received) {
    const dateTzMatch = dateHeader.match(/([+-]\d{4})/);
    const receivedTzMatch = received.match(/([+-]\d{4})/);
    if (dateTzMatch && receivedTzMatch && dateTzMatch[1] !== receivedTzMatch[1]) {
      anomalies.push({
        anomalyType: 'timezone_mismatch',
        description: `Date header timezone (${dateTzMatch[1]}) differs from Received header timezone (${receivedTzMatch[1]})`,
        severity: 0.5,
        evidence: `Date TZ: ${dateTzMatch[1]}, Received TZ: ${receivedTzMatch[1]}`,
      });
    }
  }

  // Content-Type anomalies
  const contentType = headers['content-type'] || headers['Content-Type'] || '';
  if (contentType) {
    // HTML-only email with no plain text alternative (common in phishing)
    if (/text\/html/i.test(contentType) && !/multipart\/alternative/i.test(contentType)) {
      anomalies.push({
        anomalyType: 'html_only_email',
        description: 'Email contains only HTML content with no plain text alternative — common in phishing emails',
        severity: 0.4,
        evidence: contentType,
      });
    }
  }

  // MIME version anomalies
  const mimeVersion = headers['mime-version'] || headers['MIME-Version'] || '';
  if (mimeVersion && mimeVersion.trim() !== '1.0') {
    anomalies.push({
      anomalyType: 'unusual_mime_version',
      description: `Unusual MIME version: "${mimeVersion}" (expected 1.0)`,
      severity: 0.5,
      evidence: mimeVersion,
    });
  }

  return anomalies;
}

// ---------------------------------------------------------------------------
// QR code URL pattern detection
// ---------------------------------------------------------------------------
const QR_CODE_PATTERNS: Array<{ pattern: RegExp; label: string; weight: number }> = [
  { pattern: /\b(scan\s*(this\s*)?(qr|code|barcode))\b/i, label: 'qr_scan_instruction', weight: 0.6 },
  { pattern: /\b(qr\s*code\s*(below|attached|above|here|included))\b/i, label: 'qr_code_reference', weight: 0.6 },
  { pattern: /\b(scan\s*(to|and)\s*(pay|verify|confirm|claim|access|login|sign\s*in))\b/i, label: 'qr_scan_action', weight: 0.75 },
  { pattern: /\b(point\s*your\s*(camera|phone)\s*(at|to)\s*(the|this))\b/i, label: 'qr_camera_instruction', weight: 0.65 },
  { pattern: /\b(qr\s*code\s*(payment|transfer|verification))\b/i, label: 'qr_payment', weight: 0.8 },
];

// ---------------------------------------------------------------------------
// Social media impersonation patterns
// ---------------------------------------------------------------------------
const SOCIAL_MEDIA_PATTERNS: Array<{ pattern: RegExp; label: string; weight: number }> = [
  { pattern: /\b(verified\s*(badge|account|status)|blue\s*(check|tick|badge)|get\s*verified)\b/i, label: 'social_fake_verification', weight: 0.75 },
  { pattern: /[\u2713\u2714\u2705\u2611]\s*(verified|official|authentic)/i, label: 'social_verification_emoji', weight: 0.8 },
  { pattern: /\b(official\s*(page|account|profile|channel)|this\s*is\s*(the\s*)?real)\b/i, label: 'social_official_claim', weight: 0.6 },
  { pattern: /\b(follow\s*(me|us)\s*(on|at)|dm\s*(me|us)\s*(for|to)|slide\s*into\s*(my|our)\s*dm)/i, label: 'social_engagement_bait', weight: 0.5 },
  { pattern: /\b(giveaway|give\s*away)\b.{0,40}\b(follow|like|share|retweet|comment|tag)\b/i, label: 'social_giveaway_scam', weight: 0.7 },
  { pattern: /\b(account\s*(will\s*be|has\s*been)\s*(deleted|removed|suspended)\s*(if|unless))\b/i, label: 'social_deletion_threat', weight: 0.8 },
  { pattern: /\b(your\s*(followers?|subscribers?|friends?)\s*(will|can)\s*(see|know))\b/i, label: 'social_exposure_threat', weight: 0.65 },
  { pattern: /\b(copyright\s*(strike|violation|infringement|claim)|dmca\s*(notice|takedown))\b/i, label: 'social_copyright_scam', weight: 0.7 },
  { pattern: /\b(@[a-zA-Z0-9_]{1,2}[0-9lI]{2,})\b/i, label: 'social_lookalike_handle', weight: 0.6 },
  { pattern: /\b(link\s*in\s*(bio|description|profile)|check\s*(my|our)\s*(bio|profile|link))\b/i, label: 'social_link_in_bio', weight: 0.45 },
];

// ---------------------------------------------------------------------------
// Phone signal extraction helper
// ---------------------------------------------------------------------------
export function extractPhoneSignals(text: string): Signal[] {
  const signals: Signal[] = [];
  const phones = extractPhoneNumbers(text);
  for (const phone of phones) {
    if (phone.suspicionLevel > 0.3) {
      signals.push({
        type: SignalType.TEXT,
        value: phone.number,
        confidence: phone.suspicionLevel,
        rawData: { check: 'phone_analysis', ...phone },
        label: `Suspicious phone number ${phone.number}: ${phone.reason}`,
        cost: 1,
      });
    }
  }
  return signals;
}

// ---------------------------------------------------------------------------
// Crypto wallet signal extraction helper
// ---------------------------------------------------------------------------
export function extractCryptoSignals(text: string): Signal[] {
  const signals: Signal[] = [];
  const wallets = detectCryptoWallets(text);
  for (const wallet of wallets) {
    signals.push({
      type: SignalType.TEXT,
      value: wallet.address,
      confidence: wallet.confidence,
      rawData: { check: 'crypto_wallet', walletType: wallet.type },
      label: `${wallet.type} wallet address detected: ${wallet.address.substring(0, 20)}...`,
      cost: 1,
    });
  }
  return signals;
}

// ---------------------------------------------------------------------------
// Email header anomaly signal extraction helper
// ---------------------------------------------------------------------------
export function extractHeaderAnomalySignals(headers: Record<string, string>): Signal[] {
  const signals: Signal[] = [];
  const anomalies = detectEmailHeaderAnomalies(headers);
  for (const anomaly of anomalies) {
    signals.push({
      type: SignalType.EMAIL,
      value: anomaly.evidence,
      confidence: anomaly.severity,
      rawData: { check: 'header_anomaly', anomalyType: anomaly.anomalyType },
      label: anomaly.description,
      cost: 2,
    });
  }
  return signals;
}

// ---------------------------------------------------------------------------
// Exported pattern sets (for use by other layers)
// ---------------------------------------------------------------------------
export {
  URGENCY_PATTERNS,
  FINANCIAL_PATTERNS,
  IMPERSONATION_PATTERNS,
  TOO_GOOD_PATTERNS,
  THREAT_PATTERNS,
  PAYMENT_METHOD_PATTERNS,
  BRAND_DOMAINS,
  URL_SHORTENERS,
  URL_SHORTENERS_HIGH_ABUSE,
  URL_SHORTENERS_MEDIUM_ABUSE,
  URL_SHORTENERS_LOW_ABUSE,
  SUSPICIOUS_TLDS,
  SUSPICIOUS_TLDS_TIER1,
  SUSPICIOUS_TLDS_TIER2,
  SUSPICIOUS_TLDS_TIER3,
  SUSPICIOUS_TLDS_TIER4,
  TLD_TIER_CONFIDENCE,
  KNOWN_HOMOGRAPH_ATTACKS,
  LEET_SUBSTITUTION_PATTERNS,
  QR_CODE_PATTERNS,
  SOCIAL_MEDIA_PATTERNS,
  shannonEntropy,
  containsHomoglyphs,
  getTldTier,
  getShortenerAbuseTier,
  detectBrandImpersonation,
  extractPhoneNumbers,
  detectCryptoWallets,
  detectEmailHeaderAnomalies,
};
