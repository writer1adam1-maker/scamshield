// ============================================================================
// ScamShield Deep URL Analysis Algorithm
// Proprietary algorithm: entropy calculation, DGA detection, punycode/IDN
// homograph detection, brand distance scoring, suspicious parameter detection,
// and subdomain abuse analysis.
// ============================================================================

import {
  ThreatLevel,
  DeepUrlBreakdown,
  DeepUrlResult,
} from './types';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const KNOWN_BRANDS = [
  // Real brand names
  'google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'netflix',
  'instagram', 'twitter', 'linkedin', 'youtube', 'yahoo', 'outlook', 'hotmail',
  'chase', 'bankofamerica', 'wellsfargo', 'citibank', 'capitalone', 'usbank',
  'venmo', 'zelle', 'cashapp', 'coinbase', 'binance', 'blockchain',
  'usps', 'fedex', 'ups', 'dhl', 'walmart', 'target', 'bestbuy',
  'irs', 'ssa', 'dmv', 'medicare', 'healthcare',
  'dropbox', 'icloud', 'onedrive', 'spotify', 'hulu', 'disney',
  'tiktok', 'snapchat', 'whatsapp', 'telegram', 'signal',
  'metamask', 'opensea', 'uniswap', 'phantom',
  // Real typosquatting variants observed in the wild (Levenshtein distance checks)
  'microsft', 'micros0ft', 'gooogle', 'g00gle', 'amaz0n', 'amazom',
  'paypa1', 'paypai', 'faceb00k', 'faceobok', 'netfllix', 'appie',
  // Phishing subdomain prefixes used as domain names
  'icloud-verify', 'wellsfargo-secure', 'chase-login', 'citibank-alert',
  'coinbase-support', 'binance-secure',
];

const SUSPICIOUS_PARAMS = [
  'token', 'verify', 'confirm', 'secure', 'login', 'auth', 'session',
  'account', 'password', 'credential', 'ssn', 'social', 'bank', 'card',
  'pin', 'otp', 'code', 'validate', 'update', 'restore', 'unlock',
  'suspend', 'reactivate', 'identity', 'refund', 'claim', 'reward',
  'redirect', 'callback', 'return_url', 'next', 'continue', 'goto',
];

// Tiered TLD risk scoring based on real abuse rate data (Spamhaus + SURBL + FTC reports)
// Tier 1 (score 0.95): Free/abused TLDs with near-universal abuse rates
// Tier 2 (score 0.75): High-abuse ccTLDs and common scam TLDs
// Tier 3 (score 0.55): Moderate-risk TLDs with elevated abuse rates
// Tier 4 (score 0.35): Low-cost TLDs used in phishing but also legitimate sites
const TLD_RISK_TIERS: Array<{ score: number; tlds: string[] }> = [
  {
    score: 0.95,
    tlds: ['buzz', 'wang', 'host', 'icu', 'live', 'tk', 'gq', 'ga', 'cf', 'top', 'ml', 'xin', 'info'],
  },
  {
    score: 0.75,
    tlds: ['cn', 'us', 'xyz', 'online', 'li'],
  },
  {
    score: 0.55,
    tlds: ['sbs', 'cfd', 'rest', 'bond', 'ru', 'pw', 'cc', 'ws', 'su', 'club', 'site', 'biz'],
  },
  {
    score: 0.35,
    tlds: ['work', 'click', 'link', 'support', 'zip', 'mov', 'qpon'],
  },
];

// Flat list kept for backwards-compatible flag detection (O(1) lookup)
const SUSPICIOUS_TLDS: Set<string> = new Set(
  TLD_RISK_TIERS.flatMap(tier => tier.tlds)
);

/** Returns the risk score for a given TLD, or 0 if not in any tier. */
function tldRiskScore(tld: string): number {
  const lower = tld.toLowerCase();
  for (const tier of TLD_RISK_TIERS) {
    if (tier.tlds.includes(lower)) return tier.score;
  }
  return 0;
}

const URL_SHORTENERS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'ow.ly', 'buff.ly',
  'adf.ly', 'shorte.st', 'bc.vc', 'j.mp', 'rb.gy', 'cutt.ly', 'short.io',
];

// Homograph mapping: confusable Unicode characters to their ASCII equivalents
// Sources: Unicode Consortium confusables.txt, real-world phishing kit analysis
const HOMOGLYPH_MAP: Record<string, string> = {
  // Latin→Cyrillic (IDN homograph attack chars)
  '\u0430': 'a', // Cyrillic а (U+0430)
  '\u0441': 'c', // Cyrillic с (U+0441)
  '\u0435': 'e', // Cyrillic е (U+0435)
  '\u043E': 'o', // Cyrillic о (U+043E)
  '\u0440': 'p', // Cyrillic р (U+0440)
  '\u0445': 'x', // Cyrillic х (U+0445)
  '\u0443': 'y', // Cyrillic у (U+0443)
  '\u0455': 's', // Cyrillic ѕ (U+0455)
  '\u0456': 'i', // Ukrainian і (U+0456)
  '\u0458': 'j', // Cyrillic ј (U+0458)
  '\u04BB': 'h', // Cyrillic һ (U+04BB)
  '\u0501': 'd', // Cyrillic ԁ (U+0501)
  '\u051B': 'q', // Cyrillic ԛ (U+051B)
  '\u051D': 'w', // Cyrillic ԝ (U+051D)
  // Latin→Greek
  '\u03BF': 'o', // Greek ο (U+03BF)
  '\u03BD': 'v', // Greek ν (U+03BD)
  '\u03C1': 'p', // Greek ρ (U+03C1)
  '\u03B1': 'a', // Greek α (U+03B1)
  '\u03B5': 'e', // Greek ε (U+03B5)
  // Other Latin lookalikes
  '\u0261': 'g', // Latin ɡ (U+0261)
  '\u026A': 'i', // Latin ɪ (U+026A)
  '\u0131': 'i', // Dotless ı (U+0131)
  '\u1E37': 'l', // Latin ḷ (U+1E37)
  '\u1E43': 'm', // Latin ṃ (U+1E43)
  '\u1E47': 'n', // Latin ṇ (U+1E47)
  '\u1E63': 's', // Latin ṣ (U+1E63)
  '\u1E6D': 't', // Latin ṭ (U+1E6D)
  '\u0411': 'B', // Cyrillic Б (U+0411)
  // Accented Latin (used in punycode squatting)
  '\u00E0': 'a', '\u00E1': 'a', // à á
  '\u00E8': 'e', '\u00E9': 'e', // è é
  '\u00EC': 'i', '\u00ED': 'i', // ì í
  '\u00F2': 'o', '\u00F3': 'o', // ò ó
  '\u00F9': 'u', '\u00FA': 'u', // ù ú
  // Number substitutions (leet-speak / typosquatting)
  '0': 'o', // Zero→O
  '1': 'l', // One→l (also I→l caught separately)
  '3': 'e', // Three→e
  '$': 's', // Dollar→s
  '6': 'b', // Six→b
  '9': 'g', // Nine→g
  '@': 'a', // At→a
};

// Visual bigram tricks that fool the eye (rn→m, vv→w, cl→d)
// These are checked as substring patterns, not single-char replacements
const VISUAL_BIGRAM_TRICKS: Array<{ pattern: string; lookalike: string }> = [
  { pattern: 'rn', lookalike: 'm' },
  { pattern: 'vv', lookalike: 'w' },
  { pattern: 'cl', lookalike: 'd' },
];

// ---------------------------------------------------------------------------
// URL Parsing
// ---------------------------------------------------------------------------

interface ParsedUrl {
  protocol: string;
  hostname: string;
  port: string;
  path: string;
  query: string;
  fragment: string;
  subdomain: string;
  domain: string;
  tld: string;
  params: Map<string, string>;
  fullUrl: string;
}

function parseUrl(url: string): ParsedUrl | null {
  try {
    // Add protocol if missing
    let normalized = url.trim();
    if (!/^https?:\/\//i.test(normalized)) {
      normalized = 'http://' + normalized;
    }

    const parsed = new URL(normalized);
    const hostParts = parsed.hostname.split('.');
    const tld = hostParts.length >= 2 ? hostParts[hostParts.length - 1] : '';
    const domain = hostParts.length >= 2 ? hostParts[hostParts.length - 2] : hostParts[0];
    const subdomain = hostParts.length >= 3 ? hostParts.slice(0, -2).join('.') : '';

    const params = new Map<string, string>();
    parsed.searchParams.forEach((value, key) => {
      params.set(key.toLowerCase(), value);
    });

    return {
      protocol: parsed.protocol.replace(':', ''),
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname,
      query: parsed.search,
      fragment: parsed.hash,
      subdomain,
      domain,
      tld,
      params,
      fullUrl: normalized,
    };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Entropy Calculation
// ---------------------------------------------------------------------------

/**
 * Shannon entropy of a string. High entropy suggests randomly generated strings
 * (common in phishing URLs and DGA domains).
 *
 * H = -SUM(p_i * log2(p_i)) for each unique character
 */
function shannonEntropy(str: string): number {
  if (str.length === 0) return 0;

  const freq = new Map<string, number>();
  for (const ch of str) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }

  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / str.length;
    if (p > 0) {
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

/**
 * Normalized entropy score (0-1). Thresholds calibrated for URLs:
 * - Normal domains: entropy ~2.5-3.5
 * - Suspicious/DGA: entropy >4.0
 * - Random strings: entropy ~4.5-5.0
 */
function entropyScore(hostname: string): number {
  const e = shannonEntropy(hostname);
  // Sigmoid mapping: center at 3.8, steep at 4.2+
  return 1 / (1 + Math.exp(-2.5 * (e - 3.8)));
}

// ---------------------------------------------------------------------------
// Path Depth Analysis
// ---------------------------------------------------------------------------

/**
 * Deep path structures are more suspicious.
 * Legitimate sites rarely go beyond 4-5 levels.
 * Phishing sites often use deep paths to mimic real URL structures.
 */
function pathDepthScore(path: string): number {
  const segments = path.split('/').filter((s) => s.length > 0);
  const depth = segments.length;

  // Check for suspicious path patterns
  let suspiciousPathBonus = 0;
  const pathLower = path.toLowerCase();

  // Long random-looking path segments
  for (const seg of segments) {
    if (seg.length > 20 && shannonEntropy(seg) > 3.5) {
      suspiciousPathBonus += 0.15;
    }
  }

  // Expanded real phishing kit path keywords (observed in phishing kit archives)
  const phishingPaths = [
    'login', 'signin', 'auth', 'authenticate', 'verify', 'verification',
    'confirm', 'validate', 'update', 'update-account', 'secure', 'security',
    'security-check', 'password', 'reset-password', 'change-password',
    'billing', 'payment', 'invoice', 'suspend', 'suspended', 'locked',
    'webscr', 'account', 'reactivate',
  ];
  for (const kw of phishingPaths) {
    if (pathLower.includes('/' + kw)) {
      suspiciousPathBonus += 0.2;
      break; // one match is enough to flag
    }
  }

  // Base score from depth
  const depthScore = Math.min(1, depth / 8);

  return Math.min(1, depthScore * 0.6 + suspiciousPathBonus);
}

// ---------------------------------------------------------------------------
// Suspicious Parameter Detection
// ---------------------------------------------------------------------------

function parameterScore(params: Map<string, string>): {
  score: number;
  suspiciousParams: string[];
} {
  const found: string[] = [];
  let score = 0;

  for (const [key] of params) {
    const keyLower = key.toLowerCase();
    for (const suspicious of SUSPICIOUS_PARAMS) {
      if (keyLower.includes(suspicious)) {
        found.push(key);
        score += 0.12;
        break;
      }
    }
  }

  // High entropy parameter values suggest tokens/session hijacking
  for (const [key, value] of params) {
    if (value.length > 30 && shannonEntropy(value) > 4.0) {
      if (!found.includes(key)) found.push(key);
      score += 0.1;
    }
  }

  // Many parameters = potentially harvesting data
  if (params.size > 5) {
    score += 0.1;
  }

  // Redirect chains
  for (const [key, value] of params) {
    if (/^(redirect|return|next|goto|continue|callback|url|link)/i.test(key)) {
      try {
        new URL(value);
        // Value is itself a URL - redirect chain
        score += 0.25;
        if (!found.includes(key)) found.push(key);
      } catch {
        // Not a URL, less suspicious
      }
    }
  }

  return { score: Math.min(1, score), suspiciousParams: found };
}

// ---------------------------------------------------------------------------
// DGA (Domain Generation Algorithm) Detection
// ---------------------------------------------------------------------------

/**
 * Detects algorithmically generated domains using:
 * 1. Character frequency distribution analysis
 * 2. Consonant-to-vowel ratio
 * 3. Bigram frequency vs English language
 * 4. Domain length
 */
function dgaScore(domain: string): number {
  if (domain.length < 4) return 0;

  const lower = domain.toLowerCase().replace(/[^a-z]/g, '');
  if (lower.length < 4) return 0;

  let score = 0;

  // 1. Consonant-to-vowel ratio
  const vowels = lower.replace(/[^aeiou]/g, '').length;
  const consonants = lower.length - vowels;
  const cvRatio = consonants / Math.max(1, vowels);
  // Normal English: ~1.5-2.5 ratio. DGA: often >3 or <1
  if (cvRatio > 3.5 || cvRatio < 0.8) {
    score += 0.25;
  } else if (cvRatio > 3.0) {
    score += 0.15;
  }

  // 2. Character frequency distribution (should roughly match English)
  const englishFreq: Record<string, number> = {
    e: 0.127, t: 0.091, a: 0.082, o: 0.075, i: 0.070, n: 0.067,
    s: 0.063, h: 0.061, r: 0.060, d: 0.043, l: 0.040, c: 0.028,
    u: 0.028, m: 0.024, w: 0.024, f: 0.022, g: 0.020, y: 0.020,
    p: 0.019, b: 0.015, v: 0.010, k: 0.008, j: 0.002, x: 0.002,
    q: 0.001, z: 0.001,
  };

  const charCounts = new Map<string, number>();
  for (const ch of lower) {
    charCounts.set(ch, (charCounts.get(ch) || 0) + 1);
  }

  let chiSquared = 0;
  for (const [ch, expected] of Object.entries(englishFreq)) {
    const observed = (charCounts.get(ch) || 0) / lower.length;
    chiSquared += Math.pow(observed - expected, 2) / Math.max(expected, 0.001);
  }
  // High chi-squared = distribution doesn't match English
  if (chiSquared > 0.15) score += 0.25;
  else if (chiSquared > 0.08) score += 0.15;

  // 3. Uncommon bigrams
  const uncommonBigrams = [
    'qx', 'qz', 'zx', 'jq', 'vq', 'wx', 'xj', 'zj', 'bx', 'cx',
    'dx', 'fx', 'gx', 'hx', 'jx', 'kx', 'lx', 'mx', 'px', 'rx',
    'sx', 'tx', 'vx', 'xk', 'xw', 'xz', 'zb', 'zc', 'zd', 'zf',
    'zg', 'zh', 'zk', 'zl', 'zm', 'zn', 'zp', 'zq', 'zr', 'zs',
    'zt', 'zv', 'zw',
  ];
  let uncommonCount = 0;
  for (let i = 0; i < lower.length - 1; i++) {
    const bigram = lower.substring(i, i + 2);
    if (uncommonBigrams.includes(bigram)) uncommonCount++;
  }
  if (uncommonCount > 0) score += Math.min(0.25, uncommonCount * 0.1);

  // 4. Domain length
  if (domain.length > 20) score += 0.15;
  else if (domain.length > 15) score += 0.08;

  // 5. Digit mixing in domain (common in DGA)
  const digitCount = domain.replace(/[^0-9]/g, '').length;
  const digitRatio = digitCount / domain.length;
  if (digitRatio > 0.3) score += 0.2;
  else if (digitRatio > 0.15) score += 0.1;

  return Math.min(1, score);
}

// ---------------------------------------------------------------------------
// Homograph / IDN Detection
// ---------------------------------------------------------------------------

interface HomoglyphDetection {
  original: string;
  lookalike: string;
}

function detectHomoglyphs(hostname: string): {
  score: number;
  detections: HomoglyphDetection[];
} {
  const detections: HomoglyphDetection[] = [];
  let score = 0;

  // Check each character against the homoglyph map
  for (let i = 0; i < hostname.length; i++) {
    const ch = hostname[i];
    const ascii = HOMOGLYPH_MAP[ch];
    if (ascii && ch !== ascii) {
      detections.push({ original: ch, lookalike: ascii });
      score += 0.3;
    }
  }

  // Check visual bigram tricks (rn→m, vv→w, cl→d)
  const hostLower = hostname.toLowerCase();
  for (const { pattern, lookalike } of VISUAL_BIGRAM_TRICKS) {
    if (hostLower.includes(pattern)) {
      detections.push({ original: pattern, lookalike });
      score += 0.25;
    }
  }

  // Check for punycode (xn--) prefix which indicates IDN
  if (hostname.includes('xn--')) {
    score += 0.4;
    detections.push({ original: 'xn--' + hostname, lookalike: '(punycode IDN detected)' });
  }

  // Mixed script detection: if hostname contains both ASCII and non-ASCII
  const hasAscii = /[a-zA-Z]/.test(hostname);
  const hasNonAscii = /[^\x00-\x7F]/.test(hostname);
  if (hasAscii && hasNonAscii) {
    score += 0.35;
  }

  return { score: Math.min(1, score), detections };
}

// ---------------------------------------------------------------------------
// Brand Distance Scoring (Levenshtein)
// ---------------------------------------------------------------------------

/**
 * Levenshtein edit distance between two strings.
 * Uses Wagner-Fischer dynamic programming algorithm.
 */
function levenshteinDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;

  // Optimization: early exit for identical strings
  if (a === b) return 0;
  if (m === 0) return n;
  if (n === 0) return m;

  // Use single-row optimization for memory efficiency
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  let curr = new Array(n + 1);

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(
        prev[j] + 1,       // deletion
        curr[j - 1] + 1,   // insertion
        prev[j - 1] + cost, // substitution
      );
    }
    [prev, curr] = [curr, prev];
  }

  return prev[n];
}

/**
 * Normalized brand distance: how close is this domain to a known brand?
 * Lower distance = more suspicious (likely typosquatting).
 */
function brandDistanceAnalysis(domain: string): {
  score: number;
  detectedBrands: { brand: string; distance: number }[];
} {
  const domainLower = domain.toLowerCase().replace(/[^a-z0-9]/g, '');
  const detected: { brand: string; distance: number }[] = [];
  let minNormalizedDistance = 1;

  for (const brand of KNOWN_BRANDS) {
    const distance = levenshteinDistance(domainLower, brand);
    const maxLen = Math.max(domainLower.length, brand.length);
    const normalizedDistance = maxLen > 0 ? distance / maxLen : 0;

    // If the domain is close to a brand but not exact, it's suspicious
    if (distance > 0 && distance <= 3 && normalizedDistance < 0.4) {
      detected.push({ brand, distance });
      minNormalizedDistance = Math.min(minNormalizedDistance, normalizedDistance);
    }

    // Check if brand name is embedded within domain — but NOT if the domain
    // IS the brand (e.g., "google" in "google.com" → domainLower="googlecom" or "wwwgooglecom")
    // Strip "www" prefix before checking
    const stripped = domainLower.replace(/^www/, '');
    const isActualBrand = stripped === brand || stripped === brand + 'com' || stripped === brand + 'org' || stripped === brand + 'net' || stripped === brand + 'gov' || stripped === brand + 'io';
    if (domainLower.includes(brand) && !isActualBrand) {
      detected.push({ brand, distance: 0.5 });
      minNormalizedDistance = Math.min(minNormalizedDistance, 0.15);
    }
  }

  // Score: inverse of minimum distance (closer = more suspicious)
  let score = 0;
  if (detected.length > 0) {
    score = Math.max(0, 1 - minNormalizedDistance * 2.5);
  }

  return { score: Math.min(1, score), detectedBrands: detected };
}

// ---------------------------------------------------------------------------
// Subdomain Analysis
// ---------------------------------------------------------------------------

function subdomainScore(
  subdomain: string,
  domain: string,
): number {
  if (!subdomain) return 0;

  let score = 0;
  const parts = subdomain.split('.');
  const subLower = subdomain.toLowerCase();

  // Excessive subdomains
  if (parts.length > 3) {
    score += 0.3;
  } else if (parts.length > 1) {
    score += 0.1;
  }

  // Brand name in subdomain (classic brand-in-subdomain attack)
  for (const brand of KNOWN_BRANDS) {
    if (subLower.includes(brand)) {
      score += 0.4;
      break;
    }
  }

  // Security/auth keywords in subdomain
  const authKeywords = [
    'secure', 'login', 'verify', 'auth', 'account', 'update', 'confirm',
    'support', 'service', 'help', 'admin', 'webmail', 'portal',
  ];
  for (const kw of authKeywords) {
    if (subLower.includes(kw)) {
      score += 0.15;
      break;
    }
  }

  // Very long subdomain
  if (subdomain.length > 30) {
    score += 0.2;
  }

  // IP-like subdomain patterns
  if (/\d{1,3}[-_.]\d{1,3}[-_.]\d{1,3}/.test(subdomain)) {
    score += 0.25;
  }

  return Math.min(1, score);
}

// ---------------------------------------------------------------------------
// Redirect Detection
// ---------------------------------------------------------------------------

function redirectScore(parsed: ParsedUrl): number {
  let score = 0;

  // URL shortener detection
  const fullHost = parsed.hostname.toLowerCase();
  for (const shortener of URL_SHORTENERS) {
    if (fullHost === shortener || fullHost.endsWith('.' + shortener)) {
      score += 0.4;
      break;
    }
  }

  // Redirect parameters in URL
  for (const [key, value] of parsed.params) {
    if (/^(redirect|return|next|goto|continue|callback|url|rurl|redir)/i.test(key)) {
      score += 0.2;
      // Double redirect (redirect param contains another redirect)
      if (/https?:\/\//i.test(value) && /redirect|return|next|goto/i.test(value)) {
        score += 0.3;
      }
    }
  }

  // URL-encoded URLs in the path
  if (/%2F%2F|%3A%2F%2F/i.test(parsed.path)) {
    score += 0.25;
  }

  // Data URI or javascript in params
  for (const [, value] of parsed.params) {
    if (/^(data:|javascript:)/i.test(value)) {
      score += 0.5;
    }
  }

  return Math.min(1, score);
}

// ---------------------------------------------------------------------------
// Phishing Kit Fingerprint Detection
// Real patterns sourced from PhishTank, OpenPhish, and phishing kit analysis
// ---------------------------------------------------------------------------

interface PhishingKitResult {
  score: number;
  matches: string[];
}

function detectPhishingKitFingerprints(parsed: ParsedUrl): PhishingKitResult {
  const matches: string[] = [];
  let score = 0;
  const pathLower = parsed.path.toLowerCase();
  const fullUrlLower = parsed.fullUrl.toLowerCase();

  // /webscr — classic PayPal phishing kit path
  if (/\/webscr(\?|\/|$)/.test(pathLower)) {
    matches.push('/webscr (PayPal phishing kit signature)');
    score += 0.5;
  }

  // /wp-content/.+(php|html) — compromised WordPress site used as phishing host
  if (/\/wp-content\/.+\.(php|html?)/.test(pathLower)) {
    matches.push('/wp-content/... PHP/HTML (compromised WordPress host pattern)');
    score += 0.4;
  }

  // /.well-known/ — abusing certificate verification directories to hide phishing pages
  if (/\/\.well-known\//.test(pathLower)) {
    matches.push('/.well-known/ path abuse (hiding phishing pages in cert-verification dir)');
    score += 0.35;
  }

  // ?email=...@ — pre-filled victim email (phishing kits inject victim address)
  if (/[?&]email=[^&]*@/.test(fullUrlLower)) {
    matches.push('Pre-filled email parameter (victim address injection)');
    score += 0.45;
  }

  // Base64-encoded params — phishing kits encode victim tokens/tracking data
  for (const [key, value] of parsed.params) {
    if (/^[A-Za-z0-9+/]{20,}={0,2}$/.test(value)) {
      matches.push(`Base64-encoded param value: ${key} (phishing kit token/tracking)`);
      score += 0.3;
      break; // one is enough to flag
    }
  }

  return { score: Math.min(1, score), matches };
}

// ---------------------------------------------------------------------------
// Composite Score & Public API
// ---------------------------------------------------------------------------

const WEIGHTS = {
  entropy: 0.11,
  pathDepth: 0.07,
  parameter: 0.11,
  redirect: 0.09,
  dga: 0.14,
  homograph: 0.17,
  brandDistance: 0.14,
  subdomain: 0.09,
  phishingKit: 0.08, // phishing kit fingerprints
};

function threatLevelFromScore(score: number): ThreatLevel {
  if (score >= 0.8) return 'CRITICAL';
  if (score >= 0.6) return 'HIGH';
  if (score >= 0.4) return 'MEDIUM';
  if (score >= 0.2) return 'LOW';
  return 'SAFE';
}

/**
 * Performs comprehensive deep analysis of a URL, combining eight
 * independent risk signals into a composite threat score.
 */
export function deepAnalyzeUrl(url: string): DeepUrlResult {
  const startTime = performance.now();

  const parsed = parseUrl(url);
  if (!parsed) {
    return {
      overallRiskScore: 0,
      threatLevel: 'SAFE',
      breakdown: {
        entropyScore: 0,
        pathDepthScore: 0,
        parameterScore: 0,
        redirectScore: 0,
        dgaScore: 0,
        homographScore: 0,
        brandDistanceScore: 0,
        subdomainScore: 0,
      },
      detectedBrands: [],
      suspiciousParams: [],
      homoglyphsDetected: [],
      flags: ['Invalid URL: could not be parsed'],
      processingTimeMs: performance.now() - startTime,
    };
  }

  const flags: string[] = [];

  // Compute all sub-scores
  const eScore = entropyScore(parsed.hostname);
  if (eScore > 0.5) flags.push(`High hostname entropy: ${shannonEntropy(parsed.hostname).toFixed(2)} bits`);

  const pdScore = pathDepthScore(parsed.path);
  if (pdScore > 0.4) flags.push(`Deep/suspicious path structure (${parsed.path.split('/').filter(Boolean).length} levels)`);

  const paramResult = parameterScore(parsed.params);
  if (paramResult.score > 0.3) flags.push(`Suspicious URL parameters detected: ${paramResult.suspiciousParams.join(', ')}`);

  const rScore = redirectScore(parsed);
  if (rScore > 0.3) flags.push('URL redirection chain detected');

  const dScore = dgaScore(parsed.domain);
  if (dScore > 0.4) flags.push('Domain resembles algorithmically generated (DGA)');

  const homoResult = detectHomoglyphs(parsed.hostname);
  if (homoResult.score > 0) flags.push(`Homograph/IDN characters detected in hostname`);

  const brandResult = brandDistanceAnalysis(parsed.domain + (parsed.subdomain ? '.' + parsed.subdomain : ''));
  if (brandResult.score > 0.3) {
    const brands = brandResult.detectedBrands.map((b) => b.brand).join(', ');
    flags.push(`Domain impersonates known brand(s): ${brands}`);
  }

  const sdScore = subdomainScore(parsed.subdomain, parsed.domain);
  if (sdScore > 0.3) flags.push(`Suspicious subdomain pattern: ${parsed.subdomain}`);

  const pkResult = detectPhishingKitFingerprints(parsed);
  if (pkResult.score > 0) {
    for (const m of pkResult.matches) {
      flags.push(`Phishing kit fingerprint: ${m}`);
    }
  }

  // Additional standalone checks
  if (parsed.protocol === 'http') {
    flags.push('Uses insecure HTTP protocol');
  }
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(parsed.hostname)) {
    flags.push('URL uses raw IP address instead of domain name');
  }
  if (SUSPICIOUS_TLDS.has(parsed.tld.toLowerCase())) {
    const tScore = tldRiskScore(parsed.tld);
    const tierLabel = tScore >= 0.95 ? 'Tier 1 (critical)'
      : tScore >= 0.75 ? 'Tier 2 (high)'
      : tScore >= 0.55 ? 'Tier 3 (medium)'
      : 'Tier 4 (elevated)';
    flags.push(`Uses high-risk TLD: .${parsed.tld} [${tierLabel}, abuse score ${tScore}]`);
  }
  if (parsed.port && !['80', '443', ''].includes(parsed.port)) {
    flags.push(`Non-standard port: ${parsed.port}`);
  }

  // Composite score
  const breakdown: DeepUrlBreakdown = {
    entropyScore: Math.round(eScore * 1000) / 1000,
    pathDepthScore: Math.round(pdScore * 1000) / 1000,
    parameterScore: Math.round(paramResult.score * 1000) / 1000,
    redirectScore: Math.round(rScore * 1000) / 1000,
    dgaScore: Math.round(dScore * 1000) / 1000,
    homographScore: Math.round(homoResult.score * 1000) / 1000,
    brandDistanceScore: Math.round(brandResult.score * 1000) / 1000,
    subdomainScore: Math.round(sdScore * 1000) / 1000,
    phishingKitScore: Math.round(pkResult.score * 1000) / 1000,
  };

  const overallRiskScore =
    WEIGHTS.entropy * eScore +
    WEIGHTS.pathDepth * pdScore +
    WEIGHTS.parameter * paramResult.score +
    WEIGHTS.redirect * rScore +
    WEIGHTS.dga * dScore +
    WEIGHTS.homograph * homoResult.score +
    WEIGHTS.brandDistance * brandResult.score +
    WEIGHTS.subdomain * sdScore +
    WEIGHTS.phishingKit * pkResult.score;

  // Bonus for combining multiple moderate signals (synergy effect)
  const moderateSignals = [eScore, pdScore, paramResult.score, rScore, dScore, homoResult.score, brandResult.score, sdScore, pkResult.score]
    .filter((s) => s > 0.3).length;
  const synergyBonus = moderateSignals >= 3 ? 0.1 * (moderateSignals - 2) : 0;

  const finalScore = Math.min(1, Math.round((overallRiskScore + synergyBonus) * 1000) / 1000);

  return {
    overallRiskScore: finalScore,
    threatLevel: threatLevelFromScore(finalScore),
    breakdown,
    detectedBrands: brandResult.detectedBrands,
    suspiciousParams: paramResult.suspiciousParams,
    homoglyphsDetected: homoResult.detections,
    flags,
    processingTimeMs: Math.round((performance.now() - startTime) * 100) / 100,
  };
}
