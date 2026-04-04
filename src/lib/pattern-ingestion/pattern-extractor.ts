// ============================================================================
// Pattern Extractor — Algorithmic extraction of scam patterns from text chunks
// Uses n-gram frequency analysis, TF-IDF scoring, and category classification
// ============================================================================

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

export interface ExtractedPattern {
  text: string;
  category: string;
  frequency: number;
  specificityScore: number;   // 0-1, higher = more unique to scams
  suggestedWeight: number;    // 1-30
  suggestedSeverity: "low" | "medium" | "high" | "critical";
  sourceExamples: string[];   // 2-3 example sentences where this was found
}

/**
 * Extract scam patterns from an array of text chunks.
 *
 * Algorithm:
 * 1. Tokenize each chunk into sentences
 * 2. Collect n-grams (2-5 words) across all sentences
 * 3. Filter out common English stopword sequences
 * 4. Score by frequency x specificity (IDF)
 * 5. Classify patterns by category using keyword hints
 * 6. Deduplicate against known patterns (built-in set)
 * 7. Return top unique patterns with metadata
 */
export function extractPatterns(chunks: string[]): ExtractedPattern[] {
  if (chunks.length === 0) return [];

  // Step 1: tokenize into sentences
  const allSentences: string[] = [];
  for (const chunk of chunks) {
    const sentences = tokenizeIntoSentences(chunk);
    allSentences.push(...sentences);
  }

  if (allSentences.length === 0) return [];

  const totalDocs = allSentences.length;

  // Step 2: collect n-grams (2-5 words) with frequency and document frequency
  const ngramFreq = new Map<string, number>();
  const ngramDocFreq = new Map<string, number>(); // how many sentences contain this ngram
  const ngramExamples = new Map<string, Set<string>>();

  for (const sentence of allSentences) {
    const words = normalizeText(sentence);
    if (words.length < 2) continue;

    const seenInThisSentence = new Set<string>();

    for (let n = 2; n <= Math.min(5, words.length); n++) {
      for (let i = 0; i <= words.length - n; i++) {
        const ngram = words.slice(i, i + n).join(" ");

        // Skip if it's all stopwords
        if (isAllStopwords(words.slice(i, i + n))) continue;

        ngramFreq.set(ngram, (ngramFreq.get(ngram) ?? 0) + 1);

        if (!seenInThisSentence.has(ngram)) {
          seenInThisSentence.add(ngram);
          ngramDocFreq.set(ngram, (ngramDocFreq.get(ngram) ?? 0) + 1);
        }

        // Store example sentences (keep up to 3)
        if (!ngramExamples.has(ngram)) ngramExamples.set(ngram, new Set());
        const examples = ngramExamples.get(ngram)!;
        if (examples.size < 3) {
          examples.add(sentence.length > 200 ? sentence.slice(0, 200) + "..." : sentence);
        }
      }
    }
  }

  // Step 3-4: score candidates by frequency x specificity (TF-IDF inspired)
  const candidates: Array<{
    ngram: string;
    freq: number;
    idf: number;
    score: number;
    examples: string[];
  }> = [];

  const minFrequency = Math.max(2, Math.floor(totalDocs * 0.02)); // at least 2% of docs or 2 occurrences

  for (const [ngram, freq] of ngramFreq) {
    if (freq < minFrequency) continue;
    if (isCommonPhrase(ngram)) continue;

    const docFreq = ngramDocFreq.get(ngram) ?? 1;
    const idf = Math.log(totalDocs / docFreq);
    const normalizedIdf = Math.min(idf / Math.log(totalDocs + 1), 1); // 0-1

    // Score: frequency * specificity, with a boost for scam-relevant terms
    const scamRelevance = getScamRelevanceBoost(ngram);
    const score = freq * normalizedIdf * scamRelevance;

    if (score > 0.5) {
      const examples = Array.from(ngramExamples.get(ngram) ?? []);
      candidates.push({ ngram, freq, idf: normalizedIdf, score, examples });
    }
  }

  // Sort by score descending
  candidates.sort((a, b) => b.score - a.score);

  // Step 5-6: deduplicate (remove substrings of higher-scoring ngrams) and classify
  const seen = new Set<string>();
  const results: ExtractedPattern[] = [];

  for (const candidate of candidates) {
    if (results.length >= 50) break; // cap at 50 patterns

    // Skip if this is a substring of an already-accepted pattern
    const isSubstring = Array.from(seen).some(
      (accepted) => accepted.includes(candidate.ngram) || candidate.ngram.includes(accepted),
    );
    if (isSubstring) continue;

    // Skip if it matches a known common pattern (dedup against built-in set)
    if (isKnownCommonPattern(candidate.ngram)) continue;

    seen.add(candidate.ngram);

    const category = classifyCategory(candidate.ngram);
    const severity = scoreSeverity(candidate.idf, candidate.freq, totalDocs);
    const weight = computeWeight(candidate.idf, candidate.freq, totalDocs);

    results.push({
      text: candidate.ngram,
      category,
      frequency: candidate.freq,
      specificityScore: Math.round(candidate.idf * 1000) / 1000,
      suggestedWeight: weight,
      suggestedSeverity: severity,
      sourceExamples: candidate.examples.slice(0, 3),
    });
  }

  return results;
}

// ---------------------------------------------------------------------------
// Tokenizer — split text into sentences
// ---------------------------------------------------------------------------

function tokenizeIntoSentences(text: string): string[] {
  // Split on sentence-ending punctuation followed by space or newline
  const raw = text
    .replace(/\r?\n/g, " ")
    .split(/(?<=[.!?])\s+/)
    .map((s) => s.trim())
    .filter((s) => s.length >= 10);

  return raw;
}

// ---------------------------------------------------------------------------
// Normalize — lowercase, remove punctuation, tokenize into words
// ---------------------------------------------------------------------------

function normalizeText(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s'-]/g, " ")
    .split(/\s+/)
    .filter((w) => w.length >= 2);
}

// ---------------------------------------------------------------------------
// Stopwords — common English words to filter out
// ---------------------------------------------------------------------------

const STOPWORDS = new Set([
  "the", "be", "to", "of", "and", "in", "that", "have", "it", "for",
  "not", "on", "with", "he", "as", "you", "do", "at", "this", "but",
  "his", "by", "from", "they", "we", "say", "her", "she", "or", "an",
  "will", "my", "one", "all", "would", "there", "their", "what", "so",
  "up", "out", "if", "about", "who", "get", "which", "go", "me", "when",
  "make", "can", "like", "no", "just", "him", "know", "take", "people",
  "into", "year", "your", "some", "them", "than", "then", "now", "look",
  "only", "come", "its", "over", "think", "also", "back", "after", "use",
  "two", "how", "our", "way", "even", "new", "want", "any", "these",
  "give", "day", "most", "us", "are", "is", "was", "were", "been", "has",
  "had", "did", "does", "being", "am", "very", "may", "could", "should",
]);

function isAllStopwords(words: string[]): boolean {
  return words.every((w) => STOPWORDS.has(w));
}

// ---------------------------------------------------------------------------
// Common phrase filter — generic phrases that aren't scam-specific
// ---------------------------------------------------------------------------

const COMMON_PHRASES = [
  "please click", "click here", "more information", "learn more",
  "terms and conditions", "privacy policy", "all rights reserved",
  "contact us", "read more", "see more", "for more", "thank you for",
  "we are", "you are", "it is", "this is", "that is", "there is",
  "have been", "will be", "can be", "may be", "would be", "should be",
  "has been", "had been", "could be", "do not", "does not", "did not",
  "was not", "were not", "is not", "are not",
];

function isCommonPhrase(ngram: string): boolean {
  return COMMON_PHRASES.some((cp) => ngram === cp);
}

// ---------------------------------------------------------------------------
// Scam relevance boost — keywords that indicate scam-specific phrasing
// ---------------------------------------------------------------------------

const SCAM_KEYWORDS: Record<string, number> = {
  "account": 1.5, "suspended": 2.0, "verify": 1.8, "urgent": 2.0,
  "immediately": 1.8, "confirm": 1.5, "password": 1.8, "security": 1.3,
  "unusual": 1.5, "unauthorized": 1.8, "payment": 1.5, "wire": 2.0,
  "transfer": 1.5, "gift": 1.5, "card": 1.3, "bitcoin": 1.8,
  "crypto": 1.8, "investment": 1.5, "guaranteed": 2.0, "returns": 1.5,
  "winner": 2.0, "prize": 2.0, "congratulations": 1.8, "lottery": 2.0,
  "claim": 1.5, "fee": 1.5, "customs": 1.5, "delivery": 1.3,
  "package": 1.3, "tracking": 1.3, "irs": 2.0, "tax": 1.3,
  "arrest": 2.0, "warrant": 2.0, "lawsuit": 1.8, "expire": 1.5,
  "deadline": 1.5, "limited": 1.3, "offer": 1.3, "act": 1.3,
  "ssn": 2.0, "social": 1.0, "medicare": 1.5, "refund": 1.5,
  "overpayment": 2.0, "romance": 1.5, "deployed": 1.5, "military": 1.3,
  "victim": 1.3, "scam": 1.5, "fraud": 1.5, "phishing": 1.8,
  "malware": 1.8, "virus": 1.5, "infected": 1.5, "hack": 1.5,
  "otp": 2.0, "code": 1.3, "passcode": 1.8, "pin": 1.5,
};

function getScamRelevanceBoost(ngram: string): number {
  const words = ngram.split(" ");
  let maxBoost = 1.0;
  for (const word of words) {
    const boost = SCAM_KEYWORDS[word];
    if (boost && boost > maxBoost) maxBoost = boost;
  }
  return maxBoost;
}

// ---------------------------------------------------------------------------
// Category classification — assign a threat category based on keyword hints
// ---------------------------------------------------------------------------

const CATEGORY_KEYWORDS: Record<string, string[]> = {
  URGENCY: [
    "urgent", "immediately", "act now", "right away", "expires",
    "deadline", "limited time", "last chance", "final warning", "hurry",
    "within 24 hours", "time sensitive", "don't delay",
  ],
  FINANCIAL: [
    "wire transfer", "bank account", "payment", "credit card", "debit",
    "money", "funds", "fee", "charge", "deposit", "withdrawal",
    "transaction", "billing", "invoice", "balance",
  ],
  ROMANCE: [
    "love", "heart", "relationship", "dating", "meet",
    "deployed overseas", "military", "widow", "lonely", "soul mate",
    "marry", "sweetheart", "darling",
  ],
  PHISHING: [
    "verify your", "confirm your", "update your", "login",
    "password", "credentials", "click link", "click here",
    "account suspended", "unusual activity", "security alert",
  ],
  CRYPTO_INVESTMENT: [
    "bitcoin", "crypto", "ethereum", "investment", "trading",
    "guaranteed returns", "profit", "roi", "portfolio",
    "passive income", "mining", "token", "nft",
  ],
  GOVERNMENT_IMPERSONATION: [
    "irs", "social security", "medicare", "government",
    "tax", "arrest warrant", "lawsuit", "legal action",
    "federal", "agent", "department",
  ],
  TECH_SUPPORT: [
    "virus", "malware", "infected", "computer", "microsoft",
    "apple", "tech support", "remote access", "teamviewer",
    "trojan", "security scan",
  ],
  PACKAGE_DELIVERY: [
    "package", "delivery", "shipping", "tracking", "usps",
    "fedex", "ups", "dhl", "customs", "parcel",
  ],
  LOTTERY_PRIZE: [
    "winner", "prize", "lottery", "sweepstakes", "congratulations",
    "selected", "claim", "reward", "jackpot",
  ],
  EMPLOYMENT: [
    "job", "work from home", "remote position", "salary",
    "hiring", "resume", "interview", "employee", "payroll",
  ],
};

function classifyCategory(ngram: string): string {
  const lower = ngram.toLowerCase();
  let bestCategory = "GENERIC";
  let bestMatchCount = 0;

  for (const [category, keywords] of Object.entries(CATEGORY_KEYWORDS)) {
    let matchCount = 0;
    for (const kw of keywords) {
      if (lower.includes(kw)) matchCount++;
    }
    if (matchCount > bestMatchCount) {
      bestMatchCount = matchCount;
      bestCategory = category;
    }
  }

  return bestCategory;
}

// ---------------------------------------------------------------------------
// Severity scoring
// ---------------------------------------------------------------------------

function scoreSeverity(
  idf: number,
  freq: number,
  totalDocs: number,
): "low" | "medium" | "high" | "critical" {
  const ratio = freq / Math.max(totalDocs, 1);
  const combined = idf * 0.6 + ratio * 0.4;

  if (combined >= 0.6) return "critical";
  if (combined >= 0.4) return "high";
  if (combined >= 0.2) return "medium";
  return "low";
}

// ---------------------------------------------------------------------------
// Weight computation (1-30 scale)
// ---------------------------------------------------------------------------

function computeWeight(idf: number, freq: number, totalDocs: number): number {
  const ratio = freq / Math.max(totalDocs, 1);
  const raw = (idf * 0.5 + ratio * 0.5) * 30;
  return Math.max(1, Math.min(30, Math.round(raw)));
}

// ---------------------------------------------------------------------------
// Known pattern deduplication — built-in patterns to skip
// These are commonly known and already in the immune repertoire
// ---------------------------------------------------------------------------

const KNOWN_PATTERNS = [
  "click here to verify",
  "account has been suspended",
  "update your payment",
  "confirm your identity",
  "you have won",
  "claim your prize",
  "wire transfer",
  "gift card payment",
  "act now before",
  "social security number",
];

function isKnownCommonPattern(ngram: string): boolean {
  return KNOWN_PATTERNS.some(
    (kp) => ngram === kp || (ngram.length > 8 && kp.includes(ngram)),
  );
}
