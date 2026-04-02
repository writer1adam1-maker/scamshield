// ============================================================================
// VERIDICT Layer 2: Conservation Law Violation Tensor
// Detects violations of 5 communication conservation laws.
// ============================================================================

import {
  AnalysisInput,
  ConservationLayerResult,
  ConservationViolation,
  SignalType,
} from './types';
import {
  BRAND_DOMAINS,
  URGENCY_PATTERNS,
  IMPERSONATION_PATTERNS,
  FINANCIAL_PATTERNS,
  THREAT_PATTERNS,
} from './signal-extractors';

// ---------------------------------------------------------------------------
// The 5 Conservation Laws
// ---------------------------------------------------------------------------
// Law 0: Identity-Provenance — claimed sender must match domain/WHOIS provenance
// Law 1: Information-Intent — info content must be proportional to action demanded
// Law 2: Urgency-Authority — urgency level must match sender authority level
// Law 3: Specificity-Personalization — specific claims must include personal details
// Law 4: Channel-Formality — communication channel must match message formality

const LAW_NAMES = [
  'Identity-Provenance',
  'Information-Intent',
  'Urgency-Authority',
  'Specificity-Personalization',
  'Channel-Formality',
  'Reward-Risk',
];

// ---------------------------------------------------------------------------
// Severity weights per law — Identity-Provenance violations are most serious
// ---------------------------------------------------------------------------
const LAW_SEVERITY_WEIGHTS = [
  1.5,   // Identity-Provenance: highest weight — sender authenticity is critical
  1.2,   // Information-Intent: high — information asymmetry is a key scam indicator
  1.3,   // Urgency-Authority: high — urgency from non-authoritative sources is very suspicious
  1.0,   // Specificity-Personalization: moderate
  0.8,   // Channel-Formality: lower — channel mismatches are less conclusive
  1.4,   // Reward-Risk: high — disproportionate reward claims are strong scam signals
];

// ---------------------------------------------------------------------------
// Explanatory text templates for each law violation
// ---------------------------------------------------------------------------
const LAW_EXPLANATIONS: Record<string, (evidence: string) => string> = {
  'Identity-Provenance': (evidence: string) =>
    `The sender's claimed identity does not match their actual digital provenance. ${evidence}. Legitimate organizations send from verified domains that match their brand.`,
  'Information-Intent': (evidence: string) =>
    `The message demands action but provides insufficient explanation. ${evidence}. Legitimate communications explain WHY action is needed before asking you to act.`,
  'Urgency-Authority': (evidence: string) =>
    `The message creates urgency but lacks genuine authority. ${evidence}. Real authorities do not pressure via informal channels with artificial deadlines.`,
  'Specificity-Personalization': (evidence: string) =>
    `The message makes specific claims but lacks personalization. ${evidence}. If an organization truly has your account info, they would address you by name.`,
  'Channel-Formality': (evidence: string) =>
    `The message formality does not match the communication channel. ${evidence}. Official legal/financial notices are not sent via SMS or informal email.`,
  'Reward-Risk': (evidence: string) =>
    `The promised reward is wildly disproportionate to what is asked. ${evidence}. If something sounds too good to be true, it almost certainly is.`,
};

// ---------------------------------------------------------------------------
// Helper: compute identity provenance score
// ---------------------------------------------------------------------------
function measureIdentityProvenance(input: AnalysisInput): { score: number; evidence: string } {
  let violationScore = 0;
  const evidenceParts: string[] = [];

  const from = input.emailHeaders?.['from'] || input.emailHeaders?.['From'] || '';
  const allText = [input.text, input.emailBody, input.smsBody, input.screenshotOcrText]
    .filter(Boolean)
    .join(' ');

  // Check: brand mentioned in text but sender domain doesn't match
  for (const [brand, domains] of Object.entries(BRAND_DOMAINS)) {
    const brandRegex = new RegExp(`\\b${brand}\\b`, 'i');
    if (brandRegex.test(allText)) {
      // Check if sender domain matches
      const emailMatch = from.match(/@([a-zA-Z0-9.-]+)/);
      if (emailMatch) {
        const senderDomain = emailMatch[1].toLowerCase();
        const isLegit = domains.some(d => senderDomain === d || senderDomain.endsWith('.' + d));
        if (!isLegit) {
          violationScore += 0.8;
          evidenceParts.push(`Claims to be ${brand} but sender domain is ${senderDomain}`);
        }
      }

      // Check URL in text
      if (input.url) {
        try {
          const hostname = new URL(input.url.startsWith('http') ? input.url : `https://${input.url}`).hostname.toLowerCase();
          const urlIsLegit = domains.some(d => hostname === d || hostname.endsWith('.' + d));
          if (!urlIsLegit && hostname.includes(brand)) {
            violationScore += 0.7;
            evidenceParts.push(`URL ${hostname} mimics ${brand} but is not a legitimate domain`);
          }
        } catch { /* invalid URL */ }
      }
    }
  }

  // Check: generic sender claiming to be specific entity
  if (/\b(support|security|billing|admin|service)\b/i.test(from)) {
    const emailMatch = from.match(/@([a-zA-Z0-9.-]+)/);
    if (emailMatch) {
      const domain = emailMatch[1].toLowerCase();
      const freeProviders = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'mail.com', 'protonmail.com'];
      if (freeProviders.includes(domain)) {
        violationScore += 0.7;
        evidenceParts.push(`Sender claims support/security role but uses free email provider ${domain}`);
      }
    }
  }

  // WHOIS provenance check
  if (input.whoisData) {
    const created = new Date(input.whoisData.creationDate);
    const ageDays = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24);
    if (ageDays < 30 && allText.length > 50) {
      violationScore += 0.5;
      evidenceParts.push(`Domain only ${Math.floor(ageDays)} days old but presents as established entity`);
    }
  }

  return {
    score: Math.min(1, violationScore),
    evidence: evidenceParts.join('; ') || 'No identity-provenance violations detected',
  };
}

// ---------------------------------------------------------------------------
// Helper: compute information-intent balance
// ---------------------------------------------------------------------------
function measureInformationIntent(input: AnalysisInput): { score: number; evidence: string } {
  const allText = [input.text, input.emailBody, input.smsBody, input.screenshotOcrText]
    .filter(Boolean)
    .join(' ');

  if (!allText || allText.length < 10) return { score: 0, evidence: 'Insufficient text to analyze' };

  const sentences = allText.split(/[.!?]+/).filter(s => s.trim().length > 5);
  let violationScore = 0;
  const evidenceParts: string[] = [];

  // Measure informational content vs demands
  const informationalPatterns = /\b(because|since|due to|as a result|therefore|the reason|we noticed|our records show|according to)\b/gi;
  const demandPatterns = /\b(click|call|send|wire|transfer|pay|enter|provide|submit|verify|confirm|update|reply|respond)\b/gi;

  const infoMatches = (allText.match(informationalPatterns) || []).length;
  const demandMatches = (allText.match(demandPatterns) || []).length;

  // High demands with low information = violation
  if (demandMatches > 2 && infoMatches === 0) {
    violationScore += 0.8;
    evidenceParts.push(`${demandMatches} action demands with zero explanatory information`);
  } else if (demandMatches > 0 && infoMatches > 0) {
    const ratio = demandMatches / (infoMatches + demandMatches);
    if (ratio > 0.75) {
      violationScore += ratio * 0.6;
      evidenceParts.push(`Demand-to-information ratio is ${(ratio * 100).toFixed(0)}%`);
    }
  }

  // Check for vague claims followed by specific demands
  const vagueClaimPatterns = /\b(there (is|was|has been) (a|an)? ?(problem|issue|error|suspicious|unusual))\b/i;
  const specificDemandPatterns = /\b(click (here|this link|below)|call \d{3}|send \$|transfer|pay \$)\b/i;
  if (vagueClaimPatterns.test(allText) && specificDemandPatterns.test(allText)) {
    violationScore += 0.6;
    evidenceParts.push('Vague problem claim paired with specific action demand');
  }

  // Very short message with a link (low info, high intent)
  if (sentences.length <= 2 && /https?:\/\//.test(allText)) {
    violationScore += 0.5;
    evidenceParts.push('Very short message with embedded link — low info, high action intent');
  }

  return {
    score: Math.min(1, violationScore),
    evidence: evidenceParts.join('; ') || 'Information-intent balance appears normal',
  };
}

// ---------------------------------------------------------------------------
// Helper: compute urgency-authority match
// ---------------------------------------------------------------------------
function measureUrgencyAuthority(input: AnalysisInput): { score: number; evidence: string } {
  const allText = [input.text, input.emailBody, input.smsBody, input.screenshotOcrText]
    .filter(Boolean)
    .join(' ');

  if (!allText) return { score: 0, evidence: 'No text to analyze' };

  let violationScore = 0;
  const evidenceParts: string[] = [];

  // Measure urgency level
  let urgencyLevel = 0;
  for (const { pattern, weight } of URGENCY_PATTERNS) {
    if (pattern.test(allText)) {
      urgencyLevel = Math.max(urgencyLevel, weight);
    }
  }

  // Measure authority level
  let authorityLevel = 0;

  // High authority indicators
  const highAuthority = /\b(federal|government|irs|fbi|cia|doj|department of|court order|judge|magistrate|ssa|social security administration)\b/i;
  const medAuthority = /\b(bank|financial institution|credit union|insurance|legal department|compliance|hr department)\b/i;
  const lowAuthority = /\b(customer service|support team|helpdesk|representative|agent)\b/i;

  if (highAuthority.test(allText)) authorityLevel = 0.9;
  else if (medAuthority.test(allText)) authorityLevel = 0.6;
  else if (lowAuthority.test(allText)) authorityLevel = 0.3;

  // Check the sender domain for authority
  const from = input.emailHeaders?.['from'] || '';
  if (from.includes('.gov')) authorityLevel = Math.max(authorityLevel, 0.9);
  else if (from.includes('.edu')) authorityLevel = Math.max(authorityLevel, 0.5);

  // Violation: high urgency claims but low actual authority
  if (urgencyLevel > 0.7 && authorityLevel < 0.3) {
    violationScore += 0.8;
    evidenceParts.push(`High urgency (${urgencyLevel.toFixed(2)}) from low-authority sender (${authorityLevel.toFixed(2)})`);
  } else if (urgencyLevel > 0.5 && authorityLevel < 0.5) {
    violationScore += 0.5;
    evidenceParts.push(`Moderate urgency-authority mismatch (urgency=${urgencyLevel.toFixed(2)}, authority=${authorityLevel.toFixed(2)})`);
  }

  // Violation: claiming government authority from non-gov domain
  if (highAuthority.test(allText)) {
    const emailMatch = from.match(/@([a-zA-Z0-9.-]+)/);
    if (emailMatch && !emailMatch[1].endsWith('.gov') && !emailMatch[1].endsWith('.mil')) {
      violationScore += 0.7;
      evidenceParts.push(`Claims government authority but sender domain is ${emailMatch[1]}`);
    }
  }

  // Violation: threatening legal action via SMS/informal channel
  if (input.smsBody && THREAT_PATTERNS.some(({ pattern }) => pattern.test(input.smsBody!))) {
    violationScore += 0.7;
    evidenceParts.push('Legal/enforcement threats sent via SMS — unusual for legitimate agencies');
  }

  return {
    score: Math.min(1, violationScore),
    evidence: evidenceParts.join('; ') || 'Urgency-authority balance appears normal',
  };
}

// ---------------------------------------------------------------------------
// Helper: compute specificity-personalization match
// ---------------------------------------------------------------------------
function measureSpecificityPersonalization(input: AnalysisInput): { score: number; evidence: string } {
  const allText = [input.text, input.emailBody, input.smsBody, input.screenshotOcrText]
    .filter(Boolean)
    .join(' ');

  if (!allText) return { score: 0, evidence: 'No text to analyze' };

  let violationScore = 0;
  const evidenceParts: string[] = [];

  // Measure specificity of claims
  let claimSpecificity = 0;
  const specificClaimPatterns = [
    { pattern: /\$[\d,.]+/, label: 'specific dollar amount' },
    { pattern: /\b(order|transaction|invoice|case|reference)\s*#?\s*\d+/i, label: 'specific reference number' },
    { pattern: /\b(january|february|march|april|may|june|july|august|september|october|november|december)\s+\d{1,2}/i, label: 'specific date' },
    { pattern: /\b\d{1,2}\/\d{1,2}\/\d{2,4}\b/, label: 'specific date format' },
    { pattern: /\byour (account|order|package|shipment|payment) (number|id|#)/i, label: 'account/order reference' },
  ];

  const foundClaims: string[] = [];
  for (const { pattern, label } of specificClaimPatterns) {
    if (pattern.test(allText)) {
      claimSpecificity += 0.25;
      foundClaims.push(label);
    }
  }

  // Measure personalization
  let personalization = 0;
  const personalPatterns = [
    { pattern: /\bDear\s+[A-Z][a-z]+\b/, label: 'uses name' },
    { pattern: /\b(Mr\.|Mrs\.|Ms\.|Dr\.)\s+[A-Z][a-z]+/i, label: 'uses title+name' },
    { pattern: /\b\d{4}\s*[-*]\s*\d{4}\b/, label: 'partial account number' },
  ];

  // Generic greeting = lack of personalization
  const genericGreeting = /\b(dear\s+(customer|user|member|sir|madam|valued\s+customer|account\s*holder|client))\b/i;
  if (genericGreeting.test(allText)) {
    personalization -= 0.3;
    evidenceParts.push('Uses generic greeting instead of personal name');
  }

  for (const { pattern, label } of personalPatterns) {
    if (pattern.test(allText)) {
      personalization += 0.3;
    }
  }

  // Violation: specific claims (amounts, reference numbers) but no personalization
  if (claimSpecificity > 0.3 && personalization < 0) {
    violationScore += 0.7;
    evidenceParts.push(`Makes specific claims (${foundClaims.join(', ')}) but uses generic/no personalization`);
  } else if (claimSpecificity > 0.2 && personalization <= 0) {
    violationScore += 0.4;
    evidenceParts.push(`Some specific claims without matching personalization`);
  }

  // Violation: asks for personal info but provides none (they should already have it)
  const asksForInfo = /\b(verify|confirm|provide|enter|update)\s+(your\s+)?(ssn|social security|account number|password|pin|date of birth|mother'?s maiden)\b/i;
  if (asksForInfo.test(allText) && personalization <= 0) {
    violationScore += 0.8;
    evidenceParts.push('Asks for sensitive personal information but shows no prior knowledge of recipient');
  }

  return {
    score: Math.min(1, violationScore),
    evidence: evidenceParts.join('; ') || 'Specificity-personalization balance appears normal',
  };
}

// ---------------------------------------------------------------------------
// Helper: compute channel-formality match
// ---------------------------------------------------------------------------
function measureChannelFormality(input: AnalysisInput): { score: number; evidence: string } {
  let violationScore = 0;
  const evidenceParts: string[] = [];

  const allText = [input.text, input.emailBody, input.smsBody, input.screenshotOcrText]
    .filter(Boolean)
    .join(' ');

  if (!allText) return { score: 0, evidence: 'No text to analyze' };

  // Determine channel
  let channel: 'sms' | 'email' | 'web' | 'unknown' = 'unknown';
  if (input.smsBody) channel = 'sms';
  else if (input.emailHeaders) channel = 'email';
  else if (input.url) channel = 'web';

  // Measure formality of content
  const formalIndicators = /\b(dear|pursuant|hereby|sincerely|regards|respectfully|official|notice|notification|department|compliance|regulation)\b/gi;
  const informalIndicators = /\b(hey|hi there|yo |sup |lol|omg|u |ur |gonna|wanna|gotta|asap|pls|plz|thx|tx|k |ok )\b/gi;

  const formalCount = (allText.match(formalIndicators) || []).length;
  const informalCount = (allText.match(informalIndicators) || []).length;

  // SMS channel with very formal content = suspicious
  if (channel === 'sms') {
    if (formalCount > 2) {
      violationScore += 0.6;
      evidenceParts.push('Highly formal language in SMS message — legitimate entities rarely send formal notices via SMS');
    }
    // Government/legal claims via SMS
    if (/\b(irs|government|federal|court|warrant|subpoena|legal action)\b/i.test(allText)) {
      violationScore += 0.8;
      evidenceParts.push('Government/legal claims via SMS — agencies do not send legal notices by text');
    }
    // Financial demands via SMS
    if (/\b(wire|transfer|pay|send money|gift card|bitcoin)\b/i.test(allText)) {
      violationScore += 0.6;
      evidenceParts.push('Financial demands via SMS — unusual for legitimate entities');
    }
  }

  // Email with very informal language but claiming to be a business
  if (channel === 'email' && informalCount > formalCount && formalCount > 0) {
    violationScore += 0.4;
    evidenceParts.push('Mixed formal/informal register in email — inconsistent with professional communication');
  }

  // Message length vs channel
  if (channel === 'sms' && allText.length > 500) {
    violationScore += 0.3;
    evidenceParts.push('Unusually long SMS message');
  }

  return {
    score: Math.min(1, violationScore),
    evidence: evidenceParts.join('; ') || 'Channel-formality match appears normal',
  };
}

// ---------------------------------------------------------------------------
// Helper: compute reward-risk conservation
// The promised reward must be proportional to the risk/effort asked
// ---------------------------------------------------------------------------
function measureRewardRisk(input: AnalysisInput): { score: number; evidence: string } {
  const allText = [input.text, input.emailBody, input.smsBody, input.screenshotOcrText]
    .filter(Boolean)
    .join(' ');

  if (!allText || allText.length < 10) return { score: 0, evidence: 'Insufficient text to analyze' };

  let violationScore = 0;
  const evidenceParts: string[] = [];

  // Measure reward magnitude
  let rewardLevel = 0;
  const rewardPatterns = [
    { pattern: /\$\s*[\d,]+\s*(million|billion)/i, level: 1.0, label: 'million/billion dollar amount' },
    { pattern: /\$\s*[\d,]*\d{4,}/i, level: 0.7, label: 'large dollar amount (4+ digits)' },
    { pattern: /\b(lottery|jackpot|grand\s*prize|inheritance|fortune)\b/i, level: 0.9, label: 'windfall claim' },
    { pattern: /\b(guaranteed\s*(income|return|profit)|1000%|10x|double\s*your)\b/i, level: 0.95, label: 'guaranteed multiplied returns' },
    { pattern: /\b(free\s*(money|gift|prize|reward|vacation|trip|iphone|macbook))\b/i, level: 0.7, label: 'free high-value item' },
    { pattern: /\b(earn\s*\$\d+\s*(per|a|each)\s*(day|hour|week))\b/i, level: 0.8, label: 'high earnings claim' },
    { pattern: /\b(you('ve| have)\s*(won|inherited|been\s*(awarded|selected\s*for)))\b/i, level: 0.85, label: 'prize/inheritance award' },
    { pattern: /\b(unlimited\s*(income|earnings?|access|money))\b/i, level: 0.9, label: 'unlimited earnings claim' },
  ];

  for (const { pattern, level, label } of rewardPatterns) {
    if (pattern.test(allText)) {
      rewardLevel = Math.max(rewardLevel, level);
      evidenceParts.push(`Reward: ${label}`);
    }
  }

  // Measure risk/effort asked
  let riskLevel = 0;
  const riskPatterns = [
    { pattern: /\b(click\s*(here|below|this\s*link))\b/i, level: 0.2, label: 'click a link' },
    { pattern: /\b(provide|enter|verify|confirm)\s*(your\s*)?(email|name|address)\b/i, level: 0.3, label: 'provide personal info' },
    { pattern: /\b(ssn|social\s*security|tax\s*id|date\s*of\s*birth|passport)\b/i, level: 0.9, label: 'provide sensitive identity info' },
    { pattern: /\b(credit\s*card|debit\s*card|bank\s*account|routing\s*number|cvv)\b/i, level: 0.9, label: 'provide financial details' },
    { pattern: /\b(wire|transfer|send)\s*(money|\$|funds|payment|bitcoin)\b/i, level: 0.95, label: 'send money' },
    { pattern: /\b(gift\s*card|prepaid|money\s*order|western\s*union)\b/i, level: 0.95, label: 'untraceable payment' },
    { pattern: /\b(download|install)\s*(this|the|our)\s*(app|software|program)\b/i, level: 0.6, label: 'install software' },
    { pattern: /\b(remote\s*access|teamviewer|anydesk|connect\s*to\s*your)\b/i, level: 0.85, label: 'grant remote access' },
    { pattern: /\b(processing\s*fee|advance\s*fee|small\s*fee|shipping\s*fee)\b/i, level: 0.8, label: 'pay upfront fee' },
    { pattern: /\b(seed\s*phrase|private\s*key|wallet\s*password|connect\s*wallet)\b/i, level: 0.95, label: 'provide crypto keys' },
  ];

  for (const { pattern, level, label } of riskPatterns) {
    if (pattern.test(allText)) {
      riskLevel = Math.max(riskLevel, level);
      evidenceParts.push(`Risk: ${label}`);
    }
  }

  // Conservation violation: high reward promised for low/reasonable risk = suspicious
  // The key insight: scams offer disproportionate rewards to get victims to take risks
  if (rewardLevel > 0.6 && riskLevel > 0.3) {
    // Both reward and risk present — check proportionality
    // Huge reward + low explicit risk = "too good to be true" violation
    // Any reward + very high risk = also violation (why would legitimate entity need your SSN for a prize?)
    const disproportion = rewardLevel * 0.6 + riskLevel * 0.4;
    violationScore = Math.min(1, disproportion);
    evidenceParts.push(`Reward-Risk disproportion: reward=${rewardLevel.toFixed(2)}, risk=${riskLevel.toFixed(2)}`);
  } else if (rewardLevel > 0.7 && riskLevel <= 0.3) {
    // High reward, asks for almost nothing — classic bait
    violationScore = rewardLevel * 0.7;
    evidenceParts.push(`Suspiciously high reward (${rewardLevel.toFixed(2)}) with minimal apparent risk — classic bait pattern`);
  }

  return {
    score: Math.min(1, violationScore),
    evidence: evidenceParts.join('; ') || 'Reward-risk balance appears normal',
  };
}

// ---------------------------------------------------------------------------
// Compute the full 6x6 violation tensor
// ---------------------------------------------------------------------------
// The tensor V_ij represents the cross-interaction between law i and law j.
// Diagonal: self-violations (the direct violation score, severity-weighted).
// Off-diagonal V_ij: mutual information based interaction term — measures
// how much knowing law i is violated tells us about law j being violated.
// Uses mutual information approximation instead of geometric mean.
// ---------------------------------------------------------------------------
function computeViolationTensor(lawScores: number[]): number[][] {
  const n = lawScores.length;
  const tensor: number[][] = Array.from({ length: n }, () => Array(n).fill(0));

  for (let i = 0; i < n; i++) {
    for (let j = 0; j < n; j++) {
      if (i === j) {
        // Diagonal: severity-weighted violation score
        tensor[i][j] = lawScores[i] * LAW_SEVERITY_WEIGHTS[i];
      } else {
        // Off-diagonal: mutual information approximation
        // MI(X;Y) approximation using joint vs marginal probabilities
        // When both laws are violated (high scores), the interaction is amplified
        // more than geometric mean would give
        const pi = lawScores[i];
        const pj = lawScores[j];

        if (pi > 0 && pj > 0) {
          // Joint probability estimate (both violated simultaneously)
          const pJoint = pi * pj;
          // Marginal entropy contributions
          const hI = pi > 0 && pi < 1 ? -pi * Math.log2(pi) - (1 - pi) * Math.log2(1 - pi) : 0;
          const hJ = pj > 0 && pj < 1 ? -pj * Math.log2(pj) - (1 - pj) * Math.log2(1 - pj) : 0;

          // Mutual information approximation: higher when both are violated
          // Scales with severity weights of both laws
          const mi = pJoint * (1 + Math.min(hI, hJ));
          const avgSeverityWeight = (LAW_SEVERITY_WEIGHTS[i] + LAW_SEVERITY_WEIGHTS[j]) / 2;
          tensor[i][j] = mi * avgSeverityWeight;
        }
      }
    }
  }

  return tensor;
}

// ---------------------------------------------------------------------------
// Frobenius norm of a matrix
// ---------------------------------------------------------------------------
function frobeniusNorm(matrix: number[][]): number {
  let sumSq = 0;
  for (const row of matrix) {
    for (const val of row) {
      sumSq += val * val;
    }
  }
  return Math.sqrt(sumSq);
}

// ---------------------------------------------------------------------------
// Run Conservation Law analysis
// ---------------------------------------------------------------------------
export function runConservationLaws(input: AnalysisInput): ConservationLayerResult {
  const measurements = [
    measureIdentityProvenance(input),
    measureInformationIntent(input),
    measureUrgencyAuthority(input),
    measureSpecificityPersonalization(input),
    measureChannelFormality(input),
    measureRewardRisk(input),
  ];

  const lawScores = measurements.map(m => m.score);
  const violations: ConservationViolation[] = [];
  const details: string[] = [];

  for (let i = 0; i < LAW_NAMES.length; i++) {
    const severityWeight = LAW_SEVERITY_WEIGHTS[i];
    const weightedSeverity = lawScores[i] * severityWeight;
    details.push(`Law ${i} (${LAW_NAMES[i]}): violation=${lawScores[i].toFixed(3)}, weight=${severityWeight}, weighted=${weightedSeverity.toFixed(3)} — ${measurements[i].evidence}`);
    if (lawScores[i] > 0.1) {
      // Generate explanatory text
      const explainFn = LAW_EXPLANATIONS[LAW_NAMES[i]];
      const explanation = explainFn ? explainFn(measurements[i].evidence) : measurements[i].evidence;

      violations.push({
        lawIndex: i,
        lawName: LAW_NAMES[i],
        description: explanation,
        severity: Math.min(1, weightedSeverity),
        evidence: measurements[i].evidence,
      });
    }
  }

  // Build the 6x6 violation tensor (with severity weights and mutual information)
  const tensor = computeViolationTensor(lawScores);
  const norm = frobeniusNorm(tensor);

  // The max possible Frobenius norm for a 6x6 severity-weighted matrix
  // Approximate max: sqrt(sum of (weight_i^2) + sum of cross-terms) ~ sqrt(6 * max_weight^2 * 6) ~ 6 * max_weight
  const maxNorm = Math.sqrt(LAW_SEVERITY_WEIGHTS.reduce((sum, w) => sum + w * w * LAW_NAMES.length, 0));
  const normalizedScore = Math.min(100, (norm / maxNorm) * 100);

  details.push(`Violation tensor Frobenius norm: ${norm.toFixed(4)} (max: ${maxNorm.toFixed(4)})`);
  details.push(`Normalized score: ${normalizedScore.toFixed(2)}/100`);
  details.push(`Laws violated: ${violations.length}/${LAW_NAMES.length}`);

  return {
    score: Math.round(normalizedScore * 100) / 100,
    violationTensor: tensor,
    frobeniusNorm: Math.round(norm * 10000) / 10000,
    violations,
    details,
  };
}
