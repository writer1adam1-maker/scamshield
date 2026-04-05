// ============================================================================
// VERIDICT Layer 1: Fisher Information Cascade
// Evaluates cheap signals first, expensive later, with early stopping.
// ============================================================================

import {
  Signal,
  SignalType,
  FisherLayerResult,
  AnalysisInput,
} from './types';
import {
  extractUrlSignals,
  extractTextSignals,
  extractEmailSignals,
  extractDomainSignals,
  extractSslSignals,
  shannonEntropy,
} from './signal-extractors';
import { scanPatternMaxWeights } from './pattern-engine';

// ---------------------------------------------------------------------------
// Adaptive thresholds based on input type
// URLs need less info to decide (they are either scam or not),
// while plain text has more ambiguity and needs more evidence.
// ---------------------------------------------------------------------------
function getAdaptiveThreshold(input: AnalysisInput): number {
  if (input.url && !input.text && !input.emailBody && !input.smsBody) {
    return 50; // URL-only: lower threshold, less ambiguity
  }
  if (input.smsBody && !input.emailBody) {
    return 60; // SMS: slightly lower, shorter messages carry more weight per signal
  }
  if (input.emailHeaders && input.emailBody) {
    return 75; // Email: slightly lower than default due to rich header data
  }

  // Per-category calibration: high-signal scam types need less evidence
  const allText = [input.text, input.emailBody, input.smsBody, input.screenshotOcrText]
    .filter(Boolean).join(' ').toLowerCase();

  if (allText.length > 0) {
    // Crypto investment scams: highly distinctive vocabulary, lower threshold
    if (/\b(bitcoin|btc|crypto|ethereum|nft|defi|web3)\b/.test(allText) &&
        /\b(invest|profit|return|gain|earn|multiply|double)\b/.test(allText)) {
      return 55;
    }
    // Government impersonation: arrest/warrant language is very specific
    if (/\b(irs|social\s*security|ssa|warrant|arrest|badge\s*number|federal\s*agent)\b/.test(allText)) {
      return 55;
    }
    // Romance/grooming scams: love-bombing in early messages
    if (/\b(military|deployed|widow|inheritance|love\s*you|darling|sweetheart)\b/.test(allText) &&
        /\b(send\s*money|wire|bitcoin|gift\s*card|emergency)\b/.test(allText)) {
      return 55;
    }
    // Tech support popup: very specific pattern
    if (/\b(microsoft|windows|apple)\b/.test(allText) &&
        /\b(virus|malware|infected|locked|call\s*(us|now|immediately))\b/.test(allText)) {
      return 58;
    }
    // Pig-butchering / investment platform
    if (/\b(trading\s*platform|liquidity\s*pool|withdrawal\s*fee|unlock\s*funds|tax\s*clearance)\b/.test(allText)) {
      return 52;
    }
  }

  return 80; // Default for plain text
}

// ---------------------------------------------------------------------------
// Signal correlation detection
// When two signals share the same rawData group/check, they are correlated.
// The second signal's Fisher info is discounted to avoid double-counting.
// ---------------------------------------------------------------------------
function computeCorrelationDiscount(newSignal: Signal, existingSignals: Signal[]): number {
  if (existingSignals.length === 0) return 1.0;

  let maxSameGroupCorrelation = 0;
  const existingGroups = new Set<string>();

  for (const existing of existingSignals) {
    const existingGroup = existing.rawData?.group as string | undefined;
    if (existingGroup) existingGroups.add(existingGroup);

    // Only discount signals from the SAME group + same check (true duplicates)
    const newGroup = newSignal.rawData?.group as string | undefined;
    const existingCheck = existing.rawData?.check as string | undefined;
    const newCheck = newSignal.rawData?.check as string | undefined;

    if (existingCheck && newCheck && existingCheck === newCheck) {
      // Same exact check = strong duplicate discount
      maxSameGroupCorrelation = Math.max(maxSameGroupCorrelation, 0.7);
    } else if (existingGroup && newGroup && existingGroup === newGroup && existing.type === newSignal.type) {
      // Same group + same type = moderate discount (similar signals)
      maxSameGroupCorrelation = Math.max(maxSameGroupCorrelation, 0.4);
    }
  }

  // Discount same-group duplicates (prevents inflated scores from redundant signals)
  const duplicateDiscount = Math.max(0.3, 1.0 - maxSameGroupCorrelation);

  // Cross-group synergy bonus: different signal groups reinforcing each other
  // is evidence of a coordinated scam, not a reason to reduce confidence
  const newGroup = newSignal.rawData?.group as string | undefined;
  const uniqueGroups = new Set(existingGroups);
  if (newGroup) uniqueGroups.add(newGroup);
  const crossGroupBonus = uniqueGroups.size >= 3 ? 1.0 + (uniqueGroups.size - 2) * 0.1 : 1.0;

  return duplicateDiscount * Math.min(1.5, crossGroupBonus);
}

// ---------------------------------------------------------------------------
// Signal surprise bonus
// If a signal is unexpected given the context, it carries more Fisher info.
// Example: crypto wallet in a "bank" email is surprising and thus more informative.
// ---------------------------------------------------------------------------
function computeSurpriseBonus(signal: Signal, allSignals: Signal[]): number {
  const signalGroup = signal.rawData?.group as string | undefined;
  if (!signalGroup) return 1.0;

  // Build a map of what groups are dominant
  const groupCounts: Record<string, number> = {};
  for (const s of allSignals) {
    const g = s.rawData?.group as string | undefined;
    if (g) groupCounts[g] = (groupCounts[g] || 0) + 1;
  }

  // Find the dominant group
  let dominantGroup = '';
  let maxCount = 0;
  for (const [g, c] of Object.entries(groupCounts)) {
    if (c > maxCount) { maxCount = c; dominantGroup = g; }
  }

  if (!dominantGroup || dominantGroup === signalGroup) return 1.0;

  // Cross-context surprise mappings
  const surpriseMap: Record<string, string[]> = {
    'financial': ['social_media', 'qr_code'],
    'threat': ['too_good_to_be_true', 'social_media'],
    'urgency': ['too_good_to_be_true'],
    'too_good_to_be_true': ['threat', 'impersonation'],
    'impersonation': ['too_good_to_be_true', 'qr_code'],
  };

  const surprisingGroups = surpriseMap[dominantGroup] || [];
  if (surprisingGroups.includes(signalGroup)) {
    return 1.5; // 50% bonus for surprising cross-context signals
  }

  // Any non-dominant group gets a small surprise bonus
  return 1.15;
}

// ---------------------------------------------------------------------------
// Improved scoring sigmoid — more sensitive in the 40-70 range
// Uses a modified logistic function with steeper slope in the uncertain zone
// ---------------------------------------------------------------------------
function calibratedSigmoid(rawScore: number): number {
  // Two-piece sigmoid: steeper in the 0.4-0.7 range
  // f(x) = 1 / (1 + exp(-k * (x - midpoint)))
  // We use different k values for different ranges
  if (rawScore <= 0) return 0;
  if (rawScore >= 1) return 1;

  // Steeper sigmoid centered at 0.5 for the uncertain zone
  const k = rawScore >= 0.35 && rawScore <= 0.75 ? 12 : 8;
  const midpoint = 0.5;
  const sigmoid = 1 / (1 + Math.exp(-k * (rawScore - midpoint)));

  // Normalize so sigmoid(0) ~ 0 and sigmoid(1) ~ 1
  const low = 1 / (1 + Math.exp(-k * (0 - midpoint)));
  const high = 1 / (1 + Math.exp(-k * (1 - midpoint)));
  return (sigmoid - low) / (high - low);
}

// ---------------------------------------------------------------------------
// Fisher information contribution for a signal
// ---------------------------------------------------------------------------
// The Fisher information I(θ) measures how much a signal tells us about θ
// (the true probability that this is a scam). For a Bernoulli observation
// with estimated probability p:  I = 1 / (p * (1 - p))
// We scale by signal confidence to weight more reliable signals higher.
function fisherInformation(signalConfidence: number): number {
  // Clamp to avoid division by zero at 0 or 1
  const p = Math.max(0.01, Math.min(0.99, signalConfidence));
  return 1 / (p * (1 - p));
}

// ---------------------------------------------------------------------------
// Decision threshold for early stopping
// When accumulated Fisher information exceeds this, we can stop evaluating
// because we have enough statistical evidence to make a decision.
// Based on the Cramér-Rao bound: Var(θ̂) >= 1/I(θ)
// Threshold chosen so Var(θ̂) < 0.01 → I(θ) > 100
// ---------------------------------------------------------------------------
// Base threshold — will be overridden by adaptive threshold per input type
const FISHER_DECISION_THRESHOLD = 80;

// ---------------------------------------------------------------------------
// Signal stage definitions (ordered by computational cost)
// ---------------------------------------------------------------------------
interface SignalStage {
  name: string;
  cost: number; // 0 = free, 10 = expensive
  extract: (input: AnalysisInput) => Signal[];
}

function buildStages(): SignalStage[] {
  return [
    // Stage 0: URL pattern checks (free, regex only)
    {
      name: 'url_pattern',
      cost: 0,
      extract: (input: AnalysisInput): Signal[] => {
        const signals: Signal[] = [];
        if (input.url) {
          signals.push(...extractUrlSignals(input.url));
        }
        // Also extract URLs from text bodies
        const textBodies = [input.text, input.emailBody, input.smsBody, input.screenshotOcrText].filter(Boolean) as string[];
        for (const body of textBodies) {
          const urlMatches = body.match(/https?:\/\/[^\s<>"{}|\\^`\[\]]+/gi) || [];
          for (const url of urlMatches) {
            signals.push(...extractUrlSignals(url));
          }
        }
        return signals;
      },
    },

    // Stage 1: Basic text pattern analysis (cheap, regex only)
    // Also bridges in high-weight matches from the Aho-Corasick pattern engine
    {
      name: 'text_pattern',
      cost: 1,
      extract: (input: AnalysisInput): Signal[] => {
        const signals: Signal[] = [];
        const textBodies = [input.text, input.emailBody, input.smsBody, input.screenshotOcrText].filter(Boolean) as string[];
        for (const body of textBodies) {
          signals.push(...extractTextSignals(body));

          // Pattern-engine bridge: convert high-weight Aho-Corasick matches → Fisher signals
          // Weight scale: 6-20 → confidence: 0.30-0.95
          const maxWeights = scanPatternMaxWeights(body);
          for (const [group, maxWeight] of Object.entries(maxWeights)) {
            if (maxWeight < 14) continue; // only high-signal matches (14+)
            const confidence = 0.30 + (maxWeight - 6) / (20 - 6) * 0.65;
            signals.push({
              type: SignalType.TEXT,
              value: group,
              confidence,
              rawData: { group, check: 'pattern_engine_weight', weight: maxWeight },
              label: `[pattern_engine] ${group}: weight ${maxWeight}`,
              cost: 1,
            });
          }
        }
        return signals;
      },
    },

    // Stage 2: Email header analysis (cheap if headers available)
    {
      name: 'email_header',
      cost: 2,
      extract: (input: AnalysisInput): Signal[] => {
        if (input.emailHeaders && input.emailBody) {
          return extractEmailSignals(input.emailHeaders, input.emailBody);
        }
        return [];
      },
    },

    // Stage 3: SSL certificate analysis (medium cost, requires cert data)
    {
      name: 'ssl_analysis',
      cost: 5,
      extract: (input: AnalysisInput): Signal[] => {
        if (input.sslData) {
          return extractSslSignals(input.sslData);
        }
        return [];
      },
    },

    // Stage 4: WHOIS / domain age analysis (expensive, external lookup)
    {
      name: 'domain_whois',
      cost: 7,
      extract: (input: AnalysisInput): Signal[] => {
        if (input.whoisData) {
          return extractDomainSignals(input.whoisData);
        }
        return [];
      },
    },

    // Stage 5: Structural / semantic deep analysis (most expensive)
    {
      name: 'semantic_deep',
      cost: 9,
      extract: (input: AnalysisInput): Signal[] => {
        const signals: Signal[] = [];
        const allText = [input.text, input.emailBody, input.smsBody, input.screenshotOcrText]
          .filter(Boolean)
          .join(' ');

        if (!allText || allText.length < 10) return signals;

        // Deep structural analysis: sentence-level patterns
        const sentences = allText.split(/[.!?]+/).filter(s => s.trim().length > 5);

        // Check for command-heavy language (imperatives)
        const imperativePatterns = /^(click|call|send|wire|transfer|deposit|pay|enter|provide|submit|reply|respond|download|install|open|visit|go to|tap|press)\b/i;
        let imperativeCount = 0;
        for (const sentence of sentences) {
          if (imperativePatterns.test(sentence.trim())) {
            imperativeCount++;
          }
        }
        const imperativeRatio = sentences.length > 0 ? imperativeCount / sentences.length : 0;
        if (imperativeRatio > 0.3 && imperativeCount >= 2) {
          signals.push({
            type: SignalType.TEXT,
            value: `${imperativeCount}/${sentences.length} sentences are commands`,
            confidence: 0.7,
            rawData: { check: 'imperative_heavy', imperativeRatio, imperativeCount },
            label: `High ratio of imperative/command sentences (${(imperativeRatio * 100).toFixed(0)}%)`,
            cost: 9,
          });
        }

        // Check for information asymmetry: lots of demands, little information
        const questionCount = (allText.match(/\?/g) || []).length;
        const demandWords = (allText.match(/\b(must|need to|required|mandatory|have to|should|shall)\b/gi) || []).length;
        if (demandWords > 3 && questionCount === 0 && sentences.length > 3) {
          signals.push({
            type: SignalType.TEXT,
            value: `${demandWords} demands, 0 questions`,
            confidence: 0.6,
            rawData: { check: 'information_asymmetry', demandWords, questionCount },
            label: 'One-sided communication: many demands, no information exchange',
            cost: 9,
          });
        }

        // Check for mixed register (formal + informal / poor grammar mixed with legal language)
        const formalPhrases = (allText.match(/\b(pursuant|hereby|hereunder|forthwith|whereas|therein|aforementioned|notwithstanding)\b/gi) || []).length;
        const informalPhrases = (allText.match(/\b(gonna|wanna|gotta|u |ur |pls|plz|asap|lol|omg|btw)\b/gi) || []).length;
        if (formalPhrases > 0 && informalPhrases > 0) {
          signals.push({
            type: SignalType.TEXT,
            value: `${formalPhrases} formal + ${informalPhrases} informal`,
            confidence: 0.55,
            rawData: { check: 'mixed_register', formalPhrases, informalPhrases },
            label: 'Mixed language register — formal legal language mixed with informal speech',
            cost: 9,
          });
        }

        // Entropy of the full text (very low entropy = template text)
        const textEntropy = shannonEntropy(allText);
        if (textEntropy < 3.0 && allText.length > 100) {
          signals.push({
            type: SignalType.TEXT,
            value: `entropy: ${textEntropy.toFixed(2)}`,
            confidence: 0.5,
            rawData: { check: 'low_text_entropy', textEntropy },
            label: `Low text entropy (${textEntropy.toFixed(2)}) suggests templated/repetitive content`,
            cost: 9,
          });
        }

        return signals;
      },
    },
  ];
}

// ---------------------------------------------------------------------------
// Run the Fisher Information Cascade
// ---------------------------------------------------------------------------
export function runFisherCascade(input: AnalysisInput): FisherLayerResult {
  const stages = buildStages();
  const evaluatedSignals: Signal[] = [];
  const details: string[] = [];
  let accumulatedFisher = 0;
  let earlyStopTriggered = false;
  let weightedScoreSum = 0;
  let weightSum = 0;

  // Use adaptive threshold based on input type
  const adaptiveThreshold = getAdaptiveThreshold(input);
  details.push(`Adaptive Fisher threshold: ${adaptiveThreshold} (input type: ${input.url ? 'URL' : input.smsBody ? 'SMS' : input.emailHeaders ? 'Email' : 'Text'})`);

  for (const stage of stages) {
    const stageSignals = stage.extract(input);

    if (stageSignals.length > 0) {
      evaluatedSignals.push(...stageSignals);
      details.push(`Stage "${stage.name}" (cost=${stage.cost}): found ${stageSignals.length} signal(s)`);

      for (const signal of stageSignals) {
        // Apply correlation discount for correlated signals
        const correlationDiscount = computeCorrelationDiscount(signal, evaluatedSignals.slice(0, -stageSignals.length));

        // Apply surprise bonus for unexpected cross-context signals
        const surpriseBonus = computeSurpriseBonus(signal, evaluatedSignals);

        const baseFi = fisherInformation(signal.confidence);
        const adjustedFi = baseFi * correlationDiscount * surpriseBonus;
        accumulatedFisher += adjustedFi;

        // Weighted contribution to score: Fisher information as weight
        // weight = FI (not FI*conf — that would double-count confidence)
        const weight = adjustedFi;
        weightedScoreSum += signal.confidence * weight;
        weightSum += weight;

        const modifiers = [];
        if (correlationDiscount < 1.0) modifiers.push(`corr_disc=${correlationDiscount.toFixed(2)}`);
        if (surpriseBonus > 1.0) modifiers.push(`surprise=${surpriseBonus.toFixed(2)}`);
        const modifierStr = modifiers.length > 0 ? `, ${modifiers.join(', ')}` : '';

        details.push(`  - ${signal.label} (confidence=${signal.confidence.toFixed(2)}, FI=${baseFi.toFixed(2)}→${adjustedFi.toFixed(2)}${modifierStr}, cumulative FI=${accumulatedFisher.toFixed(2)})`);
      }
    } else {
      details.push(`Stage "${stage.name}" (cost=${stage.cost}): no signals`);
    }

    // Early stopping check with adaptive threshold
    if (accumulatedFisher >= adaptiveThreshold) {
      earlyStopTriggered = true;
      details.push(`Early stop triggered: accumulated Fisher info (${accumulatedFisher.toFixed(2)}) >= adaptive threshold (${adaptiveThreshold})`);
      break;
    }
  }

  // Compute final score (0-100) using calibrated sigmoid
  let score = 0;
  if (weightSum > 0) {
    // Fisher-weighted average of signal confidences
    const weightedAvg = weightedScoreSum / weightSum;
    // Apply calibrated sigmoid for better sensitivity in the 40-70 range
    // No signalBoost multiplier — FI accumulation already encodes evidence strength
    score = Math.min(100, calibratedSigmoid(weightedAvg) * 100);

    details.push(`Scoring: weightedAvg=${weightedAvg.toFixed(4)}, calibrated=${score.toFixed(2)}`);
  }

  return {
    score: Math.round(score * 100) / 100,
    signalsEvaluated: evaluatedSignals,
    accumulatedFisherInfo: Math.round(accumulatedFisher * 100) / 100,
    earlyStopTriggered,
    details,
  };
}
