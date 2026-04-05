// ============================================================================
// VERIDICT Engine — Main Orchestrator
// Runs all 4 layers, combines scores, classifies threats, returns results.
// ============================================================================

import {
  AnalysisInput,
  VERIDICTResult,
  ThreatCategory,
  ThreatLevel,
  EvidenceItem,
  ConfidenceInterval,
  LayerScores,
  ThreatSeverity,
  ThreatSeverityInfo,
  MetaAnalysisResult,
  KnownScamTemplate,
} from './types';
import { runFisherCascade } from './fisher-cascade';
import { runConservationLaws } from './conservation-laws';
import { runCascadeBreaker } from './cascade-breaker';
import { runImmuneRepertoire } from './immune-repertoire';
import { deepAnalyzeUrl } from './url-deep-analyzer';
import { findClosestTemplates } from './similarity-engine';
import { assessFinancialRisk } from './risk-scorer';
import { detectMultilingualScam } from './multilingual-detector';
import { analyzePhoneNumbers } from './phone-analyzer';
import { detectLinguisticDeception } from './linguistic-deception';
import { analyzeConversationArc } from './conversation-arc';

// ---------------------------------------------------------------------------
// Input preprocessing: URL normalization, text cleaning, encoding detection
// ---------------------------------------------------------------------------
function preprocessInput(input: AnalysisInput): AnalysisInput {
  const processed = { ...input };

  // URL normalization
  if (processed.url) {
    let url = processed.url.trim();
    // Remove trailing slashes, normalize protocol
    if (!url.match(/^https?:\/\//i) && !url.startsWith('data:')) {
      url = 'https://' + url;
    }
    // Decode unnecessary percent-encoding in safe characters
    try {
      url = decodeURI(url);
    } catch { /* leave as-is if decoding fails */ }
    // Normalize unicode in domain
    try {
      const parsed = new URL(url);
      parsed.hostname = parsed.hostname.toLowerCase();
      url = parsed.toString();
    } catch { /* leave as-is */ }
    processed.url = url;
  }

  // Text cleaning
  const cleanText = (text: string): string => {
    let cleaned = text;
    // Normalize unicode whitespace to regular spaces
    cleaned = cleaned.replace(/[\u00A0\u2000-\u200B\u202F\u205F\u3000\uFEFF]/g, ' ');
    // Remove zero-width characters (often used to evade detection)
    cleaned = cleaned.replace(/[\u200B-\u200D\u2060\uFEFF]/g, '');
    // Normalize quotes
    cleaned = cleaned.replace(/[\u2018\u2019]/g, "'").replace(/[\u201C\u201D]/g, '"');
    // Collapse multiple spaces
    cleaned = cleaned.replace(/\s{2,}/g, ' ');
    return cleaned.trim();
  };

  if (processed.text) processed.text = cleanText(processed.text);
  if (processed.emailBody) processed.emailBody = cleanText(processed.emailBody);
  if (processed.smsBody) processed.smsBody = cleanText(processed.smsBody);
  if (processed.screenshotOcrText) processed.screenshotOcrText = cleanText(processed.screenshotOcrText);

  return processed;
}

// ---------------------------------------------------------------------------
// Known scam templates database for similarity matching
// ---------------------------------------------------------------------------
const KNOWN_SCAM_TEMPLATES: KnownScamTemplate[] = [
  {
    id: 'TPL-001', name: 'Nigerian Prince / 419 Advance Fee',
    category: ThreatCategory.ADVANCE_FEE,
    keywords: ['prince', 'minister', 'inheritance', 'million', 'transfer', 'beneficiary', 'next of kin', 'funds', 'bank', 'percentage'],
    structure: 'introduction -> claim of wealth -> request for help -> promise of reward -> request for fees',
    similarityThreshold: 0.4,
  },
  {
    id: 'TPL-002', name: 'IRS Tax Debt Threat',
    category: ThreatCategory.IRS_GOV,
    keywords: ['irs', 'tax', 'debt', 'warrant', 'arrest', 'agent', 'payment', 'gift card', 'immediately', 'legal action'],
    structure: 'authority claim -> debt notification -> legal threat -> urgent payment demand',
    similarityThreshold: 0.4,
  },
  {
    id: 'TPL-003', name: 'Account Suspension Phishing',
    category: ThreatCategory.PHISHING,
    keywords: ['account', 'suspended', 'verify', 'unusual activity', 'click', 'login', 'confirm', 'update', 'security', 'immediately'],
    structure: 'brand impersonation -> problem claim -> urgency -> verify link',
    similarityThreshold: 0.4,
  },
  {
    id: 'TPL-004', name: 'Tech Support Popup Scam',
    category: ThreatCategory.TECH_SUPPORT,
    keywords: ['virus', 'infected', 'computer', 'locked', 'call', 'microsoft', 'tech support', 'remote access', 'warning', 'firewall'],
    structure: 'scary warning -> technical jargon -> call number -> remote access request',
    similarityThreshold: 0.4,
  },
  {
    id: 'TPL-005', name: 'Package Delivery Fee Scam',
    category: ThreatCategory.PACKAGE_DELIVERY,
    keywords: ['package', 'delivery', 'usps', 'fedex', 'tracking', 'fee', 'reschedule', 'address', 'update', 'customs'],
    structure: 'delivery notification -> problem claim -> small fee request -> link',
    similarityThreshold: 0.4,
  },
  {
    id: 'TPL-006', name: 'Crypto Doubling Scam',
    category: ThreatCategory.CRYPTO,
    keywords: ['bitcoin', 'crypto', 'send', 'double', 'return', 'wallet', 'guaranteed', 'limited time', 'elon', 'giveaway'],
    structure: 'celebrity/platform claim -> send crypto instruction -> promise of return -> urgency',
    similarityThreshold: 0.4,
  },
  {
    id: 'TPL-007', name: 'Romance/Military Deployment Scam',
    category: ThreatCategory.ROMANCE,
    keywords: ['deployed', 'military', 'love', 'send money', 'wire', 'emergency', 'stranded', 'hospital', 'help', 'come home'],
    structure: 'relationship building -> crisis claim -> money request -> promise',
    similarityThreshold: 0.4,
  },
  {
    id: 'TPL-008', name: 'Sextortion Email',
    category: ThreatCategory.GENERIC,
    keywords: ['recorded', 'webcam', 'video', 'adult', 'bitcoin', 'password', 'contacts', 'send', 'expose', 'timer'],
    structure: 'password reveal -> recording claim -> threat of exposure -> bitcoin payment demand -> timer',
    similarityThreshold: 0.4,
  },
  {
    id: 'TPL-009', name: 'Lottery/Prize Winner',
    category: ThreatCategory.ADVANCE_FEE,
    keywords: ['congratulations', 'winner', 'selected', 'lottery', 'prize', 'claim', 'fee', 'processing', 'tax', 'million'],
    structure: 'congratulations -> prize claim -> personal info request -> processing fee',
    similarityThreshold: 0.4,
  },
  {
    id: 'TPL-010', name: 'Fake Charity Disaster Relief',
    category: ThreatCategory.FAKE_CHARITY,
    keywords: ['disaster', 'relief', 'donate', 'victims', 'help', 'charity', 'urgent', 'children', 'suffering', 'wire'],
    structure: 'disaster description -> emotional appeal -> donation request -> untraceable payment',
    similarityThreshold: 0.4,
  },
  {
    id: 'TPL-011', name: 'Rental Scam - Landlord Abroad',
    category: ThreatCategory.RENTAL_HOUSING,
    keywords: ['rental', 'apartment', 'landlord', 'abroad', 'overseas', 'deposit', 'wire', 'keys', 'below market', 'available'],
    structure: 'attractive listing -> landlord abroad excuse -> deposit request -> untraceable payment',
    similarityThreshold: 0.4,
  },
  {
    id: 'TPL-012', name: 'Student Loan Forgiveness Scam',
    category: ThreatCategory.STUDENT_LOAN,
    keywords: ['student loan', 'forgiveness', 'cancel', 'Biden', 'program', 'qualify', 'apply', 'deadline', 'fee', 'SSN'],
    structure: 'government program claim -> eligibility -> urgency/deadline -> fee or SSN request',
    similarityThreshold: 0.4,
  },
];

// ---------------------------------------------------------------------------
// Match against known scam templates using keyword overlap
// ---------------------------------------------------------------------------
function matchKnownScamTemplates(text: string): { templateName: string; score: number } | null {
  if (!text || text.length < 20) return null;

  const lowerText = text.toLowerCase();
  let bestMatch: { templateName: string; score: number } | null = null;
  let bestScore = 0;

  for (const template of KNOWN_SCAM_TEMPLATES) {
    let matchedKeywords = 0;
    for (const keyword of template.keywords) {
      if (lowerText.includes(keyword.toLowerCase())) {
        matchedKeywords++;
      }
    }
    const score = matchedKeywords / template.keywords.length;
    if (score >= template.similarityThreshold && score > bestScore) {
      bestScore = score;
      bestMatch = { templateName: template.name, score };
    }
  }

  return bestMatch;
}

// ---------------------------------------------------------------------------
// Meta-analysis: look for cross-layer agreement/disagreement patterns
// ---------------------------------------------------------------------------
function runMetaAnalysis(
  layerScores: LayerScores,
  fisherResult: ReturnType<typeof runFisherCascade>,
  conservationResult: ReturnType<typeof runConservationLaws>,
  cascadeResult: ReturnType<typeof runCascadeBreaker>,
  immuneResult: ReturnType<typeof runImmuneRepertoire>,
): MetaAnalysisResult {
  const scores = [layerScores.fisher, layerScores.conservation, layerScores.cascadeBreaker, layerScores.immune];
  const layerNames = ['Fisher', 'Conservation', 'CascadeBreaker', 'Immune'];

  // Cross-layer agreement: how many layers agree on the threat level
  const threshold = 25;
  const agreeing = scores.filter(s => s >= threshold).length;
  const crossLayerAgreement = agreeing / 4;

  // Find conflicting layers (high score in one, low in another)
  const conflictingLayers: string[] = [];
  for (let i = 0; i < scores.length; i++) {
    for (let j = i + 1; j < scores.length; j++) {
      if (Math.abs(scores[i] - scores[j]) > 40) {
        const highLayer = scores[i] > scores[j] ? layerNames[i] : layerNames[j];
        const lowLayer = scores[i] > scores[j] ? layerNames[j] : layerNames[i];
        conflictingLayers.push(`${highLayer} (high) vs ${lowLayer} (low)`);
      }
    }
  }

  // Determine dominant signal type
  let dominantSignalType = 'mixed';
  if (fisherResult.signalsEvaluated.length > 0) {
    const typeCounts: Record<string, number> = {};
    for (const signal of fisherResult.signalsEvaluated) {
      typeCounts[signal.type] = (typeCounts[signal.type] || 0) + 1;
    }
    let maxType = '';
    let maxCount = 0;
    for (const [type, count] of Object.entries(typeCounts)) {
      if (count > maxCount) { maxCount = count; maxType = type; }
    }
    dominantSignalType = maxType;
  }

  // Anomaly patterns
  const anomalyPatterns: string[] = [];

  // Anomaly: Immune matches many but Fisher is low — could be template-based scam with good formatting
  if (layerScores.immune > 50 && layerScores.fisher < 20) {
    anomalyPatterns.push('Known scam pattern detected but surface-level signals are clean — sophisticated scam');
  }

  // Anomaly: Conservation high but no immune match — novel scam type
  if (layerScores.conservation > 50 && layerScores.immune < 10) {
    anomalyPatterns.push('Communication integrity violations without known pattern match — potentially novel scam type');
  }

  // Anomaly: Cascade high but Conservation low — emotional manipulation without structural violations
  if (layerScores.cascadeBreaker > 50 && layerScores.conservation < 15) {
    anomalyPatterns.push('Heavy emotional manipulation detected but message structure appears normal — subtle manipulation');
  }

  // Anomaly: All layers moderate (30-60) — ambiguous, needs human review
  if (scores.every(s => s >= 25 && s <= 60)) {
    anomalyPatterns.push('All layers show moderate suspicion — ambiguous case, recommend human review');
  }

  // Confidence boost from agreement
  let overallConfidenceBoost = 0;
  if (crossLayerAgreement >= 0.75) overallConfidenceBoost = 0.2;
  else if (crossLayerAgreement >= 0.5) overallConfidenceBoost = 0.1;
  else if (conflictingLayers.length > 1) overallConfidenceBoost = -0.1;

  return {
    crossLayerAgreement,
    conflictingLayers,
    dominantSignalType,
    anomalyPatterns,
    overallConfidenceBoost,
  };
}

// ---------------------------------------------------------------------------
// Threat severity classification based on potential financial harm
// ---------------------------------------------------------------------------
function classifyThreatSeverity(
  category: ThreatCategory,
  score: number,
  allText: string,
): ThreatSeverityInfo {
  // Base severity by category
  const categorySeverity: Record<string, ThreatSeverity> = {
    [ThreatCategory.PHISHING]: ThreatSeverity.HIGH_FINANCIAL,
    [ThreatCategory.ADVANCE_FEE]: ThreatSeverity.HIGH_FINANCIAL,
    [ThreatCategory.TECH_SUPPORT]: ThreatSeverity.MODERATE_FINANCIAL,
    [ThreatCategory.ROMANCE]: ThreatSeverity.CATASTROPHIC_FINANCIAL,
    [ThreatCategory.CRYPTO]: ThreatSeverity.CATASTROPHIC_FINANCIAL,
    [ThreatCategory.IRS_GOV]: ThreatSeverity.HIGH_FINANCIAL,
    [ThreatCategory.PACKAGE_DELIVERY]: ThreatSeverity.LOW_FINANCIAL,
    [ThreatCategory.SOCIAL_MEDIA]: ThreatSeverity.MODERATE_FINANCIAL,
    [ThreatCategory.SUBSCRIPTION_TRAP]: ThreatSeverity.LOW_FINANCIAL,
    [ThreatCategory.FAKE_CHARITY]: ThreatSeverity.MODERATE_FINANCIAL,
    [ThreatCategory.RENTAL_HOUSING]: ThreatSeverity.HIGH_FINANCIAL,
    [ThreatCategory.STUDENT_LOAN]: ThreatSeverity.HIGH_FINANCIAL,
    [ThreatCategory.GENERIC]: ThreatSeverity.MODERATE_FINANCIAL,
  };

  const severityDescriptions: Record<ThreatSeverity, { maxLoss: string; desc: string }> = {
    [ThreatSeverity.INFORMATIONAL]: { maxLoss: 'No direct financial loss', desc: 'Informational — no immediate financial threat detected' },
    [ThreatSeverity.LOW_FINANCIAL]: { maxLoss: 'Up to $100', desc: 'Low financial risk — potential for small charges or fees' },
    [ThreatSeverity.MODERATE_FINANCIAL]: { maxLoss: '$100 - $1,000', desc: 'Moderate financial risk — could result in hundreds in losses' },
    [ThreatSeverity.HIGH_FINANCIAL]: { maxLoss: '$1,000 - $10,000', desc: 'High financial risk — potential for significant financial loss' },
    [ThreatSeverity.CATASTROPHIC_FINANCIAL]: { maxLoss: '$10,000+', desc: 'Catastrophic financial risk — potential for total financial devastation' },
  };

  let severity = score < 15 ? ThreatSeverity.INFORMATIONAL : (categorySeverity[category] || ThreatSeverity.MODERATE_FINANCIAL);

  // Escalate if identity theft indicators present
  if (/\b(ssn|social\s*security|passport|driver'?s?\s*license)\b/i.test(allText)) {
    if (severity === ThreatSeverity.LOW_FINANCIAL || severity === ThreatSeverity.MODERATE_FINANCIAL) {
      severity = ThreatSeverity.HIGH_FINANCIAL;
    }
  }

  // Escalate if large dollar amounts mentioned
  if (/\$\s*[\d,]*\d{5,}/.test(allText) || /\b(million|billion)\b/i.test(allText)) {
    severity = ThreatSeverity.CATASTROPHIC_FINANCIAL;
  }

  const info = severityDescriptions[severity];
  return {
    severity,
    estimatedMaxLoss: info.maxLoss,
    description: info.desc,
  };
}

// ---------------------------------------------------------------------------
// Bootstrap confidence interval (improved over Wilson score)
// ---------------------------------------------------------------------------
function bootstrapConfidenceInterval(
  score: number,
  numSignals: number,
  layerAgreement: number,
  metaConfidenceBoost: number,
): ConfidenceInterval {
  // Simulate bootstrap samples using the signal data we have
  const p = score / 100;
  const n = Math.max(4, numSignals);

  // Generate bootstrap estimates by perturbing the score
  const bootstrapSamples: number[] = [];
  const numBootstraps = 200;

  // Deterministic pseudo-bootstrap using signal count and agreement
  for (let i = 0; i < numBootstraps; i++) {
    // Perturbation based on signal uncertainty: fewer signals = more variance
    const signalVariance = 1 / Math.sqrt(n);
    // Use deterministic offsets (no actual randomness needed for this estimation)
    const offset = signalVariance * Math.sin(i * 2.618) * (1 - layerAgreement + 0.3);
    const sample = Math.max(0, Math.min(1, p + offset));
    bootstrapSamples.push(sample);
  }

  // Sort and get percentiles
  bootstrapSamples.sort((a, b) => a - b);
  const lowerIdx = Math.floor(numBootstraps * 0.025);
  const upperIdx = Math.floor(numBootstraps * 0.975);

  let lower = bootstrapSamples[lowerIdx] * 100;
  let upper = bootstrapSamples[upperIdx] * 100;

  // Apply meta-analysis confidence adjustment
  if (metaConfidenceBoost > 0) {
    // Higher agreement = tighter interval
    const tighten = metaConfidenceBoost * 0.3;
    const mid = (lower + upper) / 2;
    lower = lower + (mid - lower) * tighten;
    upper = upper - (upper - mid) * tighten;
  } else if (metaConfidenceBoost < 0) {
    // Conflicting layers = wider interval
    const widen = Math.abs(metaConfidenceBoost) * 0.4;
    const mid = (lower + upper) / 2;
    lower = Math.max(0, lower - (mid - lower) * widen);
    upper = Math.min(100, upper + (upper - mid) * widen);
  }

  return {
    lower: Math.max(0, Math.round(lower * 100) / 100),
    upper: Math.min(100, Math.round(upper * 100) / 100),
    confidence: 0.95,
  };
}

// ---------------------------------------------------------------------------
// Threat level thresholds
// ---------------------------------------------------------------------------
function classifyThreatLevel(score: number): ThreatLevel {
  if (score >= 85) return 'CRITICAL';
  if (score >= 65) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  if (score >= 15) return 'LOW';
  return 'SAFE';
}

// ---------------------------------------------------------------------------
// Threat category classification based on layer results
// ---------------------------------------------------------------------------
function classifyThreatCategory(
  fisherResult: ReturnType<typeof runFisherCascade>,
  immuneResult: ReturnType<typeof runImmuneRepertoire>,
  allText: string,
): ThreatCategory {
  // First priority: immune repertoire matched categories
  if (immuneResult.matchedAntibodies.length > 0) {
    // Count matches per category and pick the dominant one
    const categoryCounts: Record<string, number> = {};
    let maxCount = 0;
    let dominantCategory = ThreatCategory.GENERIC;

    for (const match of immuneResult.matchedAntibodies) {
      const cat = match.category;
      categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;
      if (categoryCounts[cat] > maxCount) {
        maxCount = categoryCounts[cat];
        dominantCategory = cat;
      }
    }
    return dominantCategory;
  }

  // Second priority: keyword-based classification from text
  if (!allText) return ThreatCategory.GENERIC;

  const lower = allText.toLowerCase();

  if (/\b(irs|tax|social\s*security|ssa|government\s*(grant|benefit))\b/.test(lower)) {
    return ThreatCategory.IRS_GOV;
  }
  if (/\b(bitcoin|btc|crypto|ethereum|nft|defi|invest(ment|ing)?.*return)\b/.test(lower)) {
    return ThreatCategory.CRYPTO;
  }
  if (/\b(tech\s*support|virus|malware|microsoft.*call|computer.*infect)\b/.test(lower)) {
    return ThreatCategory.TECH_SUPPORT;
  }
  if (/\b(package|delivery|shipment|usps|fedex|ups|dhl|tracking)\b/.test(lower)) {
    return ThreatCategory.PACKAGE_DELIVERY;
  }
  if (/\b(lottery|sweepstakes|prize|winner|inheritance|advance\s*fee|processing\s*fee)\b/.test(lower)) {
    return ThreatCategory.ADVANCE_FEE;
  }
  if (/\b(verify|confirm|update|suspend|account|password|login|sign[- ]in)\b/.test(lower) &&
      /\b(paypal|amazon|apple|google|microsoft|netflix|bank|chase|wells\s*fargo)\b/.test(lower)) {
    return ThreatCategory.PHISHING;
  }
  if (/\b(love|darling|sweetheart|deployed|military|stranded|widow)\b/.test(lower)) {
    return ThreatCategory.ROMANCE;
  }
  if (/\b(phish|spoof|fake|credential|login|password|click\s*(here|below))\b/.test(lower)) {
    return ThreatCategory.PHISHING;
  }
  if (/\b(instagram|tiktok|twitter|facebook|youtube)\b/.test(lower) &&
      /\b(verif|giveaway|follow|hack|recover|sponsor|ambassador)\b/.test(lower)) {
    return ThreatCategory.SOCIAL_MEDIA;
  }
  if (/\b(subscription|auto[- ]?renew|recurring|trial)\b/.test(lower) &&
      /\b(cancel|charge|bill|payment|fee)\b/.test(lower)) {
    return ThreatCategory.SUBSCRIPTION_TRAP;
  }
  if (/\b(charit|donat|relief|humanitarian|fundrais|gofundme)\b/.test(lower)) {
    return ThreatCategory.FAKE_CHARITY;
  }
  if (/\b(rent|rental|apartment|landlord|tenant|lease|deposit)\b/.test(lower) &&
      /\b(wire|transfer|fee|payment|advance|deposit)\b/.test(lower)) {
    return ThreatCategory.RENTAL_HOUSING;
  }
  if (/\b(student\s*loan|loan\s*forgiv|financial\s*aid|scholarship|fafsa)\b/.test(lower)) {
    return ThreatCategory.STUDENT_LOAN;
  }

  return ThreatCategory.GENERIC;
}

// ---------------------------------------------------------------------------
// Build evidence array from layer results
// ---------------------------------------------------------------------------
function buildEvidence(
  fisherResult: ReturnType<typeof runFisherCascade>,
  conservationResult: ReturnType<typeof runConservationLaws>,
  cascadeResult: ReturnType<typeof runCascadeBreaker>,
  immuneResult: ReturnType<typeof runImmuneRepertoire>,
): EvidenceItem[] {
  const evidence: EvidenceItem[] = [];

  // Fisher cascade evidence
  for (const signal of fisherResult.signalsEvaluated) {
    if (signal.confidence >= 0.7) {
      evidence.push({
        layer: 'Fisher Cascade',
        finding: signal.label,
        severity: signal.confidence >= 0.9 ? 'critical' : signal.confidence >= 0.8 ? 'high' : 'medium',
        detail: `Confidence: ${(signal.confidence * 100).toFixed(0)}%`,
      });
    }
  }

  // Conservation law violations
  for (const violation of conservationResult.violations) {
    if (violation.severity >= 0.3) {
      evidence.push({
        layer: 'Conservation Laws',
        finding: `${violation.lawName} violation: ${violation.description}`,
        severity: violation.severity >= 0.8 ? 'critical' : violation.severity >= 0.6 ? 'high' : violation.severity >= 0.4 ? 'medium' : 'low',
        detail: `Violation severity: ${(violation.severity * 100).toFixed(0)}%`,
      });
    }
  }

  // Cascade breaker findings
  for (const breakdown of cascadeResult.breakdowns) {
    if (breakdown.triggersFound.length > 0) {
      const severity = breakdown.fragility >= 1.5 ? 'high' : breakdown.fragility >= 1.2 ? 'medium' : 'low';
      evidence.push({
        layer: 'Cascade Breaker',
        finding: `Manipulation category "${breakdown.triggerCategory}": ${breakdown.triggersFound.length} trigger(s) detected`,
        severity: severity as EvidenceItem['severity'],
        detail: `Fragility: ${breakdown.fragility.toFixed(3)} — triggers: ${breakdown.triggersFound.slice(0, 3).join(', ')}${breakdown.triggersFound.length > 3 ? '...' : ''}`,
      });

      if (breakdown.secondOrderTriggers.length > 0) {
        evidence.push({
          layer: 'Cascade Breaker',
          finding: `Second-order manipulation in "${breakdown.triggerCategory}"`,
          severity: 'high',
          detail: `${breakdown.secondOrderTriggers.length} subtler trigger(s): ${breakdown.secondOrderTriggers.slice(0, 2).join(', ')}`,
        });
      }
    }
  }

  // Immune repertoire matches
  for (const match of immuneResult.matchedAntibodies) {
    evidence.push({
      layer: 'Immune Repertoire',
      finding: `Pattern match: ${match.name}`,
      severity: match.affinity >= 0.9 ? 'critical' : match.affinity >= 0.8 ? 'high' : 'medium',
      detail: `Affinity: ${(match.affinity * 100).toFixed(0)}% — matched: "${match.matchedText.substring(0, 60)}"`,
    });
  }

  // Sort by severity
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  evidence.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  // Generate human-readable summary evidence items
  const criticalCount = evidence.filter(e => e.severity === 'critical').length;
  const highCount = evidence.filter(e => e.severity === 'high').length;

  if (criticalCount > 0 || highCount > 0) {
    evidence.unshift({
      layer: 'Summary',
      finding: `Found ${criticalCount} critical and ${highCount} high-severity indicators across ${new Set(evidence.map(e => e.layer)).size} analysis layers`,
      severity: criticalCount > 0 ? 'critical' : 'high',
      detail: 'This combination of signals strongly suggests this is a scam attempt. Do not click any links, provide personal information, or send money.',
    });
  }

  return evidence;
}

// ---------------------------------------------------------------------------
// Measure layer agreement (how many layers agree the input is a scam)
// ---------------------------------------------------------------------------
function measureLayerAgreement(scores: LayerScores): number {
  const threshold = 25; // a layer "agrees" if its score >= 25
  let agreeing = 0;
  let total = 0;

  for (const score of Object.values(scores)) {
    total++;
    if (score >= threshold) agreeing++;
  }

  return total > 0 ? agreeing / total : 0;
}

// ---------------------------------------------------------------------------
// Main VERIDICT analysis function
// ---------------------------------------------------------------------------
export async function analyzeWithVERIDICT(input: AnalysisInput): Promise<VERIDICTResult> {
  const startTime = performance.now();

  // --- Input preprocessing ---
  const processedInput = preprocessInput(input);

  // Collect all text for category classification
  const allText = [processedInput.text, processedInput.emailBody, processedInput.smsBody, processedInput.screenshotOcrText]
    .filter(Boolean)
    .join(' ');

  // --- Layer 1: Fisher Information Cascade ---
  const fisherResult = runFisherCascade(processedInput);

  // --- Layer 2: Conservation Law Violation Tensor ---
  const conservationResult = runConservationLaws(processedInput);

  // --- Layer 3: Information Cascade Breaker ---
  const cascadeResult = runCascadeBreaker(processedInput);

  // --- Layer 4: Adaptive Immune Repertoire ---
  // Danger signal gating: activate if Layer 1 OR Layer 2 flagged something
  const dangerSignalActive = fisherResult.score > 15 || conservationResult.score > 15;
  const immuneResult = runImmuneRepertoire(processedInput, dangerSignalActive);

  // --- Combine scores using inclusion-exclusion ---
  const s1 = fisherResult.score / 100;
  const s2 = conservationResult.score / 100;
  const s3 = cascadeResult.score / 100;
  const s4 = immuneResult.score / 100;

  const combinedScore = (1 - (1 - s1) * (1 - s2) * (1 - s3) * (1 - s4)) * 100;

  // --- Classify ---
  const layerScores: LayerScores = {
    fisher: fisherResult.score,
    conservation: conservationResult.score,
    cascadeBreaker: cascadeResult.score,
    immune: immuneResult.score,
  };

  // --- Meta-analysis: cross-layer agreement/disagreement ---
  const metaAnalysis = runMetaAnalysis(layerScores, fisherResult, conservationResult, cascadeResult, immuneResult);

  // Apply meta-analysis confidence boost to final score
  let adjustedScore = combinedScore;
  if (metaAnalysis.crossLayerAgreement >= 0.75 && combinedScore > 30) {
    // Strong agreement on threat: boost score slightly
    adjustedScore = Math.min(100, combinedScore * (1 + metaAnalysis.overallConfidenceBoost));
  } else if (metaAnalysis.conflictingLayers.length > 1 && combinedScore > 20 && combinedScore < 70) {
    // Conflicting signals in the uncertain zone: be more conservative
    adjustedScore = combinedScore * 0.95;
  }

  // preFinalScore used before URL deep analysis boost; final threatLevel computed after
  const preFinalScore = Math.round(adjustedScore * 100) / 100;

  // threatLevel will be re-computed after finalScore is determined below
  let threatLevel = classifyThreatLevel(preFinalScore);
  const category = classifyThreatCategory(fisherResult, immuneResult, allText);

  // --- Threat severity classification ---
  const threatSeverity = classifyThreatSeverity(category, preFinalScore, allText);

  // --- Known scam template matching ---
  const templateMatch = matchKnownScamTemplates(allText);
  const similarKnownScam = templateMatch
    ? `${templateMatch.templateName} (${(templateMatch.score * 100).toFixed(0)}% match)`
    : null;

  // --- Build evidence ---
  const evidence = buildEvidence(fisherResult, conservationResult, cascadeResult, immuneResult);

  // Add meta-analysis findings to evidence
  for (const anomaly of metaAnalysis.anomalyPatterns) {
    evidence.push({
      layer: 'Meta-Analysis',
      finding: anomaly,
      severity: 'medium',
      detail: `Cross-layer agreement: ${(metaAnalysis.crossLayerAgreement * 100).toFixed(0)}%`,
    });
  }

  // Add known scam template match to evidence
  if (templateMatch && templateMatch.score > 0.4) {
    evidence.push({
      layer: 'Template Matching',
      finding: `Matches known scam template: "${templateMatch.templateName}"`,
      severity: templateMatch.score > 0.7 ? 'critical' : templateMatch.score > 0.5 ? 'high' : 'medium',
      detail: `Keyword overlap: ${(templateMatch.score * 100).toFixed(0)}% — this message closely resembles a well-known scam pattern`,
    });
  }

  // Add threat severity to evidence if significant
  if (threatSeverity.severity !== ThreatSeverity.INFORMATIONAL) {
    evidence.push({
      layer: 'Financial Risk',
      finding: `Estimated max financial loss: ${threatSeverity.estimatedMaxLoss}`,
      severity: threatSeverity.severity === ThreatSeverity.CATASTROPHIC_FINANCIAL ? 'critical' :
                threatSeverity.severity === ThreatSeverity.HIGH_FINANCIAL ? 'high' : 'medium',
      detail: threatSeverity.description,
    });
  }

  // --- URL Deep Analysis (runs in parallel with main 4 layers conceptually; applied after) ---
  let urlDeepAnalysis = processedInput.url
    ? deepAnalyzeUrl(processedInput.url)
    : undefined;

  // If URL deep analysis found high risk, add evidence and apply score boost
  if (urlDeepAnalysis && urlDeepAnalysis.overallRiskScore > 0.3) {
    const urlRiskPct = urlDeepAnalysis.overallRiskScore * 100;

    // Add URL flags as evidence items
    for (const flag of urlDeepAnalysis.flags.slice(0, 5)) {
      evidence.push({
        layer: 'URL Deep Analysis',
        finding: flag,
        severity: urlDeepAnalysis.overallRiskScore >= 0.75 ? 'critical'
          : urlDeepAnalysis.overallRiskScore >= 0.55 ? 'high'
          : urlDeepAnalysis.overallRiskScore >= 0.35 ? 'medium' : 'low',
        detail: `URL risk score: ${urlRiskPct.toFixed(0)}%`,
      });
    }

    // Add detected brand impersonation
    for (const b of urlDeepAnalysis.detectedBrands.slice(0, 2)) {
      evidence.push({
        layer: 'URL Deep Analysis',
        finding: `Brand impersonation: "${b.brand}" (edit distance ${b.distance})`,
        severity: b.distance <= 1 ? 'critical' : 'high',
        detail: `Domain closely mimics a trusted brand to deceive victims`,
      });
    }

    // Add homoglyphs detected
    if (urlDeepAnalysis.homoglyphsDetected.length > 0) {
      const examples = urlDeepAnalysis.homoglyphsDetected.slice(0, 2)
        .map(h => `"${h.lookalike}" looks like "${h.original}"`)
        .join(', ');
      evidence.push({
        layer: 'URL Deep Analysis',
        finding: `Visual deception: lookalike characters in URL`,
        severity: 'high',
        detail: examples,
      });
    }

    // Blend URL deep score into final score via inclusion-exclusion
    const sUrl = urlDeepAnalysis.overallRiskScore;
    const blendedScore = (1 - (1 - preFinalScore / 100) * (1 - sUrl * 0.6)) * 100;
    adjustedScore = Math.min(100, blendedScore);
  } else {
    adjustedScore = preFinalScore;
  }

  const finalScore = Math.round(Math.max(0, Math.min(100, adjustedScore)) * 100) / 100;
  threatLevel = classifyThreatLevel(finalScore);

  // --- Similarity Engine: replace keyword-only template matching with trigram+TF-IDF ---
  let similarityAnalysis = undefined;
  const fullText = [processedInput.text, processedInput.emailBody, processedInput.smsBody,
    processedInput.screenshotOcrText].filter(Boolean).join(' ');

  if (fullText.trim().length >= 30) {
    similarityAnalysis = findClosestTemplates(fullText);

    // Add similarity evidence for best match
    if (similarityAnalysis.bestScore > 0.35 && similarityAnalysis.topMatches[0]) {
      const topMatch = similarityAnalysis.topMatches[0];
      evidence.push({
        layer: 'Similarity Engine',
        finding: `Matches scam template: "${topMatch.template.name}"`,
        severity: topMatch.compositeScore >= 0.7 ? 'critical'
          : topMatch.compositeScore >= 0.5 ? 'high' : 'medium',
        detail: `Trigram: ${(topMatch.trigramScore * 100).toFixed(0)}% | TF-IDF: ${(topMatch.tfidfScore * 100).toFixed(0)}% | Structural: ${(topMatch.structuralScore * 100).toFixed(0)}%`,
      });
    }
  }

  // Override similarKnownScam with similarity engine result if better
  const resolvedSimilarKnownScam = (
    similarityAnalysis && similarityAnalysis.bestScore > 0.35 && similarityAnalysis.topMatches[0]
      ? `${similarityAnalysis.topMatches[0].template.name} (${(similarityAnalysis.bestScore * 100).toFixed(0)}% similarity)`
      : similarKnownScam
  );

  // --- Bootstrap confidence interval ---
  const numSignals = fisherResult.signalsEvaluated.length +
    conservationResult.violations.length +
    cascadeResult.breakdowns.reduce((s, b) => s + b.triggersFound.length, 0) +
    immuneResult.matchedAntibodies.length;

  const layerAgreement = measureLayerAgreement(layerScores);
  const confidenceInterval = bootstrapConfidenceInterval(
    finalScore,
    numSignals,
    Math.max(0.25, layerAgreement),
    metaAnalysis.overallConfidenceBoost,
  );

  const processingTimeMs = Math.round((performance.now() - startTime) * 100) / 100;

  // --- Build partial result first (needed by assessFinancialRisk) ---
  const partialResult: VERIDICTResult = {
    score: finalScore,
    threatLevel,
    category,
    evidence,
    layerScores,
    confidenceInterval,
    processingTimeMs,
    threatSeverity,
    metaAnalysis,
    similarKnownScam: resolvedSimilarKnownScam,
    layerDetails: {
      fisher: fisherResult,
      conservation: conservationResult,
      cascadeBreaker: cascadeResult,
      immune: immuneResult,
    },
    urlDeepAnalysis,
    similarityAnalysis,
  };

  // --- Financial Risk Assessment (uses full result) ---
  const financialRisk = finalScore >= 15 ? assessFinancialRisk(partialResult) : undefined;

  // Add financial risk evidence if significant
  if (financialRisk && financialRisk.riskScore >= 5) {
    evidence.push({
      layer: 'Financial Risk Engine',
      finding: `Financial risk level: ${financialRisk.riskScore.toFixed(1)}/10 — ${financialRisk.riskType.replace('_', ' ')}`,
      severity: financialRisk.riskScore >= 8 ? 'critical' : financialRisk.riskScore >= 6 ? 'high' : 'medium',
      detail: `Estimated loss range: $${financialRisk.estimatedLoss.min.toLocaleString()}–$${financialRisk.estimatedLoss.max.toLocaleString()} (median $${financialRisk.estimatedLoss.median.toLocaleString()})`,
    });
  }

  // --- Multilingual Scam Detection ---
  const multilingualDetection = detectMultilingualScam(fullText);
  if (multilingualDetection.detected && multilingualDetection.riskScore > 0.3) {
    evidence.push({
      layer: 'Multilingual Detector',
      finding: `${multilingualDetection.matches.length} scam pattern(s) detected in ${multilingualDetection.dominantLanguage?.toUpperCase() ?? 'foreign language'}`,
      severity: multilingualDetection.riskScore >= 0.7 ? 'high' : 'medium',
      detail: multilingualDetection.flags.slice(0, 3).join('; '),
    });
  }

  // --- Phone Number Scam Analysis ---
  const phoneAnalysis = analyzePhoneNumbers(fullText);
  if (phoneAnalysis.detected && phoneAnalysis.highestRisk > 0.25) {
    evidence.push({
      layer: 'Phone Analyzer',
      finding: `${phoneAnalysis.phones.length} phone number(s) with elevated scam risk (max score: ${(phoneAnalysis.highestRisk * 100).toFixed(0)}%)`,
      severity: phoneAnalysis.highestRisk >= 0.6 ? 'high' : 'medium',
      detail: phoneAnalysis.flags.slice(0, 3).join('; '),
    });
  }

  // --- Linguistic Deception Layer (Layer 5) ---
  const linguisticDeception = detectLinguisticDeception(fullText);
  if (linguisticDeception.score > 10) {
    evidence.push({
      layer: 'Linguistic Deception Layer',
      finding: `${linguisticDeception.deceptionTactics.length} psychological manipulation tactic(s) detected (score: ${linguisticDeception.score.toFixed(1)}/100)`,
      severity: linguisticDeception.score >= 60 ? 'critical'
        : linguisticDeception.score >= 40 ? 'high'
        : linguisticDeception.score >= 20 ? 'medium' : 'low',
      detail: linguisticDeception.flags.slice(0, 4).join('; '),
    });
  }

  // --- Conversation Arc Analysis (grooming phase detection for multi-message exports) ---
  // Activate when content is long enough to contain a conversation (200+ chars, 3+ lines or timestamps)
  let conversationArc: import('./conversation-arc').ConversationArcResult | undefined;
  const looksLikeConversation = fullText.length >= 200 &&
    (fullText.split('\n').length >= 4 || /\d{1,2}[:/]\d{2}/.test(fullText));
  if (looksLikeConversation) {
    conversationArc = analyzeConversationArc(fullText);
    if (conversationArc.overallRisk > 15) {
      evidence.push({
        layer: 'Conversation Arc',
        finding: `${conversationArc.arcLabel} detected — ${conversationArc.phases.filter(p => p.present).length} grooming phases active`,
        severity: conversationArc.overallRisk >= 70 ? 'critical'
          : conversationArc.overallRisk >= 45 ? 'high'
          : 'medium',
        detail: conversationArc.criticalFindings.length > 0
          ? conversationArc.criticalFindings.slice(0, 3).join('; ')
          : `Risk: ${conversationArc.overallRisk.toFixed(0)}% — arc type: ${conversationArc.arcType}`,
      });
    }
  }

  return {
    ...partialResult,
    financialRisk,
    multilingualDetection: multilingualDetection.detected ? multilingualDetection : undefined,
    phoneAnalysis: phoneAnalysis.detected ? phoneAnalysis : undefined,
    linguisticDeception: linguisticDeception.score > 5 ? linguisticDeception : undefined,
    conversationArc,
  };
}

// ---------------------------------------------------------------------------
// Alias for backward compatibility with existing API routes
export const runVERIDICT = analyzeWithVERIDICT;

// Convenience: quick scan that returns just score + threat level
// ---------------------------------------------------------------------------
export async function quickScan(input: AnalysisInput): Promise<{
  score: number;
  threatLevel: ThreatLevel;
  category: ThreatCategory;
  topEvidence: string[];
}> {
  const result = await analyzeWithVERIDICT(input);
  return {
    score: result.score,
    threatLevel: result.threatLevel,
    category: result.category,
    topEvidence: result.evidence.slice(0, 5).map(e => e.finding),
  };
}
