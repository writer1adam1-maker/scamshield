// ============================================================================
// ScamShield Financial Risk Assessment Algorithm
// Proprietary algorithm: multi-factor risk scoring combining category-based
// loss estimation, sophistication analysis, urgency detection, and targeting
// profile to produce a 1-10 risk score with actionable recommendations.
// ============================================================================

import {
  ThreatCategory,
  ThreatLevel,
  VERIDICTResult,
  FinancialRiskType,
  LossRange,
  FinancialRiskResult,
  EvidenceItem,
} from './types';

// ---------------------------------------------------------------------------
// Category-to-Risk Mapping
// ---------------------------------------------------------------------------

interface CategoryRiskProfile {
  primaryRiskType: FinancialRiskType;
  baseLoss: LossRange;
  baseRisk: number; // 1-10
  typicalSophistication: number; // 0-1
  isTargeted: boolean;
}

const CATEGORY_RISK_MAP: Record<ThreatCategory, CategoryRiskProfile> = {
  [ThreatCategory.PHISHING]: {
    primaryRiskType: 'credential_theft',
    baseLoss: { min: 0, max: 50000, median: 2500 },
    baseRisk: 7,
    typicalSophistication: 0.6,
    isTargeted: false,
  },
  [ThreatCategory.ADVANCE_FEE]: {
    primaryRiskType: 'advance_fee',
    baseLoss: { min: 100, max: 10000, median: 1500 },
    baseRisk: 6,
    typicalSophistication: 0.4,
    isTargeted: false,
  },
  [ThreatCategory.TECH_SUPPORT]: {
    primaryRiskType: 'direct_payment',
    baseLoss: { min: 200, max: 25000, median: 3000 },
    baseRisk: 7,
    typicalSophistication: 0.5,
    isTargeted: false,
  },
  [ThreatCategory.ROMANCE]: {
    primaryRiskType: 'direct_payment',
    baseLoss: { min: 1000, max: 500000, median: 25000 },
    baseRisk: 9,
    typicalSophistication: 0.8,
    isTargeted: true,
  },
  [ThreatCategory.CRYPTO]: {
    primaryRiskType: 'investment_fraud',
    baseLoss: { min: 500, max: 1000000, median: 50000 },
    baseRisk: 9,
    typicalSophistication: 0.7,
    isTargeted: false,
  },
  [ThreatCategory.IRS_GOV]: {
    primaryRiskType: 'identity_theft',
    baseLoss: { min: 500, max: 100000, median: 10000 },
    baseRisk: 8,
    typicalSophistication: 0.6,
    isTargeted: false,
  },
  [ThreatCategory.PACKAGE_DELIVERY]: {
    primaryRiskType: 'credential_theft',
    baseLoss: { min: 0, max: 5000, median: 500 },
    baseRisk: 5,
    typicalSophistication: 0.3,
    isTargeted: false,
  },
  [ThreatCategory.SOCIAL_MEDIA]: {
    primaryRiskType: 'credential_theft',
    baseLoss: { min: 0, max: 10000, median: 1000 },
    baseRisk: 5,
    typicalSophistication: 0.4,
    isTargeted: false,
  },
  [ThreatCategory.SUBSCRIPTION_TRAP]: {
    primaryRiskType: 'subscription_trap',
    baseLoss: { min: 50, max: 2000, median: 300 },
    baseRisk: 4,
    typicalSophistication: 0.3,
    isTargeted: false,
  },
  [ThreatCategory.FAKE_CHARITY]: {
    primaryRiskType: 'direct_payment',
    baseLoss: { min: 25, max: 5000, median: 500 },
    baseRisk: 5,
    typicalSophistication: 0.4,
    isTargeted: false,
  },
  [ThreatCategory.RENTAL_HOUSING]: {
    primaryRiskType: 'advance_fee',
    baseLoss: { min: 500, max: 10000, median: 3000 },
    baseRisk: 7,
    typicalSophistication: 0.5,
    isTargeted: true,
  },
  [ThreatCategory.STUDENT_LOAN]: {
    primaryRiskType: 'identity_theft',
    baseLoss: { min: 200, max: 50000, median: 5000 },
    baseRisk: 6,
    typicalSophistication: 0.5,
    isTargeted: false,
  },
  [ThreatCategory.GENERIC]: {
    primaryRiskType: 'unknown',
    baseLoss: { min: 0, max: 5000, median: 500 },
    baseRisk: 3,
    typicalSophistication: 0.3,
    isTargeted: false,
  },
  // v2 categories
  [ThreatCategory.MARKETPLACE_FRAUD]: {
    primaryRiskType: 'direct_payment',
    baseLoss: { min: 50, max: 15000, median: 800 },
    baseRisk: 7,
    typicalSophistication: 0.45,
    isTargeted: false,
  },
  [ThreatCategory.ELDER_SCAM]: {
    primaryRiskType: 'direct_payment',
    baseLoss: { min: 500, max: 100000, median: 9000 },
    baseRisk: 9,
    typicalSophistication: 0.75,
    isTargeted: true,
  },
  [ThreatCategory.TICKET_SCAM]: {
    primaryRiskType: 'direct_payment',
    baseLoss: { min: 30, max: 2000, median: 200 },
    baseRisk: 6,
    typicalSophistication: 0.35,
    isTargeted: false,
  },
  [ThreatCategory.INVESTMENT_FRAUD]: {
    primaryRiskType: 'investment_fraud',
    baseLoss: { min: 1000, max: 500000, median: 25000 },
    baseRisk: 9,
    typicalSophistication: 0.80,
    isTargeted: true,
  },
  [ThreatCategory.EMPLOYMENT_SCAM]: {
    primaryRiskType: 'identity_theft',
    baseLoss: { min: 200, max: 20000, median: 3000 },
    baseRisk: 7,
    typicalSophistication: 0.55,
    isTargeted: false,
  },
  [ThreatCategory.BANK_OTP]: {
    primaryRiskType: 'direct_payment',
    baseLoss: { min: 500, max: 200000, median: 15000 },
    baseRisk: 9,
    typicalSophistication: 0.85,
    isTargeted: true,
  },
};

// ---------------------------------------------------------------------------
// Sophistication Analysis
// ---------------------------------------------------------------------------

interface SophisticationSignals {
  score: number;
  factors: string[];
}

/**
 * Analyzes the sophistication of the scam based on evidence from the
 * VERIDICT analysis. Higher sophistication = harder for victims to detect.
 */
function analyzeSophistication(verdict: VERIDICTResult): SophisticationSignals {
  let score = 0;
  const factors: string[] = [];

  // Cross-layer agreement: high agreement on scam = sophisticated enough to trigger all layers
  if (verdict.metaAnalysis.crossLayerAgreement > 0.8) {
    score += 0.15;
    factors.push('Multi-layer signal consistency indicates well-crafted scam');
  }

  // Fisher layer: high information content = more deceptive signals planted
  if (verdict.layerScores.fisher > 70) {
    score += 0.15;
    factors.push('High information-theoretic signal density');
  }

  // Conservation violations: more violations = more attack vectors used
  const violationCount = verdict.layerDetails.conservation.violations.length;
  if (violationCount >= 4) {
    score += 0.2;
    factors.push(`${violationCount} conservation violations: multi-vector attack`);
  } else if (violationCount >= 2) {
    score += 0.1;
    factors.push(`${violationCount} conservation violations detected`);
  }

  // Cascade fragility: high fragility means scam depends on single deception
  // Low fragility = layered deceptions = more sophisticated
  if (verdict.layerDetails.cascadeBreaker.overallFragility < 0.3) {
    score += 0.15;
    factors.push('Low fragility: deception resilient to partial detection');
  }

  // Immune layer: more antibody matches = using known effective patterns
  const antibodyCount = verdict.layerDetails.immune.matchedAntibodies.length;
  if (antibodyCount >= 5) {
    score += 0.15;
    factors.push('Multiple known scam pattern antibodies triggered');
  }

  // Overall VERIDICT score proximity to threshold (70-85 range is most sophisticated)
  // Too obvious (>90) is actually less sophisticated; sweet spot is 70-85
  if (verdict.score >= 70 && verdict.score <= 85) {
    score += 0.1;
    factors.push('Score in sophisticated range: designed to bypass casual inspection');
  }

  // Confidence interval width: narrow CI with high score = precision attack
  const ciWidth = verdict.confidenceInterval.upper - verdict.confidenceInterval.lower;
  if (ciWidth < 15 && verdict.score > 60) {
    score += 0.1;
    factors.push('Narrow confidence interval: consistent scam signals');
  }

  return { score: Math.min(1, score), factors };
}

// ---------------------------------------------------------------------------
// Urgency Analysis
// ---------------------------------------------------------------------------

/**
 * Computes urgency score based on evidence items and layer results.
 * Urgency indicates how quickly the victim needs to act (higher = more pressure).
 */
function analyzeUrgency(verdict: VERIDICTResult): number {
  let urgency = 0;

  // Check evidence items for urgency-related findings
  const urgencyKeywords = [
    'urgent', 'immediate', 'expire', 'deadline', 'suspend', 'locked',
    'hours', 'minutes', 'today', 'now', 'limited time', 'act fast',
    'final notice', 'last chance', 'terminate', 'disable',
  ];

  for (const evidence of verdict.evidence) {
    const detail = evidence.detail.toLowerCase();
    const matchCount = urgencyKeywords.filter((kw) => detail.includes(kw)).length;
    urgency += matchCount * 0.08;

    // Severity-based boost
    if (evidence.severity === 'critical') urgency += 0.15;
    else if (evidence.severity === 'high') urgency += 0.1;
  }

  // Conservation layer violations with time pressure
  for (const v of verdict.layerDetails.conservation.violations) {
    if (v.evidence.toLowerCase().includes('time') || v.evidence.toLowerCase().includes('deadline')) {
      urgency += 0.12;
    }
  }

  // Cascade breaker: check for urgency triggers
  for (const bd of verdict.layerDetails.cascadeBreaker.breakdowns) {
    if (bd.triggerCategory === 'urgency' || bd.triggerCategory === 'deadline') {
      urgency += 0.15;
    }
  }

  return Math.min(1, urgency);
}

// ---------------------------------------------------------------------------
// Targeting Analysis
// ---------------------------------------------------------------------------

/**
 * Determines whether the scam is mass-distributed or targeted at an individual.
 * Targeted scams are more dangerous due to personalization.
 */
function analyzeTargeting(verdict: VERIDICTResult): {
  score: number;
  isTargeted: boolean;
} {
  let targetingSignals = 0;

  // Check for personalization signals in evidence
  const personalizationKeywords = [
    'your name', 'dear [name]', 'account ending in', 'specific amount',
    'personal details', 'your address', 'your phone', 'your email',
    'we noticed you', 'based on your',
  ];

  for (const evidence of verdict.evidence) {
    const detail = evidence.detail.toLowerCase();
    for (const kw of personalizationKeywords) {
      if (detail.includes(kw)) targetingSignals += 0.15;
    }
  }

  // Category-based targeting tendency
  const categoryProfile = CATEGORY_RISK_MAP[verdict.category];
  if (categoryProfile.isTargeted) {
    targetingSignals += 0.3;
  }

  // Immune layer: check if antibodies suggest targeted patterns
  for (const ab of verdict.layerDetails.immune.matchedAntibodies) {
    if (ab.category === ThreatCategory.ROMANCE || ab.category === ThreatCategory.RENTAL_HOUSING) {
      targetingSignals += 0.1;
    }
  }

  const score = Math.min(1, targetingSignals);
  return { score, isTargeted: score > 0.5 };
}

// ---------------------------------------------------------------------------
// Loss Estimation
// ---------------------------------------------------------------------------

/**
 * Adjusts the base loss range based on sophistication, targeting, and
 * urgency factors. More sophisticated, targeted, urgent scams have higher
 * potential losses.
 */
function estimateLoss(
  baseLoss: LossRange,
  sophistication: number,
  targeting: number,
  urgency: number,
): LossRange {
  // Combined multiplier: sophisticated + targeted + urgent = higher loss potential
  const multiplier = 1 + sophistication * 0.5 + targeting * 0.8 + urgency * 0.3;

  return {
    min: Math.round(baseLoss.min * multiplier),
    max: Math.round(baseLoss.max * multiplier),
    median: Math.round(baseLoss.median * multiplier),
  };
}

// ---------------------------------------------------------------------------
// Recommendation Engine
// ---------------------------------------------------------------------------

function generateRecommendations(
  riskType: FinancialRiskType,
  riskScore: number,
  urgencyScore: number,
  category: ThreatCategory,
): string[] {
  const actions: string[] = [];

  // Universal recommendations
  actions.push('Do not click any links or download attachments');
  actions.push('Do not provide personal information, passwords, or financial details');

  // Risk-type specific
  switch (riskType) {
    case 'credential_theft':
      actions.push('Change passwords for any accounts that may be compromised');
      actions.push('Enable two-factor authentication on all financial accounts');
      actions.push('Check account statements for unauthorized transactions');
      break;
    case 'direct_payment':
      actions.push('Do NOT send money via wire transfer, gift cards, or cryptocurrency');
      actions.push('Contact your bank immediately if you already sent payment');
      actions.push('Request a chargeback if payment was made by credit card');
      break;
    case 'identity_theft':
      actions.push('Place a fraud alert or credit freeze with all three credit bureaus');
      actions.push('Monitor your credit reports for unauthorized accounts');
      actions.push('File an Identity Theft Report at IdentityTheft.gov');
      break;
    case 'subscription_trap':
      actions.push('Check credit card statements for recurring unauthorized charges');
      actions.push('Contact your card issuer to block the merchant');
      actions.push('File a dispute for any unauthorized charges');
      break;
    case 'investment_fraud':
      actions.push('Do NOT invest any money regardless of "guaranteed" returns');
      actions.push('Report to the SEC if securities fraud is suspected');
      actions.push('No legitimate investment guarantees specific returns');
      break;
    case 'advance_fee':
      actions.push('Legitimate prizes and loans do not require upfront payments');
      actions.push('Never pay processing fees, taxes, or shipping for prizes you did not enter');
      actions.push('If you sent money, contact your bank or payment provider immediately');
      break;
    default:
      actions.push('Report this content to the platform where you received it');
      break;
  }

  // Category-specific additions
  if (category === ThreatCategory.IRS_GOV) {
    actions.push('The IRS never initiates contact via text, email, or social media');
    actions.push('Report IRS impersonation to the Treasury Inspector General: 1-800-366-4484');
  }
  if (category === ThreatCategory.ROMANCE) {
    actions.push('Never send money to someone you have not met in person');
    actions.push('Do a reverse image search on their photos');
    actions.push('Report romance scams to the FTC at ReportFraud.ftc.gov');
  }
  if (category === ThreatCategory.CRYPTO) {
    actions.push('Cryptocurrency transactions are irreversible - never send crypto to unknown parties');
    actions.push('Report crypto scams to the FTC and FBI IC3');
  }

  // High urgency: emphasize immediate action
  if (urgencyScore > 0.7) {
    actions.unshift('IMMEDIATE: Do not respond or take any action under pressure');
  }

  // High risk score: emphasize reporting
  if (riskScore >= 8) {
    actions.push('File a report with the FBI Internet Crime Complaint Center (IC3)');
    actions.push('Report to the FTC at ReportFraud.ftc.gov');
  }

  return actions;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Performs a comprehensive financial risk assessment based on a VERIDICT
 * analysis result. Produces a 1-10 risk score, estimated loss range,
 * urgency/targeting/sophistication sub-scores, and actionable recommendations.
 */
export function assessFinancialRisk(verdict: VERIDICTResult): FinancialRiskResult {
  // Get category risk profile
  const categoryProfile = CATEGORY_RISK_MAP[verdict.category] ?? CATEGORY_RISK_MAP[ThreatCategory.GENERIC];

  // Analyze sub-factors
  const sophistication = analyzeSophistication(verdict);
  const urgencyScore = analyzeUrgency(verdict);
  const targeting = analyzeTargeting(verdict);

  // Composite risk score (1-10 scale)
  // Base risk from category, adjusted by VERIDICT score and sub-factors
  const verdictFactor = verdict.score / 100; // 0-1
  const categoryRisk = categoryProfile.baseRisk * verdictFactor;
  const sophisticationRisk = sophistication.score * 2.5; // max 2.5
  const urgencyRisk = urgencyScore * 2.0; // max 2.0
  const targetingRisk = targeting.score * 1.5; // max 1.5

  // Weighted combination capped at 10
  const rawRisk =
    categoryRisk * 0.40 +
    sophisticationRisk * 0.20 +
    urgencyRisk * 0.20 +
    targetingRisk * 0.20;

  const riskScore = Math.min(10, Math.max(1, Math.round(rawRisk * 10) / 10));

  // Estimate adjusted loss range
  const estimatedLoss = estimateLoss(
    categoryProfile.baseLoss,
    sophistication.score,
    targeting.score,
    urgencyScore,
  );

  // Determine risk type (may differ from category default based on evidence)
  let riskType = categoryProfile.primaryRiskType;

  // Override risk type if evidence strongly suggests a different type
  const evidenceText = verdict.evidence.map((e) => e.detail.toLowerCase()).join(' ');
  if (evidenceText.includes('password') || evidenceText.includes('credential') || evidenceText.includes('login')) {
    riskType = 'credential_theft';
  } else if (evidenceText.includes('wire') || evidenceText.includes('gift card') || evidenceText.includes('payment')) {
    riskType = 'direct_payment';
  } else if (evidenceText.includes('ssn') || evidenceText.includes('social security') || evidenceText.includes('identity')) {
    riskType = 'identity_theft';
  }

  // Generate recommendations
  const recommendedActions = generateRecommendations(
    riskType,
    riskScore,
    urgencyScore,
    verdict.category,
  );

  return {
    riskScore,
    riskType,
    estimatedLoss,
    urgencyScore: Math.round(urgencyScore * 100) / 100,
    targetingScore: Math.round(targeting.score * 100) / 100,
    sophisticationScore: Math.round(sophistication.score * 100) / 100,
    recommendedActions,
    breakdown: {
      categoryRisk: Math.round(categoryRisk * 100) / 100,
      sophisticationRisk: Math.round(sophisticationRisk * 100) / 100,
      urgencyRisk: Math.round(urgencyRisk * 100) / 100,
      targetingRisk: Math.round(targetingRisk * 100) / 100,
    },
  };
}
