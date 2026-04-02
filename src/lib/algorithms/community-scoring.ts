// ============================================================================
// ScamShield Community Trust Aggregation Algorithm
// Proprietary algorithm: Bayesian reputation system, Wilson score intervals,
// temporal decay, and anti-gaming detection for community scam reports.
// ============================================================================

import {
  CommunityReport,
  ReporterReliability,
  CommunityTrustResult,
} from './types';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const WILSON_Z = 1.96; // 95% confidence interval
const TEMPORAL_DECAY_HALF_LIFE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const MIN_REPORTS_FOR_RELIABILITY = 3;
const BAYESIAN_PRIOR_ALPHA = 2; // prior "positive" observations
const BAYESIAN_PRIOR_BETA = 2; // prior "negative" observations
const COORDINATION_TIME_WINDOW_MS = 10 * 60 * 1000; // 10-minute window for burst detection
const COORDINATION_MIN_CLUSTER_SIZE = 3;
const NEW_ACCOUNT_THRESHOLD_DAYS = 30;
const SUSPICIOUS_AGREEMENT_RATE = 0.95; // too-perfect agreement threshold
const MIN_REPORTS_FOR_GAMING_ANALYSIS = 5;

// ---------------------------------------------------------------------------
// Temporal Decay
// ---------------------------------------------------------------------------

/**
 * Exponential decay weight based on age of the report.
 * Reports decay to half-weight at HALF_LIFE intervals.
 * w(t) = 2^(-age / halfLife)
 */
function temporalWeight(reportTimestamp: number, now: number): number {
  const age = now - reportTimestamp;
  if (age <= 0) return 1;
  return Math.pow(2, -age / TEMPORAL_DECAY_HALF_LIFE_MS);
}

// ---------------------------------------------------------------------------
// Wilson Score Interval
// ---------------------------------------------------------------------------

/**
 * Computes the Wilson score confidence interval for a proportion.
 * This is the gold standard for rating systems with small sample sizes.
 *
 * Given n trials with p positive outcomes, returns the lower and upper
 * bounds of the confidence interval.
 *
 * Formula:
 *   center = (p + z^2/2n) / (1 + z^2/n)
 *   margin = z * sqrt(p(1-p)/n + z^2/4n^2) / (1 + z^2/n)
 */
function wilsonScore(
  positive: number,
  total: number,
  z: number = WILSON_Z,
): { lower: number; upper: number; center: number } {
  if (total === 0) return { lower: 0, upper: 0, center: 0 };

  const phat = positive / total;
  const z2 = z * z;
  const denominator = 1 + z2 / total;
  const center = (phat + z2 / (2 * total)) / denominator;
  const margin =
    (z * Math.sqrt((phat * (1 - phat)) / total + z2 / (4 * total * total))) /
    denominator;

  return {
    lower: Math.max(0, center - margin),
    upper: Math.min(1, center + margin),
    center,
  };
}

// ---------------------------------------------------------------------------
// Bayesian Reporter Reliability
// ---------------------------------------------------------------------------

/**
 * Computes reporter reliability using a Beta-Binomial Bayesian model.
 *
 * Prior: Beta(ALPHA, BETA) - mildly skeptical prior
 * Likelihood: Binomial(accurate | total)
 * Posterior: Beta(ALPHA + accurate, BETA + inaccurate)
 *
 * Returns the posterior mean as the reliability score.
 */
function bayesianReliability(
  accurateReports: number,
  totalReports: number,
): number {
  const alpha = BAYESIAN_PRIOR_ALPHA + accurateReports;
  const beta = BAYESIAN_PRIOR_BETA + (totalReports - accurateReports);
  // Posterior mean of Beta distribution
  return alpha / (alpha + beta);
}

/**
 * Account age factor: newer accounts have lower trust.
 * Sigmoid curve: ramps from 0.3 (brand new) to 1.0 (~90 days).
 */
function accountAgeFactor(accountAgeDays: number): number {
  // Logistic curve centered at 45 days, steepness 0.08
  return 0.3 + 0.7 / (1 + Math.exp(-0.08 * (accountAgeDays - 45)));
}

/**
 * Activity volume factor: accounts with very few reports have less weight.
 * Logarithmic scaling with diminishing returns.
 */
function volumeFactor(totalReports: number): number {
  if (totalReports <= 0) return 0;
  return Math.min(1, Math.log2(totalReports + 1) / Math.log2(50));
}

// ---------------------------------------------------------------------------
// Anti-Gaming Detection
// ---------------------------------------------------------------------------

interface GamingSignal {
  type: string;
  description: string;
  severity: number; // 0-1
  involvedReporters: string[];
}

/**
 * Detects coordinated false reporting by analyzing temporal clustering,
 * reporter relationships, and statistical anomalies.
 */
function detectGamingSignals(reports: CommunityReport[]): GamingSignal[] {
  const signals: GamingSignal[] = [];

  if (reports.length < MIN_REPORTS_FOR_GAMING_ANALYSIS) return signals;

  // --- 1. Temporal burst detection ---
  // Sort by timestamp and find clusters of reports within the coordination window
  const sorted = [...reports].sort((a, b) => a.timestamp - b.timestamp);
  let clusterStart = 0;

  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i].timestamp - sorted[clusterStart].timestamp > COORDINATION_TIME_WINDOW_MS) {
      clusterStart = i;
    }
    const clusterSize = i - clusterStart + 1;
    if (clusterSize >= COORDINATION_MIN_CLUSTER_SIZE) {
      const clusterReporters = sorted
        .slice(clusterStart, i + 1)
        .map((r) => r.reporterId);
      const uniqueReporters = new Set(clusterReporters);

      // Only flag if it's different reporters (not one person editing)
      if (uniqueReporters.size >= COORDINATION_MIN_CLUSTER_SIZE) {
        signals.push({
          type: 'temporal_burst',
          description: `${uniqueReporters.size} unique reporters within ${COORDINATION_TIME_WINDOW_MS / 60000} minutes`,
          severity: Math.min(1, uniqueReporters.size / 8),
          involvedReporters: [...uniqueReporters],
        });
      }
    }
  }

  // --- 2. New account coordination ---
  // Multiple new accounts all reporting the same target
  const newAccounts = reports.filter(
    (r) => r.reporterAccountAge < NEW_ACCOUNT_THRESHOLD_DAYS,
  );
  if (newAccounts.length >= 3 && newAccounts.length / reports.length > 0.5) {
    signals.push({
      type: 'new_account_swarm',
      description: `${newAccounts.length}/${reports.length} reports from accounts <${NEW_ACCOUNT_THRESHOLD_DAYS} days old`,
      severity: Math.min(1, newAccounts.length / reports.length),
      involvedReporters: newAccounts.map((r) => r.reporterId),
    });
  }

  // --- 3. Unanimous agreement anomaly ---
  // Perfect agreement is suspicious when there are many reports
  if (reports.length >= MIN_REPORTS_FOR_GAMING_ANALYSIS) {
    const scamVotes = reports.filter((r) => r.isScam).length;
    const agreementRate = Math.max(scamVotes, reports.length - scamVotes) / reports.length;
    if (agreementRate >= SUSPICIOUS_AGREEMENT_RATE && reports.length >= 8) {
      signals.push({
        type: 'unanimous_agreement',
        description: `${(agreementRate * 100).toFixed(1)}% agreement across ${reports.length} reports is statistically anomalous`,
        severity: 0.6,
        involvedReporters: reports.map((r) => r.reporterId),
      });
    }
  }

  // --- 4. Low-accuracy reporter clustering ---
  // Multiple reporters with poor track records all filing reports
  const lowAccuracyReporters = reports.filter(
    (r) => r.reporterAccuracy < 0.4 && r.reporterTotalReports >= 5,
  );
  if (lowAccuracyReporters.length >= 3) {
    signals.push({
      type: 'low_accuracy_cluster',
      description: `${lowAccuracyReporters.length} reporters with <40% accuracy contributing to this target`,
      severity: Math.min(1, lowAccuracyReporters.length / 5),
      involvedReporters: lowAccuracyReporters.map((r) => r.reporterId),
    });
  }

  // --- 5. Single-target reporters ---
  // Reporters who only ever report one target are suspicious
  const singleTargetReporters = reports.filter(
    (r) => r.reporterTotalReports === 1,
  );
  if (
    singleTargetReporters.length >= 3 &&
    singleTargetReporters.length / reports.length > 0.6
  ) {
    signals.push({
      type: 'single_target_swarm',
      description: `${singleTargetReporters.length} reporters have only ever made this one report`,
      severity: Math.min(1, singleTargetReporters.length / reports.length),
      involvedReporters: singleTargetReporters.map((r) => r.reporterId),
    });
  }

  return signals;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Computes the reliability score for an individual reporter using
 * Bayesian inference and account quality factors.
 */
export function computeReporterReliability(
  report: CommunityReport,
): ReporterReliability {
  const bayesian = bayesianReliability(
    Math.round(report.reporterAccuracy * report.reporterTotalReports),
    report.reporterTotalReports,
  );

  const ageFactor = accountAgeFactor(report.reporterAccountAge);
  const volFactor = volumeFactor(report.reporterTotalReports);

  // Composite reliability: Bayesian base adjusted by account quality
  const reliabilityScore = bayesian * ageFactor * (0.5 + 0.5 * volFactor);

  // Flag as suspicious if very new + low accuracy + few reports
  const isSuspicious =
    report.reporterAccountAge < NEW_ACCOUNT_THRESHOLD_DAYS &&
    report.reporterAccuracy < 0.5 &&
    report.reporterTotalReports < 5;

  return {
    reporterId: report.reporterId,
    reliabilityScore: Math.round(reliabilityScore * 1000) / 1000,
    totalReports: report.reporterTotalReports,
    accurateReports: Math.round(report.reporterAccuracy * report.reporterTotalReports),
    averageAgreement: report.reporterAccuracy,
    accountAgeDays: report.reporterAccountAge,
    isSuspicious,
  };
}

/**
 * Detects coordinated gaming / false reporting patterns.
 * Returns gaming signals with severity scores and involved reporters.
 */
export function detectGaming(reports: CommunityReport[]): {
  gamingDetected: boolean;
  signals: GamingSignal[];
  overallSeverity: number;
} {
  const signals = detectGamingSignals(reports);
  const overallSeverity =
    signals.length > 0
      ? Math.min(1, signals.reduce((sum, s) => sum + s.severity, 0) / signals.length)
      : 0;

  return {
    gamingDetected: signals.some((s) => s.severity > 0.5),
    signals,
    overallSeverity,
  };
}

/**
 * Aggregates community reports into a single trust score using
 * weighted Wilson score intervals with temporal decay and reliability
 * weighting. Also runs anti-gaming detection.
 *
 * The trust score represents: "How confident are we that this target is a scam?"
 * 0 = probably safe, 1 = definitely scam.
 */
export function aggregateCommunityReports(
  reports: CommunityReport[],
): CommunityTrustResult {
  if (reports.length === 0) {
    return {
      trustScore: 0,
      confidenceLevel: 0,
      wilsonLower: 0,
      wilsonUpper: 0,
      totalReports: 0,
      weightedReports: 0,
      gamingDetected: false,
      gamingDetails: [],
      reportQuality: 'low',
      topReporterReliability: 0,
    };
  }

  const now = Date.now();

  // --- Step 1: Compute per-reporter reliability ---
  const reliabilities = reports.map((r) => computeReporterReliability(r));

  // --- Step 2: Compute weighted votes ---
  let weightedPositive = 0; // weighted "is scam" votes
  let weightedTotal = 0;

  for (let i = 0; i < reports.length; i++) {
    const report = reports[i];
    const reliability = reliabilities[i];

    // Combined weight: reliability * temporal decay
    const tWeight = temporalWeight(report.timestamp, now);
    const weight = reliability.reliabilityScore * tWeight;

    weightedTotal += weight;
    if (report.isScam) {
      weightedPositive += weight;
    }
  }

  // --- Step 3: Wilson score on weighted votes ---
  // Effective sample size (sum of weights acts as sample size)
  const effectiveN = Math.max(1, weightedTotal);
  const effectivePositive = weightedPositive;
  const wilson = wilsonScore(effectivePositive, effectiveN);

  // --- Step 4: Anti-gaming analysis ---
  const gaming = detectGaming(reports);

  // Dampen trust score if gaming detected
  let trustScore = wilson.center;
  if (gaming.gamingDetected) {
    // Reduce confidence proportional to gaming severity
    const dampFactor = 1 - gaming.overallSeverity * 0.6;
    trustScore *= dampFactor;
  }

  // --- Step 5: Confidence level ---
  // Based on effective sample size and reliability distribution
  const avgReliability =
    reliabilities.reduce((s, r) => s + r.reliabilityScore, 0) / reliabilities.length;
  const sampleFactor = Math.min(1, Math.log2(reports.length + 1) / 5);
  const confidenceLevel = Math.min(
    0.99,
    sampleFactor * 0.5 + avgReliability * 0.3 + (1 - (wilson.upper - wilson.lower)) * 0.2,
  );

  // --- Step 6: Report quality assessment ---
  let reportQuality: 'low' | 'medium' | 'high';
  if (avgReliability > 0.7 && reports.length >= 10 && !gaming.gamingDetected) {
    reportQuality = 'high';
  } else if (avgReliability > 0.4 && reports.length >= 5) {
    reportQuality = 'medium';
  } else {
    reportQuality = 'low';
  }

  // Top reporter reliability
  const topReporterReliability = Math.max(...reliabilities.map((r) => r.reliabilityScore));

  return {
    trustScore: Math.round(trustScore * 1000) / 1000,
    confidenceLevel: Math.round(confidenceLevel * 1000) / 1000,
    wilsonLower: Math.round(wilson.lower * 1000) / 1000,
    wilsonUpper: Math.round(wilson.upper * 1000) / 1000,
    totalReports: reports.length,
    weightedReports: Math.round(weightedTotal * 100) / 100,
    gamingDetected: gaming.gamingDetected,
    gamingDetails: gaming.signals.map((s) => `[${s.type}] ${s.description} (severity: ${s.severity.toFixed(2)})`),
    reportQuality,
    topReporterReliability: Math.round(topReporterReliability * 1000) / 1000,
  };
}
