// ============================================================================
// ScamShield Threat Trend Prediction Algorithm
// Proprietary algorithm: time-windowed frequency analysis, adaptive EMA,
// outbreak detection via z-score, and kinematic wave prediction.
// ============================================================================

import {
  ThreatCategory,
  ThreatLevel,
  TrendDataPoint,
  TrendVelocity,
  ThreatPrediction,
  ThreatIntelligenceResult,
} from './types';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FrequencyBucket {
  timestamp: number;
  count: number;
}

export interface TrendData {
  pattern: string;
  category: ThreatCategory;
  buckets: FrequencyBucket[];
  totalCount: number;
  windowMs: number;
}

export interface OutbreakAlert {
  pattern: string;
  category: ThreatCategory;
  zScore: number;
  velocity: number;
  acceleration: number;
  detectedAt: number;
  severity: 'watch' | 'warning' | 'critical';
  baselineRate: number;
  currentRate: number;
  estimatedPeakMs: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const WINDOWS = {
  HOUR: 60 * 60 * 1000,
  DAY: 24 * 60 * 60 * 1000,
  WEEK: 7 * 24 * 60 * 60 * 1000,
  MONTH: 30 * 24 * 60 * 60 * 1000,
} as const;

const BUCKET_SIZE_MS = 60 * 60 * 1000; // 1-hour granularity
const EMA_BASE_ALPHA = 0.3;
const OUTBREAK_Z_THRESHOLD = 2.0;
const CRITICAL_Z_THRESHOLD = 3.5;
const MIN_BUCKETS_FOR_TREND = 4;
const PREDICTION_HORIZON_MS = 72 * 60 * 60 * 1000;

// ---------------------------------------------------------------------------
// Internal Helpers
// ---------------------------------------------------------------------------

function bucketize(
  points: TrendDataPoint[],
  windowMs: number,
): Map<string, TrendData> {
  const now = Date.now();
  const cutoff = now - windowMs;
  const filtered = points.filter((p) => p.timestamp >= cutoff);
  const map = new Map<string, TrendData>();

  for (const pt of filtered) {
    const key = `${pt.category}::${pt.pattern}`;
    if (!map.has(key)) {
      map.set(key, {
        pattern: pt.pattern,
        category: pt.category,
        buckets: [],
        totalCount: 0,
        windowMs,
      });
    }
    const td = map.get(key)!;
    const bts = Math.floor(pt.timestamp / BUCKET_SIZE_MS) * BUCKET_SIZE_MS;
    const existing = td.buckets.find((b) => b.timestamp === bts);
    if (existing) {
      existing.count++;
    } else {
      td.buckets.push({ timestamp: bts, count: 1 });
    }
    td.totalCount++;
  }

  for (const td of map.values()) {
    td.buckets.sort((a, b) => a.timestamp - b.timestamp);
    // Fill gaps with zero-count buckets so EMA sees quiet periods
    if (td.buckets.length >= 2) {
      const filled: FrequencyBucket[] = [];
      const first = td.buckets[0].timestamp;
      const last = td.buckets[td.buckets.length - 1].timestamp;
      const bucketIndex = new Map(td.buckets.map((b) => [b.timestamp, b.count]));
      for (let t = first; t <= last; t += BUCKET_SIZE_MS) {
        filled.push({ timestamp: t, count: bucketIndex.get(t) ?? 0 });
      }
      td.buckets = filled;
    }
  }

  return map;
}

/**
 * Adaptive EMA: alpha scales with data density.
 * More data => trust recent observations more (higher alpha).
 * Sparse data => smooth aggressively (lower alpha).
 */
function computeEMA(buckets: FrequencyBucket[]): number {
  if (buckets.length === 0) return 0;
  const densityFactor = Math.min(1, buckets.length / 48); // normalize to ~2 days
  const alpha = EMA_BASE_ALPHA * (0.5 + 0.5 * densityFactor);
  let ema = buckets[0].count;
  for (let i = 1; i < buckets.length; i++) {
    ema = alpha * buckets[i].count + (1 - alpha) * ema;
  }
  return ema;
}

/**
 * Multi-window EMA: returns EMAs for each of the four standard windows,
 * computed on the appropriate suffix of the data.
 */
function multiWindowEMA(
  allBuckets: FrequencyBucket[],
): Record<string, number> {
  const now = Date.now();
  const windows: Record<string, number> = {};
  for (const [name, ms] of Object.entries(WINDOWS)) {
    const cutoff = now - ms;
    const subset = allBuckets.filter((b) => b.timestamp >= cutoff);
    windows[name] = computeEMA(subset);
  }
  return windows;
}

function meanAndStdDev(values: number[]): { mean: number; stdDev: number } {
  if (values.length === 0) return { mean: 0, stdDev: 0 };
  const mean = values.reduce((s, v) => s + v, 0) / values.length;
  const variance = values.reduce((s, v) => s + (v - mean) ** 2, 0) / values.length;
  return { mean, stdDev: Math.sqrt(variance) };
}

/**
 * Finite-difference velocity and acceleration over the most recent buckets.
 * Uses weighted recent window (last 8 buckets) for responsiveness.
 */
function derivatives(buckets: FrequencyBucket[]): {
  velocity: number;
  acceleration: number;
} {
  if (buckets.length < 2) return { velocity: 0, acceleration: 0 };

  const window = Math.min(buckets.length, 8);
  const recent = buckets.slice(-window);

  // First derivatives (velocity per bucket step)
  const velocities: number[] = [];
  for (let i = 1; i < recent.length; i++) {
    const dt = (recent[i].timestamp - recent[i - 1].timestamp) / BUCKET_SIZE_MS;
    if (dt > 0) {
      velocities.push((recent[i].count - recent[i - 1].count) / dt);
    }
  }

  // Exponentially weight recent velocities more
  let vWeightSum = 0;
  let vWeighted = 0;
  for (let i = 0; i < velocities.length; i++) {
    const w = Math.pow(1.5, i); // later entries have higher weight
    vWeighted += velocities[i] * w;
    vWeightSum += w;
  }
  const velocity = vWeightSum > 0 ? vWeighted / vWeightSum : 0;

  // Second derivatives (acceleration)
  const accels: number[] = [];
  for (let i = 1; i < velocities.length; i++) {
    accels.push(velocities[i] - velocities[i - 1]);
  }
  const acceleration =
    accels.length > 0 ? accels.reduce((s, a) => s + a, 0) / accels.length : 0;

  return { velocity, acceleration };
}

/**
 * Select adaptive window based on data density and recency.
 */
function selectAdaptiveWindow(data: TrendDataPoint[]): number {
  if (data.length === 0) return WINDOWS.WEEK;
  const sorted = [...data].sort((a, b) => a.timestamp - b.timestamp);
  const span = sorted[sorted.length - 1].timestamp - sorted[0].timestamp;
  const density = data.length / Math.max(1, span / BUCKET_SIZE_MS);

  if (density > 5) return WINDOWS.DAY;
  if (density > 2) return WINDOWS.WEEK;
  if (density > 0.3) return WINDOWS.WEEK;
  return WINDOWS.MONTH;
}

function velocityToThreatLevel(v: number): ThreatLevel {
  const abs = Math.abs(v);
  if (abs > 10) return 'CRITICAL';
  if (abs > 5) return 'HIGH';
  if (abs > 2) return 'MEDIUM';
  if (abs > 0.5) return 'LOW';
  return 'SAFE';
}

function zScoreToSeverity(z: number): 'watch' | 'warning' | 'critical' {
  if (z >= CRITICAL_Z_THRESHOLD) return 'critical';
  if (z >= OUTBREAK_Z_THRESHOLD + 0.75) return 'warning';
  return 'watch';
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Analyzes a scan history to compute velocity, acceleration, EMA, and
 * z-scores for every observed scam pattern. Returns results sorted by
 * absolute velocity descending.
 */
export function analyzeTrends(data: TrendDataPoint[]): TrendVelocity[] {
  const windowMs = selectAdaptiveWindow(data);
  const seriesMap = bucketize(data, windowMs);
  const results: TrendVelocity[] = [];

  for (const td of seriesMap.values()) {
    if (td.buckets.length < MIN_BUCKETS_FOR_TREND) continue;

    const ema = computeEMA(td.buckets);
    const { velocity, acceleration } = derivatives(td.buckets);
    const counts = td.buckets.map((b) => b.count);
    const { mean, stdDev } = meanAndStdDev(counts);
    const latestCount = td.buckets[td.buckets.length - 1].count;
    const zScore = stdDev > 0 ? (latestCount - mean) / stdDev : 0;

    results.push({
      pattern: td.pattern,
      category: td.category,
      velocity,
      acceleration,
      ema,
      isOutbreak: zScore >= OUTBREAK_Z_THRESHOLD,
      zScore,
    });
  }

  results.sort((a, b) => Math.abs(b.velocity) - Math.abs(a.velocity));
  return results;
}

/**
 * Detects outbreaks: patterns whose recent activity exceeds 2 standard
 * deviations above baseline. Returns detailed OutbreakAlert objects with
 * severity classification and estimated peak time.
 */
export function detectOutbreak(data: TrendDataPoint[]): OutbreakAlert[] {
  const windowMs = selectAdaptiveWindow(data);
  const seriesMap = bucketize(data, windowMs);
  const alerts: OutbreakAlert[] = [];

  for (const td of seriesMap.values()) {
    if (td.buckets.length < MIN_BUCKETS_FOR_TREND) continue;

    const counts = td.buckets.map((b) => b.count);
    const { mean, stdDev } = meanAndStdDev(counts);
    const latestCount = td.buckets[td.buckets.length - 1].count;
    const zScore = stdDev > 0 ? (latestCount - mean) / stdDev : 0;

    if (zScore < OUTBREAK_Z_THRESHOLD) continue;

    const { velocity, acceleration } = derivatives(td.buckets);

    // Estimate when the outbreak will peak using kinematic model
    let estimatedPeakMs: number;
    if (acceleration < -0.01 && velocity > 0) {
      // Decelerating: peak when velocity hits zero => t = -v/a
      const bucketsUntilPeak = -velocity / acceleration;
      estimatedPeakMs = Math.min(bucketsUntilPeak * BUCKET_SIZE_MS, PREDICTION_HORIZON_MS);
    } else if (velocity > 0) {
      // Still accelerating or constant: peak beyond horizon
      estimatedPeakMs = PREDICTION_HORIZON_MS;
    } else {
      // Already declining
      estimatedPeakMs = 0;
    }

    alerts.push({
      pattern: td.pattern,
      category: td.category,
      zScore,
      velocity,
      acceleration,
      detectedAt: Date.now(),
      severity: zScoreToSeverity(zScore),
      baselineRate: mean,
      currentRate: latestCount,
      estimatedPeakMs,
    });
  }

  alerts.sort((a, b) => b.zScore - a.zScore);
  return alerts;
}

/**
 * Predicts the next wave of scam activity by extrapolating current
 * velocity and acceleration using a kinematic model.
 * Only predicts for rising patterns (positive velocity).
 */
export function predictNextWave(data: TrendDataPoint[]): ThreatPrediction[] {
  const windowMs = selectAdaptiveWindow(data);
  const seriesMap = bucketize(data, windowMs);
  const predictions: ThreatPrediction[] = [];

  for (const td of seriesMap.values()) {
    if (td.buckets.length < MIN_BUCKETS_FOR_TREND) continue;

    const { velocity, acceleration } = derivatives(td.buckets);
    if (velocity <= 0) continue;

    const counts = td.buckets.map((b) => b.count);
    const { mean, stdDev } = meanAndStdDev(counts);
    const latestCount = td.buckets[td.buckets.length - 1].count;
    const zScore = stdDev > 0 ? (latestCount - mean) / stdDev : 0;

    // Kinematic peak estimation
    let predictedPeakTime: number;
    if (acceleration < -0.01) {
      const bucketsUntilPeak = -velocity / acceleration;
      predictedPeakTime = Math.min(bucketsUntilPeak * BUCKET_SIZE_MS, PREDICTION_HORIZON_MS);
    } else {
      predictedPeakTime = PREDICTION_HORIZON_MS;
    }

    // Multi-factor confidence calculation
    const dataDensity = Math.min(1, td.buckets.length / 24);
    const zFactor = Math.min(1, Math.abs(zScore) / 4);
    const consistencyBonus = velocity > 0 && acceleration >= 0 ? 0.85 : 0.5;
    const multiWindowEmas = multiWindowEMA(td.buckets);
    // Short-term EMA > long-term EMA indicates genuine uptrend
    const trendAlignment =
      multiWindowEmas.HOUR > multiWindowEmas.WEEK ? 0.9 : 0.4;

    const confidence = Math.min(
      0.95,
      dataDensity * 0.25 + zFactor * 0.25 + consistencyBonus * 0.25 + trendAlignment * 0.25,
    );

    predictions.push({
      category: td.category,
      pattern: td.pattern,
      confidence,
      predictedPeakTime,
      currentVelocity: velocity,
      riskLevel: velocityToThreatLevel(velocity),
    });
  }

  predictions.sort((a, b) => b.confidence - a.confidence);
  return predictions;
}

/**
 * Full threat intelligence generation: combines trend analysis, outbreak
 * detection, and wave prediction into a single intelligence report.
 */
export function generateThreatIntelligence(
  data: TrendDataPoint[],
): ThreatIntelligenceResult {
  const start = performance.now();
  const windowMs = selectAdaptiveWindow(data);

  const allTrends = analyzeTrends(data);
  const outbreaks = allTrends.filter((t) => t.isOutbreak);
  const predictions = predictNextWave(data);

  // Aggregate by category
  const categoryAgg = new Map<ThreatCategory, { velocity: number; count: number }>();
  for (const trend of allTrends) {
    const prev = categoryAgg.get(trend.category);
    if (prev) {
      prev.velocity += Math.abs(trend.velocity);
      prev.count++;
    } else {
      categoryAgg.set(trend.category, {
        velocity: Math.abs(trend.velocity),
        count: 1,
      });
    }
  }

  const trendingCategories = Array.from(categoryAgg.entries())
    .map(([category, info]) => ({ category, velocity: info.velocity, count: info.count }))
    .sort((a, b) => b.velocity - a.velocity);

  // Emerging: rising but not yet outbreak
  const emergingPatterns = allTrends.filter(
    (t) => t.velocity > 0.2 && !t.isOutbreak,
  );

  return {
    trendingCategories,
    emergingPatterns,
    outbreaks,
    predictions,
    analysisWindowMs: windowMs,
    dataPointCount: data.length,
    generatedAt: Date.now(),
  };
}
