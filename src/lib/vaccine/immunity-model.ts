// ============================================================================
// Immunity Model
// Models how "immune" a user is to a specific threat after scanning.
// Uses an exponential decay model: immunity decays faster for critical threats
// because attackers mutate faster and the user's guard drops sooner.
//
// ImmunityProfile:
//   strength   — current immunity level 0-100
//   half_life  — time until immunity drops to 50% (ms)
//   peakAt     — when full immunity is reached (ms from scan)
//   boosterDue — when to rescan for full protection
//   tier       — NAIVE | EXPOSED | PARTIAL | IMMUNE | VETERAN
// ============================================================================

export type ImmunityTier =
  | "NAIVE"     // never seen this type of threat
  | "EXPOSED"   // seen it, no protection built
  | "PARTIAL"   // some immunity, still vulnerable
  | "IMMUNE"    // full protection
  | "VETERAN";  // seen many variants, highly resistant

export interface ImmunityProfile {
  strength: number;        // 0-100 (current immune strength)
  peakStrength: number;    // max possible strength for this threat
  halfLifeMs: number;      // decay half-life in ms
  tier: ImmunityTier;
  boosterDueAt: number;    // timestamp when booster is needed
  exposureCount: number;   // total times this threat class seen
  decayRateLabel: string;  // human-readable decay speed
  antibodies: Antibody[];  // what specific defenses were generated
}

export interface Antibody {
  dimension: string;       // which DNA dimension this antibody targets
  strength: number;        // 0-100
  targetLabel: string;     // human-readable label
}

// ---------------------------------------------------------------------------
// Half-life config by threat level
// Critical threats decay fast (attackers mutate quickly)
// ---------------------------------------------------------------------------
const HALF_LIFE_MS: Record<string, number> = {
  safe:     7  * 24 * 60 * 60 * 1000,  // 7 days
  low:      3  * 24 * 60 * 60 * 1000,  // 3 days
  medium:   24 * 60 * 60 * 1000,       // 24 hours
  high:     12 * 60 * 60 * 1000,       // 12 hours
  critical: 4  * 60 * 60 * 1000,       // 4 hours
};

const DECAY_LABELS: Record<string, string> = {
  safe:     "Very slow decay (7 days)",
  low:      "Slow decay (3 days)",
  medium:   "Moderate decay (24h)",
  high:     "Fast decay (12h)",
  critical: "Rapid decay (4h) — threat mutates quickly",
};

// Exposure counter: tracks how many times this threat class has been seen
const exposureCounter = new Map<string, number>();

// ---------------------------------------------------------------------------
// Build immunity profile after scanning
// ---------------------------------------------------------------------------
export function buildImmunityProfile(
  threatLevel: string,
  threatScore: number,
  dnaHex: string,
  dominantDimensions: Array<{ name: string; intensity: number; label: string }>
): ImmunityProfile {
  const level = threatLevel.toLowerCase();
  const halfLifeMs = HALF_LIFE_MS[level] ?? HALF_LIFE_MS.medium;

  // Track exposure
  const exposureKey = dnaHex.slice(0, 6); // first 3 bytes = threat family
  const exposureCount = (exposureCounter.get(exposureKey) ?? 0) + 1;
  exposureCounter.set(exposureKey, exposureCount);

  // Peak strength: higher threat → higher immunity built (you learn more from dangerous exposure)
  // But safe content → minimal immunity needed
  const peakStrength = level === "safe" ? 30
    : level === "low"      ? 55
    : level === "medium"   ? 72
    : level === "high"     ? 88
    : 97; // critical

  // Current strength starts at peak (just vaccinated)
  const strength = peakStrength;

  // Booster due when immunity drops to 30% of peak (using half-life decay)
  // t = -halfLife * log2(target/peak)
  const targetFraction = 0.30;
  const decayTimeMs = -halfLifeMs * Math.log2(targetFraction);
  const boosterDueAt = Date.now() + decayTimeMs;

  // Tier classification
  const tier = classifyTier(strength, exposureCount);

  // Generate antibodies: top N dimensions with intensity > 3
  const antibodies: Antibody[] = dominantDimensions
    .filter((d) => d.intensity > 3)
    .sort((a, b) => b.intensity - a.intensity)
    .slice(0, 5)
    .map((d) => ({
      dimension: d.name,
      strength: Math.round((d.intensity / 15) * 100),
      targetLabel: d.label,
    }));

  return {
    strength,
    peakStrength,
    halfLifeMs,
    tier,
    boosterDueAt,
    exposureCount,
    decayRateLabel: DECAY_LABELS[level] ?? "Unknown decay rate",
    antibodies,
  };
}

// ---------------------------------------------------------------------------
// Compute current immunity strength given time elapsed since vaccination
// ---------------------------------------------------------------------------
export function computeCurrentImmunity(
  peakStrength: number,
  halfLifeMs: number,
  vaccineAppliedAt: number
): number {
  const elapsed = Date.now() - vaccineAppliedAt;
  if (elapsed <= 0) return peakStrength;
  const decayed = peakStrength * Math.pow(0.5, elapsed / halfLifeMs);
  return Math.max(0, Math.round(decayed));
}

function classifyTier(strength: number, exposures: number): ImmunityTier {
  if (exposures === 0) return "NAIVE";
  if (strength < 30) return "EXPOSED";
  if (strength < 60) return "PARTIAL";
  if (exposures >= 5) return "VETERAN";
  return "IMMUNE";
}

export function tierLabel(tier: ImmunityTier): string {
  switch (tier) {
    case "NAIVE":   return "No immunity — first exposure";
    case "EXPOSED": return "Exposed — weak immunity forming";
    case "PARTIAL": return "Partial immunity — some protection";
    case "IMMUNE":  return "Full immunity — protected";
    case "VETERAN": return "Veteran immunity — highly resistant";
  }
}

export function tierColor(tier: ImmunityTier): string {
  switch (tier) {
    case "NAIVE":   return "text-text-muted";
    case "EXPOSED": return "text-caution";
    case "PARTIAL": return "text-caution";
    case "IMMUNE":  return "text-safe";
    case "VETERAN": return "text-shield";
  }
}
