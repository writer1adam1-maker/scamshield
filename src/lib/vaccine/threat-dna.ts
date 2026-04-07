// ============================================================================
// Threat DNA Engine
// Generates a compact genetic fingerprint from any scam/fraud content.
// DNA is a 24-byte hex string encoding 12 threat dimensions at 0-15 intensity.
// Two DNAs can be compared via Hamming distance to detect scam mutations.
// ============================================================================

import { scanPatternCounts } from "@/lib/algorithms/pattern-engine";
import type { LinguisticDeceptionResult } from "@/lib/algorithms/types";

// ---------------------------------------------------------------------------
// 12 DNA dimensions (2 hex chars each = 24 char string total)
// ---------------------------------------------------------------------------
export interface ThreatDNA {
  hex: string;          // 24-char hex fingerprint
  dimensions: DNADimension[];
  dominantStrand: string;   // name of strongest dimension
  mutation: MutationClass;
  generatedAt: number;
}

export interface DNADimension {
  name: string;
  intensity: number;    // 0-15 (nibble)
  label: string;
}

export type MutationClass =
  | "NOVEL"       // first time seen
  | "VARIANT"     // same family, slightly mutated
  | "CLONE"       // near-identical to known threat
  | "EVOLVED"     // known threat, new capabilities added
  | "SYNTHETIC";  // machine-generated scam content

// In-memory known DNA bank (session-scoped)
const DNA_BANK = new Map<string, { dna: ThreatDNA; seenAt: number }>();

// ---------------------------------------------------------------------------
// Core extraction — maps text signals → 12 dimensions
// ---------------------------------------------------------------------------

export function generateThreatDNA(
  text: string,
  linguisticResult: LinguisticDeceptionResult
): ThreatDNA {
  const patternCounts = scanPatternCounts(text);
  const tactics = linguisticResult.deceptionTactics;

  // Helper: count tactics in a category
  const tacticScore = (cat: string) =>
    tactics.filter((t) => t.category === cat)
           .reduce((s, t) => s + t.severity, 0);

  // Helper: pattern group total → 0-15 intensity
  const groupIntensity = (groups: string[]): number => {
    const total = groups.reduce((s, g) => s + (patternCounts[g] ?? 0), 0);
    return Math.min(15, Math.round(total * 1.5));
  };

  // Helper: score → 0-15
  const scale = (v: number, max = 1) => Math.min(15, Math.round((v / max) * 15));

  const dims: DNADimension[] = [
    {
      name: "AUTHORITY",
      label: "Authority Faking",
      intensity: scale(linguisticResult.authorityFakingScore + tacticScore("authority"), 2),
    },
    {
      name: "URGENCY",
      label: "Urgency / Pressure",
      intensity: groupIntensity(["urgency"]) + scale(tacticScore("urgency"), 1) >> 1,
    },
    {
      name: "FEAR",
      label: "Fear Exploitation",
      intensity: scale(tacticScore("fear"), 1),
    },
    {
      name: "GREED",
      label: "Greed Exploitation",
      intensity: scale(tacticScore("greed") + tacticScore("reciprocity"), 2),
    },
    {
      name: "ISOLATION",
      label: "Isolation Tactics",
      intensity: scale(linguisticResult.isolationAttemptScore + tacticScore("isolation"), 2),
    },
    {
      name: "FINANCIAL",
      label: "Financial Attack",
      intensity: groupIntensity(["financial", "crypto_investment", "payment_fraud", "elder_fraud"]),
    },
    {
      name: "PHISHING",
      label: "Phishing / Credential Theft",
      intensity: groupIntensity(["phishing", "brand_impersonation", "government_impersonation"]),
    },
    {
      name: "TECH",
      label: "Tech Deception",
      intensity: groupIntensity(["tech_support", "malware_distribution", "fake_antivirus"]),
    },
    {
      name: "CRYPTO",
      label: "Crypto / Investment Fraud",
      intensity: groupIntensity(["crypto_investment", "pig_butchering"]),
    },
    {
      name: "ROMANCE",
      label: "Romance / Grooming",
      intensity: groupIntensity(["romance"]),
    },
    {
      name: "SOCIAL_ENG",
      label: "Social Engineering",
      intensity: scale(linguisticResult.manipulationScore, 1),
    },
    {
      name: "DELIVERY",
      label: "Package / Delivery Scam",
      intensity: groupIntensity(["package_delivery", "smishing"]),
    },
  ];

  // Clamp all to 0-15
  for (const d of dims) d.intensity = Math.max(0, Math.min(15, d.intensity));

  // Build hex string
  const hex = dims.map((d) => d.intensity.toString(16)).join("").toUpperCase();

  // Dominant strand
  const dominant = dims.reduce((best, d) => d.intensity > best.intensity ? d : best);

  // Mutation classification
  const mutation = classifyMutation(hex);

  // Bank this DNA
  DNA_BANK.set(hex, { dna: { hex, dimensions: dims, dominantStrand: dominant.name, mutation, generatedAt: Date.now() }, seenAt: Date.now() });

  return { hex, dimensions: dims, dominantStrand: dominant.name, mutation, generatedAt: Date.now() };
}

// ---------------------------------------------------------------------------
// Hamming distance between two DNA hex strings (nibble-level)
// Returns 0 (identical) to 12 (completely different)
// ---------------------------------------------------------------------------

export function dnaHammingDistance(a: string, b: string): number {
  if (a.length !== b.length) return 12;
  let distance = 0;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) distance++;
  }
  return distance;
}

export function dnaSimilarity(a: string, b: string): number {
  const dist = dnaHammingDistance(a, b);
  return 1 - dist / Math.max(a.length, 1);
}

// ---------------------------------------------------------------------------
// Classify mutation by comparing to known DNA bank
// ---------------------------------------------------------------------------

function classifyMutation(hex: string): MutationClass {
  if (DNA_BANK.size === 0) return "NOVEL";

  let closestDistance = Infinity;

  for (const [known] of DNA_BANK) {
    if (known === hex) continue;
    const dist = dnaHammingDistance(hex, known);
    if (dist < closestDistance) closestDistance = dist;
  }

  if (closestDistance === Infinity) return "NOVEL";
  if (closestDistance === 0) return "CLONE";
  if (closestDistance <= 2) return "VARIANT";
  if (closestDistance <= 5) return "EVOLVED";

  // Check for machine-generation pattern: very uniform intensity across dimensions
  const values = hex.split("").map((c) => parseInt(c, 16));
  const avg = values.reduce((s, v) => s + v, 0) / values.length;
  const variance = values.reduce((s, v) => s + (v - avg) ** 2, 0) / values.length;
  if (variance < 1.5 && avg > 3) return "SYNTHETIC";

  return "NOVEL";
}

// ---------------------------------------------------------------------------
// DNA visual rendering helpers
// ---------------------------------------------------------------------------

export function dnaStrandLabel(mutation: MutationClass): string {
  switch (mutation) {
    case "CLONE":     return "Known Threat Clone";
    case "VARIANT":   return "Known Threat Variant";
    case "EVOLVED":   return "Evolved Threat Family";
    case "SYNTHETIC": return "AI-Generated Scam";
    case "NOVEL":     return "Novel Threat";
  }
}

export function dnaSegmentColor(intensity: number): string {
  if (intensity >= 12) return "bg-critical/80 text-white";
  if (intensity >= 8)  return "bg-danger/70 text-white";
  if (intensity >= 5)  return "bg-caution/60 text-black";
  if (intensity >= 2)  return "bg-shield/40 text-white";
  return "bg-slate-deep/40 text-text-muted";
}
