// ============================================================================
// VERIDICT Layer 5: Linguistic Deception Detector
// Analyzes psychological manipulation tactics used in scam communications.
// Based on Cialdini's influence principles + FBI behavioral analysis patterns.
// ============================================================================

import { LinguisticDeceptionResult, DeceptionTactic } from './types';

// ---------------------------------------------------------------------------
// Deception tactic definitions
// ---------------------------------------------------------------------------

interface TacticPattern {
  id: string;
  name: string;
  category: DeceptionTactic['category'];
  patterns: RegExp[];
  severity: number;
  description: string;
}

const DECEPTION_TACTICS: TacticPattern[] = [

  // ── AUTHORITY FAKING ─────────────────────────────────────────────────────

  {
    id: 'AUTH-001',
    name: 'Official institution impersonation',
    category: 'authority',
    patterns: [
      /\b(department|bureau|division|agency|office)\s*(of|for)\b/i,
      /\b(official\s*(notice|notification|communication|letter|correspondence))\b/i,
      /\b(this\s*(is\s*an?\s*)?(official|authorized|verified|certified)\s*(message|notice|communication))\b/i,
    ],
    severity: 0.75,
    description: 'Uses official-sounding institutional language to appear authoritative',
  },
  {
    id: 'AUTH-002',
    name: 'Legal threat language',
    category: 'authority',
    patterns: [
      /\b(legal\s*(action|proceedings?|consequence|obligation)|lawfully|pursuant\s*to)\b/i,
      /\b(federal\s*(law|regulation|statute|code))\b/i,
      /\b(violation\s*(of|under)\s*(federal|state|local))\b/i,
      /\b(civil|criminal)\s*(liability|penalty|charge|prosecution)\b/i,
    ],
    severity: 0.80,
    description: 'Invokes legal terminology to intimidate and pressure compliance',
  },
  {
    id: 'AUTH-003',
    name: 'Badge/credential assertion',
    category: 'authority',
    patterns: [
      /\b(badge\s*number|agent\s*id|officer|investigator|detective|inspector)\b.{0,40}\b(id|#|number|\d+)\b/i,
      /\b(case\s*(number|#|id)|ref(erence)?\s*(number|#|id)|ticket\s*#)\b/i,
      /\b(badge|credential|identification|clearance)\b.{0,30}\b\d+\b/i,
    ],
    severity: 0.70,
    description: 'Provides fake badge/case numbers to appear legitimate',
  },
  {
    id: 'AUTH-004',
    name: 'Fake endorsement/certification',
    category: 'authority',
    patterns: [
      /\b(endorsed\s*by|certified\s*by|approved\s*by|in\s*partnership\s*with)\b.{0,30}\b(government|bank|official|federal)\b/i,
      /\b(as\s*(seen|featured)\s*(on|in))\b/i,
      /\b(accredited|licensed|registered|insured)\b.{0,40}\b(invest|fund|platform|firm)\b/i,
    ],
    severity: 0.65,
    description: 'Claims fake endorsements from trusted institutions',
  },

  // ── URGENCY / SCARCITY ────────────────────────────────────────────────────

  {
    id: 'URG-001',
    name: 'Artificial time pressure',
    category: 'urgency',
    patterns: [
      /\b(within\s*\d+\s*(hours?|minutes?|days?))\b/i,
      /\b(act\s*now|immediately|right\s*away|don'?t\s*delay|no\s*time\s*to\s*waste)\b/i,
      /\b(expires?|expiring|deadline|last\s*chance|final\s*(notice|warning|call))\b.{0,30}\b(today|now|soon|\d+\s*(hours?|days?))\b/i,
      /\b(limited\s*time|time[- ]sensitive|urgent|asap)\b/i,
    ],
    severity: 0.65,
    description: 'Creates artificial time pressure to prevent careful deliberation',
  },
  {
    id: 'URG-002',
    name: 'Scarcity manipulation',
    category: 'urgency',
    patterns: [
      /\b(limited\s*(spots?|slots?|seats?|openings?|availability|supply))\b/i,
      /\b(only\s*\d+\s*(left|remaining|available|spots?))\b/i,
      /\b(exclusive|once[- ]in[- ]a[- ]lifetime|rare|one[- ]time\s*(offer|opportunity))\b/i,
    ],
    severity: 0.60,
    description: 'Uses false scarcity to pressure immediate action',
  },

  // ── FEAR TACTICS ──────────────────────────────────────────────────────────

  {
    id: 'FEAR-001',
    name: 'Arrest / criminal threat',
    category: 'fear',
    patterns: [
      /\b(arrest(ed)?|handcuff|jail|prison|warrant|custody|detain)\b/i,
      /\b(criminal\s*(record|charge|case|investigation|prosecution))\b/i,
      /\b(will\s*be\s*(arrested|prosecuted|charged|detained|jailed))\b/i,
    ],
    severity: 0.90,
    description: 'Threatens arrest or criminal action — never done legitimately by phone/text',
  },
  {
    id: 'FEAR-002',
    name: 'Financial ruin threat',
    category: 'fear',
    patterns: [
      /\b(bank\s*(account\s*)?(frozen|seized|garnished|levied))\b/i,
      /\b(assets?\s*(frozen|seized|confiscated|forfeited))\b/i,
      /\b(wage\s*(garnishment|garnish|levy))\b/i,
      /\b(credit\s*(ruin(ed)?|destroy|damage|score\s*drop))\b/i,
    ],
    severity: 0.85,
    description: 'Threatens financial ruin, asset seizure or account freeze',
  },
  {
    id: 'FEAR-003',
    name: 'Identity exposure threat',
    category: 'fear',
    patterns: [
      /\b(your\s*(identity|personal\s*information|data)\s*(compromised?|stolen|exposed|leaked))\b/i,
      /\b(dark\s*web|hacked|breached|leaked)\b.{0,40}\b(your|account|data|password|ssn)\b/i,
      /\b(your\s*(ssn|social\s*security)\s*(is\s*being|has\s*been)\s*(used|stolen|misused))\b/i,
    ],
    severity: 0.80,
    description: 'Threatens that personal identity or data has been compromised',
  },

  // ── GREED / REWARD ────────────────────────────────────────────────────────

  {
    id: 'GRD-001',
    name: 'Guaranteed high returns',
    category: 'greed',
    patterns: [
      /\b(guaranteed?|assured|certain|risk[- ]?free)\b.{0,30}\b(return|profit|income|gain|earn)\b/i,
      /\b(no\s*risk|zero\s*risk|100%\s*(safe|secure|guaranteed))\b/i,
      /\b(\d+%|double|triple|10x|100x)\b.{0,20}\b(return|profit|gain|earn|per\s*(day|week|month))\b/i,
    ],
    severity: 0.85,
    description: 'Promises guaranteed returns or unrealistic profits',
  },
  {
    id: 'GRD-002',
    name: 'Unexpected windfall',
    category: 'greed',
    patterns: [
      /\b(you'?ve?\s*(been\s*)?(selected|chosen|won|awarded|qualified|eligible))\b/i,
      /\b(unclaimed\s*(funds?|money|inheritance|prize|reward))\b/i,
      /\b(free\s*money|free\s*cash|no\s*strings\s*attached|nothing\s*to\s*(buy|pay|owe))\b/i,
    ],
    severity: 0.75,
    description: 'Presents unexpected windfall or special selection',
  },

  // ── ISOLATION ─────────────────────────────────────────────────────────────

  {
    id: 'ISO-001',
    name: 'Secrecy demand',
    category: 'isolation',
    patterns: [
      /\b(don'?t\s*(tell|share|discuss|mention)\s*(anyone|anybody|your\s*(family|friends?|spouse|husband|wife)))\b/i,
      /\b(keep\s*(this\s*)?(secret|confidential|between\s*us|private|quiet))\b/i,
      /\b(just\s*(between\s*us|you\s*and\s*(me|I)))\b/i,
    ],
    severity: 0.90,
    description: 'Demands secrecy to prevent victim from consulting others',
  },
  {
    id: 'ISO-002',
    name: 'Warn against contacting authorities',
    category: 'isolation',
    patterns: [
      /\b(do\s*not\s*(contact|call|notify|report)\s*(the\s*)?(police|fbi|authorities|bank|irs))\b/i,
      /\b(if\s*(you\s*)?(call|contact|notify|tell)\s*(anyone|police|bank))\b/i,
      /\b(avoid\s*(contact|calling|notifying))\b.{0,20}\b(police|authorities|bank)\b/i,
    ],
    severity: 0.95,
    description: 'Discourages contacting authorities — strongest isolation indicator',
  },
  {
    id: 'ISO-003',
    name: 'Third party manipulation',
    category: 'isolation',
    patterns: [
      /\b(your\s*(bank|family|friends?)\s*(doesn'?t\s*understand|will\s*interfere|won'?t\s*help))\b/i,
      /\b(banks?\s*(block|stop|interfere|flag)\s*(these\s*)?(transfer|transaction|payment))\b/i,
      /\b(ignore\s*(warnings?|alerts?)\s*(from\s*)?(your\s*)?(bank|account))\b/i,
    ],
    severity: 0.85,
    description: 'Discredits legitimate third parties (bank, family) who might intervene',
  },

  // ── RECIPROCITY ───────────────────────────────────────────────────────────

  {
    id: 'RCP-001',
    name: 'Gift/favor before ask',
    category: 'reciprocity',
    patterns: [
      /\b(free\s*(gift|sample|trial|bonus)|no\s*charge\s*(for\s*now|today|this\s*time))\b.{0,100}\b(but|however|just|only)\b/i,
      /\b(we'?ve?\s*(already|just)\s*(sent|transferred|released|processed))\b.{0,40}\b(but|however|need|require)\b/i,
    ],
    severity: 0.70,
    description: 'Offers gift/favor to trigger reciprocity obligation',
  },

  // ── SOCIAL PROOF ─────────────────────────────────────────────────────────

  {
    id: 'SOC-001',
    name: 'False testimonials',
    category: 'social_proof',
    patterns: [
      /\b(thousands?\s*(of\s*)?(people|customers|users|members)\s*(have\s*)?(already|joined|invested|earned))\b/i,
      /\b(join\s*(over\s*)?\d+(,\d+)*\s*(satisfied\s*)?(customers?|members?|users?))\b/i,
      /\b(testimonial|success\s*stor|real\s*people|real\s*results|real\s*winners?)\b/i,
    ],
    severity: 0.60,
    description: 'Uses fake social proof / testimonials to build false credibility',
  },
  {
    id: 'SOC-002',
    name: 'Celebrity / expert endorsement',
    category: 'social_proof',
    patterns: [
      /\b(elon\s*musk|oprah|warren\s*buffett|bezos|zuckerberg|bill\s*gates)\b.{0,60}\b(invest|endorse|recommend|partner|back|crypto|coin)\b/i,
      /\b(endorsed?\s*by)\b.{0,40}\b(expert|millionaire|billionaire|celebrity|influencer)\b/i,
    ],
    severity: 0.88,
    description: 'False celebrity endorsement for investment/crypto scam',
  },
];

// ---------------------------------------------------------------------------
// Score computation helpers
// ---------------------------------------------------------------------------

function scoreAuthority(tactics: DeceptionTactic[]): number {
  const authTactics = tactics.filter((t) =>
    t.tacticId.startsWith('AUTH')
  );
  if (authTactics.length === 0) return 0;
  return Math.min(1, authTactics.reduce((sum, t) => sum + t.severity, 0) / 1.5);
}

function scoreEmotional(tactics: DeceptionTactic[]): number {
  const emotional = tactics.filter((t) =>
    t.tacticId.startsWith('FEAR') || t.tacticId.startsWith('GRD') || t.tacticId.startsWith('URG')
  );
  if (emotional.length === 0) return 0;
  return Math.min(1, emotional.reduce((sum, t) => sum + t.severity, 0) / 2.0);
}

function scoreIsolation(tactics: DeceptionTactic[]): number {
  const iso = tactics.filter((t) => t.tacticId.startsWith('ISO'));
  if (iso.length === 0) return 0;
  return Math.min(1, iso.reduce((sum, t) => sum + t.severity, 0) / 1.5);
}

function scoreManipulation(tactics: DeceptionTactic[]): number {
  if (tactics.length === 0) return 0;
  const totalSeverity = tactics.reduce((sum, t) => sum + t.severity, 0);
  // Synergy bonus: multiple tactic categories together is much more suspicious
  const uniqueCategories = new Set(tactics.map((t) => t.category)).size;
  const synergyBonus = uniqueCategories >= 3 ? 0.20 : uniqueCategories === 2 ? 0.10 : 0;
  return Math.min(1, totalSeverity / (DECEPTION_TACTICS.length * 0.4) + synergyBonus);
}

// ---------------------------------------------------------------------------
// Main export
// ---------------------------------------------------------------------------

export function detectLinguisticDeception(text: string): LinguisticDeceptionResult {
  const startTime = performance.now();
  const matchedTactics: DeceptionTactic[] = [];
  const details: string[] = [];
  const flags: string[] = [];

  for (const tactic of DECEPTION_TACTICS) {
    for (const pattern of tactic.patterns) {
      const match = text.match(pattern);
      if (match) {
        matchedTactics.push({
          tacticId: tactic.id,
          tacticName: tactic.name,
          category: tactic.category,
          evidence: match[0].substring(0, 100),
          severity: tactic.severity,
        });
        flags.push(`[${tactic.category.toUpperCase()}] ${tactic.name}`);
        details.push(`${tactic.id}: "${match[0].substring(0, 80)}" — ${tactic.description}`);
        break; // one match per tactic is enough
      }
    }
  }

  const manipulationScore = scoreManipulation(matchedTactics);
  const authorityFakingScore = scoreAuthority(matchedTactics);
  const emotionalExploitScore = scoreEmotional(matchedTactics);
  const isolationAttemptScore = scoreIsolation(matchedTactics);
  const reciprocityScore = matchedTactics.some((t) => t.tacticId.startsWith('RCP'))
    ? matchedTactics.filter((t) => t.tacticId.startsWith('RCP')).reduce((s, t) => s + t.severity, 0)
    : 0;

  // Layer 5 score: weighted composite
  const rawScore =
    manipulationScore * 0.40 +
    isolationAttemptScore * 0.30 +
    authorityFakingScore * 0.15 +
    emotionalExploitScore * 0.10 +
    Math.min(1, reciprocityScore) * 0.05;

  const score = Math.round(Math.min(100, rawScore * 100) * 100) / 100;

  return {
    score,
    deceptionTactics: matchedTactics,
    manipulationScore,
    authorityFakingScore,
    emotionalExploitScore,
    isolationAttemptScore,
    reciprocityScore: Math.min(1, reciprocityScore),
    flags: Array.from(new Set(flags)),
    details,
    processingTimeMs: Math.round((performance.now() - startTime) * 100) / 100,
  };
}
