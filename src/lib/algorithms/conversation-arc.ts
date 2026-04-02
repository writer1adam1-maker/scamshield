// ============================================================================
// Conversation Arc Analyzer — Grooming Phase Detection Engine
// ============================================================================
// Detects pig-butchering, romance scam, and social engineering grooming patterns
// in conversation exports. Supports WhatsApp, Telegram, Signal, SMS, and generic formats.

export enum GroomingPhase {
  RAPPORT_BUILDING    = 'RAPPORT_BUILDING',
  TRUST_DEVELOPMENT   = 'TRUST_DEVELOPMENT',
  ISOLATION           = 'ISOLATION',
  INVESTMENT_HOOK     = 'INVESTMENT_HOOK',
  PRESSURE_ESCALATION = 'PRESSURE_ESCALATION',
  COLLECTION          = 'COLLECTION',
}

export type ArcType =
  | 'PIG_BUTCHERING'
  | 'ROMANCE_SCAM'
  | 'INVESTMENT_FRAUD'
  | 'ADVANCE_FEE'
  | 'GENERIC_GROOMING'
  | 'BENIGN';

// ---------------------------------------------------------------------------
// Data interfaces
// ---------------------------------------------------------------------------

export interface ParsedMessage {
  index: number;
  timestamp: Date | null;
  sender: string;
  content: string;
}

export interface PhaseSignal {
  phase: GroomingPhase;
  patternLabel: string;
  matchedText: string;
  weight: number;
  messageIndex: number;
  sender: string;
}

export interface PhaseResult {
  phase: GroomingPhase;
  label: string;
  description: string;
  color: string;
  score: number;
  present: boolean;
  signals: PhaseSignal[];
  topFindings: string[];
}

export interface TimelineSegment {
  segmentIndex: number;
  startMessage: number;
  endMessage: number;
  dominantPhase: GroomingPhase | null;
  riskLevel: number;
}

export interface ConversationArcResult {
  overallRisk: number;
  threatLevel: 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  arcType: ArcType;
  arcLabel: string;
  arcDescription: string;
  phases: PhaseResult[];
  messageCount: number;
  senderCount: number;
  senders: string[];
  timeline: TimelineSegment[];
  criticalFindings: string[];
  recommendedActions: string[];
  processingTimeMs: number;
}

// ---------------------------------------------------------------------------
// Phase pattern definitions
// ---------------------------------------------------------------------------

interface PatternDef {
  pattern: RegExp;
  weight: number;
  label: string;
}

interface PhaseDef {
  label: string;
  description: string;
  color: string;
  patterns: PatternDef[];
}

const PHASE_DEFS: Record<GroomingPhase, PhaseDef> = {
  [GroomingPhase.RAPPORT_BUILDING]: {
    label: 'Rapport Building',
    description: 'Excessive flattery, rapid romantic escalation, and love-bombing tactics',
    color: '#22c55e',
    patterns: [
      { pattern: /soul\s*mate|soulmate/i, weight: 0.9, label: 'Soulmate language' },
      { pattern: /destiny|fate brought|meant to be together/i, weight: 0.8, label: 'Fate/destiny framing' },
      { pattern: /never felt this way|never met anyone like you/i, weight: 0.9, label: 'Unique connection claim' },
      { pattern: /fallen for you|falling for you/i, weight: 0.9, label: 'Rapid love declaration' },
      { pattern: /i love you/i, weight: 0.7, label: 'Early love declaration' },
      { pattern: /can.t stop thinking about you|thinking about you all day/i, weight: 0.8, label: 'Obsessive thinking pattern' },
      { pattern: /you are so (beautiful|gorgeous|stunning|perfect|amazing|special)/i, weight: 0.6, label: 'Intense physical flattery' },
      { pattern: /perfect match|made for each other|you complete me/i, weight: 0.8, label: 'Perfection framing' },
      { pattern: /my (love|darling|dear heart|angel|princess|prince|sweetheart)/i, weight: 0.5, label: 'Pet names used early' },
      { pattern: /lucky to have found you|blessed to know you|God sent you/i, weight: 0.8, label: 'Providential meeting claim' },
      { pattern: /you understand me (better than|like no one)/i, weight: 0.8, label: 'Unique understanding claim' },
      { pattern: /we have so much in common|everything in common/i, weight: 0.6, label: 'Interest mirroring' },
      { pattern: /i feel like i.ve known you (forever|my whole life|all my life)/i, weight: 0.9, label: 'False familiarity claim' },
      { pattern: /miss you (so much|already|terribly)/i, weight: 0.6, label: 'Premature longing' },
      { pattern: /my (heart|soul) belongs to you/i, weight: 0.8, label: 'Rapid emotional bonding' },
      { pattern: /been waiting (for|to find) someone like you/i, weight: 0.7, label: 'Waiting-for-you narrative' },
      { pattern: /you.re the (one|person) i.ve been looking for/i, weight: 0.8, label: 'Predestined match claim' },
    ],
  },

  [GroomingPhase.TRUST_DEVELOPMENT]: {
    label: 'Trust Development',
    description: 'Fabricated backstories, false credentials, and emotional vulnerability tactics',
    color: '#14b8a6',
    patterns: [
      { pattern: /my (wife|husband|spouse|partner) (died|passed away|was killed|left me)/i, weight: 0.9, label: 'Dead/absent spouse backstory' },
      { pattern: /lost my (child|son|daughter|baby)/i, weight: 0.9, label: 'Deceased child claim' },
      { pattern: /i.m (in the military|a soldier|a colonel|a general|an officer|serving overseas|on deployment)/i, weight: 0.9, label: 'Military identity claim' },
      { pattern: /i.m a (doctor|surgeon|physician|nurse|medical professional) (working|serving|stationed|abroad)/i, weight: 0.9, label: 'Medical professional abroad' },
      { pattern: /i.m an? (engineer|contractor|worker) (on an oil rig|offshore|abroad|overseas)/i, weight: 0.9, label: 'Offshore engineer identity' },
      { pattern: /i.m a (CEO|successful businessman|senior manager|executive|director)/i, weight: 0.7, label: 'Wealthy executive claim' },
      { pattern: /you.re the only (one|person) (i can talk to|who understands|that cares)/i, weight: 0.9, label: 'Exclusive confidant positioning' },
      { pattern: /i.ve never (told|shared|opened up about) this (before|to anyone)/i, weight: 0.8, label: 'False secret sharing' },
      { pattern: /i trust you (completely|with my life|with everything|more than anyone)/i, weight: 0.8, label: 'Rapid trust declaration' },
      { pattern: /want to send you (a gift|flowers|something special|a surprise)/i, weight: 0.7, label: 'Gift promise/hook' },
      { pattern: /stuck (at|in) (the airport|customs|immigration|a hospital|deployment)/i, weight: 0.8, label: 'Stuck abroad setup' },
      { pattern: /my (late|deceased) (wife|husband|mother|father|son|daughter)/i, weight: 0.8, label: 'Deceased family backstory' },
      { pattern: /terrible (accident|tragedy|loss) (that|which) (changed|ruined|destroyed)/i, weight: 0.8, label: 'Tragic backstory' },
      { pattern: /raising (my|our) (child|kids|son|daughter) (alone|by myself|as a single)/i, weight: 0.8, label: 'Single parent sympathy hook' },
      { pattern: /retirement (fund|savings|money|investment)/i, weight: 0.5, label: 'Retirement wealth mention' },
      { pattern: /widower|widowed|lost (my|a) spouse/i, weight: 0.9, label: 'Widow/widower status' },
    ],
  },

  [GroomingPhase.ISOLATION]: {
    label: 'Isolation',
    description: 'Cutting the victim off from family/friends and creating exclusive dependency',
    color: '#f59e0b',
    patterns: [
      { pattern: /(your|those|these) (friends?|family|people|relatives?) (are |is )?(jealous|toxic|negative|against us|don.t understand)/i, weight: 0.9, label: 'Friends/family jealousy framing' },
      { pattern: /don.t (tell|share|mention|discuss) (this|us|our relationship) (with|to) (anyone|your family|your friends)/i, weight: 0.9, label: 'Secrecy demand' },
      { pattern: /keep (this|our relationship|us|what we have) (private|secret|between us|just between)/i, weight: 0.9, label: 'Relationship secrecy request' },
      { pattern: /they (don.t|do not|won.t) (want|understand|approve|support) (us|our|you|your happiness)/i, weight: 0.8, label: 'Us-vs-them construction' },
      { pattern: /you (only need|don.t need) (me|anyone else|them anymore)/i, weight: 0.9, label: 'Dependency creation' },
      { pattern: /move (to|our conversation to) (telegram|signal|whatsapp|a private|another) (chat|app|platform)/i, weight: 0.8, label: 'Platform migration push' },
      { pattern: /delete (this|these messages|our conversation|the chat|your history)/i, weight: 0.8, label: 'Evidence deletion request' },
      { pattern: /no one (can|will ever) understand (us|what we have|our love|our connection)/i, weight: 0.8, label: 'Isolation justification' },
      { pattern: /trust (only|just) me (on this|about this|with this)/i, weight: 0.8, label: 'Exclusive trust demand' },
      { pattern: /they (are|will be|will try to) (separate|come between|destroy) (us|our relationship)/i, weight: 0.9, label: 'Threat to relationship framing' },
      { pattern: /i.m (all you need|the only one who|always here for you|your everything)/i, weight: 0.7, label: 'Total dependency positioning' },
      { pattern: /don.t listen to (them|your family|your friends|what others say)/i, weight: 0.8, label: 'Discrediting outside advice' },
    ],
  },

  [GroomingPhase.INVESTMENT_HOOK]: {
    label: 'Investment Hook',
    description: 'Introducing cryptocurrency, trading platforms, or investment opportunities',
    color: '#f97316',
    patterns: [
      { pattern: /i (made|earned|profited|gained) (\$[\d,]+|a lot of money|good money|huge profits?) (from|through|via|on)/i, weight: 0.8, label: 'Investment success story' },
      { pattern: /(crypto|cryptocurrency|bitcoin|BTC|ethereum|ETH|USDT|tether) (trading|investment|platform|app)/i, weight: 0.9, label: 'Crypto trading pitch' },
      { pattern: /(forex|FX|foreign exchange|stock|commodities) trading/i, weight: 0.8, label: 'Financial trading mention' },
      { pattern: /my (uncle|aunt|friend|cousin|mentor|broker|analyst) (has|owns|runs|manages|showed me) (a|an) (special|exclusive|private|unique)/i, weight: 0.9, label: 'Third-party platform endorsement' },
      { pattern: /(exclusive|special|private|limited|VIP) (trading|investment|crypto|mining) (platform|app|site|opportunity)/i, weight: 0.9, label: 'Exclusive platform pitch' },
      { pattern: /i can (teach|show|guide|help) you (how to|to) (trade|invest|make money|earn)/i, weight: 0.9, label: 'Teaching/mentoring offer' },
      { pattern: /(guaranteed|risk.free|zero.risk|100%) (returns?|profit|gains?|income)/i, weight: 1.0, label: 'Guaranteed returns claim' },
      { pattern: /start with (a small|just a|only a|a minimum) (amount|investment|deposit)/i, weight: 0.8, label: 'Low-entry investment pitch' },
      { pattern: /(my|our) (portfolio|investment|account|capital) (grew|is|has grown|increased) (\d+%|significantly|by)/i, weight: 0.8, label: 'Portfolio growth display' },
      { pattern: /initial (investment|deposit|capital|contribution) of (\$|€|£|¥)?\s*\d+/i, weight: 0.8, label: 'Initial deposit amount' },
      { pattern: /crypto (mining|farm|node|staking)/i, weight: 0.8, label: 'Crypto mining/staking scheme' },
      { pattern: /trading (signals?|bots?|algorithm|strategy|system)/i, weight: 0.7, label: 'Trading system pitch' },
      { pattern: /\d+(x|X) (returns?|profit|gains?|your money)/i, weight: 1.0, label: 'Unrealistic return multiplier' },
      { pattern: /passive income (from|through|via|using)/i, weight: 0.7, label: 'Passive income pitch' },
      { pattern: /let me (show|teach|walk) you (how|the way)/i, weight: 0.6, label: 'Financial mentoring hook' },
      { pattern: /i (invested|put in|deposited) for (you|us|both of us)/i, weight: 0.9, label: 'Invested on your behalf' },
    ],
  },

  [GroomingPhase.PRESSURE_ESCALATION]: {
    label: 'Pressure Escalation',
    description: 'Time pressure, FOMO tactics, and manufactured urgency',
    color: '#ef4444',
    patterns: [
      { pattern: /(limited|running out of|almost no) time (left|remaining|to invest|to act)/i, weight: 0.9, label: 'Limited time pressure' },
      { pattern: /(only|just) (a few|one|two) (spots?|places?|positions?) (left|remaining|available)/i, weight: 0.9, label: 'Artificial scarcity' },
      { pattern: /you.ll miss out|don.t miss (this|out|the opportunity)/i, weight: 0.8, label: 'FOMO creation' },
      { pattern: /act (now|fast|immediately|quickly|today)|do it now|hurry (up)?/i, weight: 0.8, label: 'Urgency demand' },
      { pattern: /(platform|account|position|offer|window) (closes?|expires?|ends?|shuts?) (soon|tomorrow|today|in \d)/i, weight: 0.9, label: 'Artificial deadline' },
      { pattern: /i (already|have) (invested|put in|deposited) (my|the|our) money (for you|for us)/i, weight: 0.9, label: 'Pre-invested for you claim' },
      { pattern: /your (profits?|returns?|earnings?|investment|funds?) (are|is) (growing|increasing|up|at)/i, weight: 0.8, label: 'Growing profits display' },
      { pattern: /(just|only) (a bit|a little|little more|a small amount) more (needed|to go|to release|to withdraw)/i, weight: 0.9, label: 'Incremental extraction' },
      { pattern: /(account|funds?|withdrawal|profits?) (frozen|locked|suspended|blocked|on hold|flagged)/i, weight: 0.9, label: 'Account blocked pretext' },
      { pattern: /need to (verify|confirm|validate|upgrade|unlock) (your account|the account|your identity)/i, weight: 0.8, label: 'Verification fee pretext' },
      { pattern: /once in a lifetime (opportunity|chance|offer|deal)/i, weight: 0.9, label: 'Once-in-lifetime framing' },
      { pattern: /(withdraw|withdrawal) (minimum|requires?|needs?) (more|additional|another)/i, weight: 0.9, label: 'Withdrawal minimum trap' },
      { pattern: /my (friends?|family|colleagues?) (all|already|have) (made|earned|profited)/i, weight: 0.7, label: 'Social proof pressure' },
      { pattern: /invest (now|today|immediately|right now) (and|to) (get|secure|guarantee|receive)/i, weight: 0.9, label: 'Invest-now pressure' },
      { pattern: /if you don.t (act|invest|deposit|send) (now|today|soon|fast)/i, weight: 0.9, label: 'Threat of missed opportunity' },
      { pattern: /the (platform|system|market|window) (is|will be) closing/i, weight: 0.9, label: 'Closing platform urgency' },
    ],
  },

  [GroomingPhase.COLLECTION]: {
    label: 'Collection',
    description: 'Direct financial demands, payment solicitation, and fund extraction',
    color: '#dc2626',
    patterns: [
      { pattern: /send (me|the|some|us) money|transfer (me|the|some) funds?/i, weight: 1.0, label: 'Direct money request' },
      { pattern: /(western union|moneygram|wire transfer|bank wire|swift transfer)/i, weight: 1.0, label: 'Wire transfer service' },
      { pattern: /(google play|amazon|apple|steam|itunes|target|walmart|ebay|vanilla) (gift )?card/i, weight: 1.0, label: 'Gift card solicitation' },
      { pattern: /bitcoin (wallet|address|transfer|send|receive)/i, weight: 1.0, label: 'Bitcoin transfer request' },
      { pattern: /crypto (wallet|address|transfer|send|receive|deposit)/i, weight: 1.0, label: 'Crypto payment request' },
      { pattern: /[13][a-zA-Z0-9]{25,34}\b|0x[a-fA-F0-9]{40}\b/i, weight: 1.0, label: 'Crypto wallet address' },
      { pattern: /(hospital|medical|surgery|operation|treatment) (bill|fee|cost|expense|payment)/i, weight: 0.9, label: 'Medical emergency extraction' },
      { pattern: /stuck (at|in) (the airport|customs|immigration|jail|prison|detention)/i, weight: 0.9, label: 'Stuck abroad emergency' },
      { pattern: /(customs|tax|release|processing|clearing|handling) fee/i, weight: 0.9, label: 'Fake fee extraction' },
      { pattern: /emergency (fund|money|transfer|help|loan|financial assistance)/i, weight: 0.8, label: 'Emergency financial request' },
      { pattern: /(borrow|loan) (me|some) money|lend me|i need to borrow/i, weight: 0.9, label: 'Loan request' },
      { pattern: /i need (\$|USD|€|£|¥|GBP|EUR)\s*[\d,]+/i, weight: 0.9, label: 'Specific amount demanded' },
      { pattern: /pay (the|a) (tax|fee|duty|charge|tariff) (to|before|in order to) (release|receive|get|access)/i, weight: 1.0, label: 'Pay-to-release scheme' },
      { pattern: /(account|funds?|money|investment) (is|has been|are) (seized|blocked|frozen) (by|due to)/i, weight: 0.9, label: 'Seized funds pretext' },
      { pattern: /send (the money|funds?|payment|transfer) (to|via|through|using)/i, weight: 0.9, label: 'Payment instruction' },
      { pattern: /i.m (stranded|stuck|trapped|in trouble|in danger) (and|,|;) (need|require)/i, weight: 0.9, label: 'Distress extraction' },
      { pattern: /reimburs(e|ement)|pay you back|return (it|the money|everything) (soon|immediately)/i, weight: 0.7, label: 'False repayment promise' },
    ],
  },
};

// ---------------------------------------------------------------------------
// Message parser
// ---------------------------------------------------------------------------

// WhatsApp: [01/15/2024, 9:30:25 AM] Sender: Message
const WHATSAPP_RE = /^\[(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}),?\s+(\d{1,2}:\d{2}(?::\d{2})?\s*(?:AM|PM)?)\]\s+([^:]+):\s*([\s\S]*)/i;
// Telegram: Sender [Jan 15, 2024 9:30 AM]: Message
const TELEGRAM_RE = /^([^\[]{1,60})\s+\[([^\]]+)\]:\s*([\s\S]*)/;
// Generic: Sender: Message (sender name ≤ 40 chars, no newline)
const GENERIC_COLON_RE = /^([A-Za-z][A-Za-z0-9 ]{0,39}):\s+([\s\S]+)/;

export function parseConversation(text: string): ParsedMessage[] {
  const lines = text.split('\n');
  const messages: ParsedMessage[] = [];
  let current: ParsedMessage | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    if (!line.trim()) continue;

    // WhatsApp format
    const waMatch = WHATSAPP_RE.exec(line);
    if (waMatch) {
      if (current) messages.push(current);
      current = {
        index: messages.length,
        timestamp: tryParseDate(`${waMatch[1]} ${waMatch[2]}`),
        sender: waMatch[3].trim(),
        content: waMatch[4].trim(),
      };
      continue;
    }

    // Telegram format
    const tgMatch = TELEGRAM_RE.exec(line);
    if (tgMatch && /\d/.test(tgMatch[2])) {
      if (current) messages.push(current);
      current = {
        index: messages.length,
        timestamp: null,
        sender: tgMatch[1].trim(),
        content: tgMatch[3].trim(),
      };
      continue;
    }

    // Generic "Name: message" format
    const gcMatch = GENERIC_COLON_RE.exec(line);
    if (gcMatch) {
      if (current) messages.push(current);
      current = {
        index: messages.length,
        timestamp: null,
        sender: gcMatch[1].trim(),
        content: gcMatch[2].trim(),
      };
      continue;
    }

    // Continuation line
    if (current) {
      current.content += ' ' + line.trim();
    }
  }

  if (current) messages.push(current);

  // Fallback: treat each non-empty line as a message if parsing yielded ≤ 1 message
  if (messages.length <= 1 && lines.length > 5) {
    return lines
      .filter(l => l.trim().length > 0)
      .map((l, i) => ({
        index: i,
        timestamp: null,
        sender: 'Unknown',
        content: l.trim(),
      }));
  }

  return messages;
}

function tryParseDate(str: string): Date | null {
  const d = new Date(str);
  return isNaN(d.getTime()) ? null : d;
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

function scoreMessage(
  content: string,
  phase: GroomingPhase,
  messageIndex: number,
  sender: string,
): PhaseSignal[] {
  const signals: PhaseSignal[] = [];
  const { patterns } = PHASE_DEFS[phase];

  for (const { pattern, weight, label } of patterns) {
    const match = pattern.exec(content);
    if (match) {
      const start = Math.max(0, match.index - 15);
      const end = Math.min(content.length, match.index + match[0].length + 30);
      signals.push({
        phase,
        patternLabel: label,
        matchedText: content.substring(start, end).trim(),
        weight,
        messageIndex,
        sender,
      });
    }
  }

  return signals;
}

function computePhaseScore(signals: PhaseSignal[], totalMessages: number): number {
  if (signals.length === 0) return 0;
  const rawWeight = signals.reduce((sum, s) => sum + s.weight, 0);
  // Normalize by log(messageCount) to prevent long conversations from always
  // dominating. A short but signal-heavy conversation should score high too.
  const normalizer = Math.max(1, Math.log2(totalMessages + 2) / 2);
  return Math.min(100, (rawWeight / normalizer) * 10);
}

// ---------------------------------------------------------------------------
// Main exported analysis function
// ---------------------------------------------------------------------------

export function analyzeConversationArc(text: string): ConversationArcResult {
  const startTime = performance.now();

  const messages = parseConversation(text.trim());
  const totalMessages = messages.length;

  // Unique senders
  const senderSet = new Set(messages.map(m => m.sender));
  const senders = Array.from(senderSet).filter(s => s !== 'Unknown').slice(0, 10);

  // Score every message against every phase
  const allSignals: Record<GroomingPhase, PhaseSignal[]> = {
    [GroomingPhase.RAPPORT_BUILDING]: [],
    [GroomingPhase.TRUST_DEVELOPMENT]: [],
    [GroomingPhase.ISOLATION]: [],
    [GroomingPhase.INVESTMENT_HOOK]: [],
    [GroomingPhase.PRESSURE_ESCALATION]: [],
    [GroomingPhase.COLLECTION]: [],
  };

  for (const msg of messages) {
    for (const phase of Object.values(GroomingPhase)) {
      const sigs = scoreMessage(msg.content, phase, msg.index, msg.sender);
      allSignals[phase].push(...sigs);
    }
  }

  // Build PhaseResult objects
  const phases: PhaseResult[] = Object.values(GroomingPhase).map(phase => {
    const def = PHASE_DEFS[phase];
    const signals = allSignals[phase];
    const score = computePhaseScore(signals, totalMessages);

    // Deduplicated top findings
    const seenLabels = new Set<string>();
    const topFindings: string[] = [];
    for (const sig of [...signals].sort((a, b) => b.weight - a.weight)) {
      if (!seenLabels.has(sig.patternLabel)) {
        seenLabels.add(sig.patternLabel);
        const excerpt = sig.matchedText.length > 80
          ? sig.matchedText.substring(0, 80) + '…'
          : sig.matchedText;
        topFindings.push(`${sig.patternLabel}: "${excerpt}"`);
        if (topFindings.length >= 4) break;
      }
    }

    return {
      phase,
      label: def.label,
      description: def.description,
      color: def.color,
      score: Math.round(score),
      present: score >= 15,
      signals,
      topFindings,
    };
  });

  // Build timeline (5–10 segments based on message count)
  const segCount = totalMessages < 10 ? 5 : Math.min(10, Math.floor(totalMessages / 3));
  const segSize = Math.max(1, Math.ceil(totalMessages / segCount));
  const timeline: TimelineSegment[] = [];

  for (let i = 0; i < segCount; i++) {
    const startIdx = i * segSize;
    const endIdx = Math.min(totalMessages - 1, (i + 1) * segSize - 1);

    let maxWeight = 0;
    let dominantPhase: GroomingPhase | null = null;
    const phaseWeights: Record<string, number> = {};

    for (const phase of Object.values(GroomingPhase)) {
      const w = allSignals[phase]
        .filter(s => s.messageIndex >= startIdx && s.messageIndex <= endIdx)
        .reduce((sum, s) => sum + s.weight, 0);
      phaseWeights[phase] = w;
      if (w > maxWeight) { maxWeight = w; dominantPhase = phase; }
    }

    const rawRisk =
      (phaseWeights[GroomingPhase.COLLECTION] ?? 0) * 40 +
      (phaseWeights[GroomingPhase.PRESSURE_ESCALATION] ?? 0) * 25 +
      (phaseWeights[GroomingPhase.INVESTMENT_HOOK] ?? 0) * 20 +
      (phaseWeights[GroomingPhase.ISOLATION] ?? 0) * 10 +
      (phaseWeights[GroomingPhase.TRUST_DEVELOPMENT] ?? 0) * 5;

    timeline.push({
      segmentIndex: i,
      startMessage: startIdx,
      endMessage: endIdx,
      dominantPhase: maxWeight >= 0.3 ? dominantPhase : null,
      riskLevel: Math.min(100, Math.round(rawRisk)),
    });
  }

  // Overall risk
  const scoreByPhase: Record<GroomingPhase, number> = Object.fromEntries(
    phases.map(p => [p.phase, p.score]),
  ) as Record<GroomingPhase, number>;

  let overallRisk =
    (scoreByPhase[GroomingPhase.COLLECTION] / 100) * 40 +
    (scoreByPhase[GroomingPhase.PRESSURE_ESCALATION] / 100) * 25 +
    (scoreByPhase[GroomingPhase.INVESTMENT_HOOK] / 100) * 20 +
    (scoreByPhase[GroomingPhase.ISOLATION] / 100) * 10 +
    (scoreByPhase[GroomingPhase.TRUST_DEVELOPMENT] / 100) * 5;

  // Arc completion multiplier — more phases = more deliberate script
  const phasesPresent = phases.filter(p => p.present).length;
  if (phasesPresent >= 5) overallRisk = Math.min(100, overallRisk * 1.5);
  else if (phasesPresent >= 4) overallRisk = Math.min(100, overallRisk * 1.3);
  else if (phasesPresent >= 3) overallRisk = Math.min(100, overallRisk * 1.15);

  overallRisk = Math.min(100, Math.round(overallRisk));

  const threatLevel: ConversationArcResult['threatLevel'] =
    overallRisk >= 75 ? 'CRITICAL' :
    overallRisk >= 55 ? 'HIGH' :
    overallRisk >= 35 ? 'MEDIUM' :
    overallRisk >= 15 ? 'LOW' : 'SAFE';

  // Arc type
  const r   = scoreByPhase[GroomingPhase.RAPPORT_BUILDING];
  const t   = scoreByPhase[GroomingPhase.TRUST_DEVELOPMENT];
  const iso = scoreByPhase[GroomingPhase.ISOLATION];
  const inv = scoreByPhase[GroomingPhase.INVESTMENT_HOOK];
  const prs = scoreByPhase[GroomingPhase.PRESSURE_ESCALATION];
  const col = scoreByPhase[GroomingPhase.COLLECTION];

  let arcType: ArcType = 'BENIGN';
  let arcLabel = 'No Grooming Pattern';
  let arcDescription = 'No significant manipulation patterns detected. The conversation appears normal.';

  if (r >= 20 && inv >= 20 && (col >= 15 || prs >= 25)) {
    arcType = 'PIG_BUTCHERING';
    arcLabel = 'Pig Butchering Scam';
    arcDescription =
      'Classic cryptocurrency investment romance scam. A fabricated romantic relationship is used to establish deep trust before pivoting to a fraudulent investment platform designed to extract funds.';
  } else if (r >= 20 && (col >= 20 || iso >= 25) && inv < 20) {
    arcType = 'ROMANCE_SCAM';
    arcLabel = 'Romance Scam';
    arcDescription =
      'Fraudulent romantic relationship built to extract money through emotional manipulation, fabricated emergencies, and psychological dependency.';
  } else if (inv >= 25 && (prs >= 20 || col >= 20) && r < 15) {
    arcType = 'INVESTMENT_FRAUD';
    arcLabel = 'Investment Fraud';
    arcDescription =
      'Direct financial manipulation without romantic framing. Uses high-pressure tactics, fake returns, and fraudulent investment platforms to extract funds.';
  } else if (col >= 25 && t >= 15 && r < 15) {
    arcType = 'ADVANCE_FEE';
    arcLabel = 'Advance Fee Fraud';
    arcDescription =
      'Classic 419 advance fee fraud. Requires upfront payment (tax, fee, customs) with false promises of a larger return — inheritance, lottery, or business windfall.';
  } else if (overallRisk >= 30) {
    arcType = 'GENERIC_GROOMING';
    arcLabel = 'Grooming Pattern Detected';
    arcDescription =
      'Multiple manipulation indicators detected. The conversation shows deliberate grooming tactics even without matching a specific known scam template.';
  }

  // Critical findings
  const criticalFindings: string[] = [];
  if (col >= 30) criticalFindings.push('IMMEDIATE RISK: Direct money solicitation or payment method requests detected.');
  if (prs >= 40) criticalFindings.push('High-pressure tactics with artificial urgency detected — designed to block careful decision-making.');
  if (inv >= 30) criticalFindings.push('Investment or cryptocurrency opportunity pitched — likely a fraudulent or controlled platform.');
  if (iso >= 25) criticalFindings.push('Isolation tactics detected — scammer is actively cutting off outside perspective and support.');
  if (r >= 40)  criticalFindings.push('Extreme love-bombing: rapid romantic escalation is a primary grooming technique in romance scams.');
  if (t >= 30)  criticalFindings.push('Fabricated backstory elements detected — military/doctor/offshore engineer claims are hallmarks of romance fraud.');
  if (phasesPresent >= 4) criticalFindings.push(`${phasesPresent}/6 grooming phases detected — this conversation follows a well-known scam script.`);

  // Recommended actions
  const recommendedActions: string[] = [];
  if (arcType !== 'BENIGN') {
    recommendedActions.push('Do NOT send money, gift cards, or cryptocurrency to this person under any circumstances.');
    recommendedActions.push('Talk to a trusted friend or family member about this relationship immediately — outside perspective is critical.');
    recommendedActions.push('Report this account to the platform (WhatsApp, Telegram, Facebook, Instagram, etc.).');
  }
  if (col >= 20) {
    recommendedActions.push('If payments have already been made, contact your bank immediately — early intervention improves recovery odds.');
    recommendedActions.push('File a report with FTC (reportfraud.ftc.gov), FBI IC3 (ic3.gov), or your national cybercrime unit.');
  }
  if (arcType === 'PIG_BUTCHERING' || arcType === 'INVESTMENT_FRAUD') {
    recommendedActions.push('Never transfer funds to any trading platform, app, or website recommended by someone you met online.');
  }
  if (arcType !== 'BENIGN') {
    recommendedActions.push('Block and cease all contact with this person to prevent further manipulation.');
  }

  return {
    overallRisk,
    threatLevel,
    arcType,
    arcLabel,
    arcDescription,
    phases,
    messageCount: totalMessages,
    senderCount: senders.length,
    senders,
    timeline,
    criticalFindings,
    recommendedActions,
    processingTimeMs: Math.round(performance.now() - startTime),
  };
}
