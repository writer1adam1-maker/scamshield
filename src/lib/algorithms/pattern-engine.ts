// ============================================================================
// VERIDICT Aho-Corasick Pattern Matching Engine
// Replaces O(N*M) inner loops with O(N+M+Z) multi-pattern search.
// Built once at module load; exported scanPatterns() runs the automaton.
// ============================================================================

import AhoCorasick from 'ahocorasick';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PatternEntry {
  id: string;
  text: string;
  category: string;
  group: string;
  weight: number;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface PatternMatch {
  id: string;
  text: string;
  category: string;
  group: string;
  weight: number;
  severity: string;
  position: number; // end-index in the haystack
}

// ---------------------------------------------------------------------------
// Master Pattern Library — 500+ patterns
// ---------------------------------------------------------------------------

let _nextId = 0;
function p(
  group: string,
  category: string,
  text: string,
  weight: number,
  severity: 'low' | 'medium' | 'high' | 'critical' = 'medium',
): PatternEntry {
  _nextId++;
  return { id: `${group.toUpperCase()}-${String(_nextId).padStart(3, '0')}`, text: text.toLowerCase(), category, group, weight, severity };
}

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 1: URGENCY  (80+ patterns)
// ═══════════════════════════════════════════════════════════════════════════
const URGENCY: PatternEntry[] = [
  // -- Time pressure --
  p('urgency', 'time_pressure', 'act now', 0.70, 'medium'),
  p('urgency', 'time_pressure', 'immediately', 0.70, 'medium'),
  p('urgency', 'time_pressure', 'right away', 0.70, 'medium'),
  p('urgency', 'time_pressure', 'right now', 0.70, 'medium'),
  p('urgency', 'time_pressure', 'urgently', 0.70, 'medium'),
  p('urgency', 'time_pressure', 'urgent', 0.70, 'medium'),
  p('urgency', 'time_pressure', 'asap', 0.65, 'medium'),
  p('urgency', 'time_pressure', 'time is running out', 0.75, 'medium'),
  p('urgency', 'time_pressure', 'before midnight', 0.70, 'medium'),
  p('urgency', 'time_pressure', 'last chance', 0.80, 'high'),
  p('urgency', 'time_pressure', 'limited time offer', 0.70, 'medium'),
  p('urgency', 'time_pressure', 'offer expires', 0.70, 'medium'),
  p('urgency', 'time_pressure', 'today only', 0.70, 'medium'),
  p('urgency', 'time_pressure', 'final notice', 0.85, 'high'),
  p('urgency', 'time_pressure', 'don\'t delay', 0.70, 'medium'),
  p('urgency', 'time_pressure', 'don\'t wait', 0.65, 'medium'),
  p('urgency', 'time_pressure', 'hurry up', 0.65, 'medium'),
  p('urgency', 'time_pressure', 'must act now', 0.75, 'medium'),
  p('urgency', 'time_pressure', 'clock is ticking', 0.75, 'medium'),
  p('urgency', 'time_pressure', 'every minute counts', 0.75, 'medium'),
  p('urgency', 'time_pressure', 'every second counts', 0.75, 'medium'),
  p('urgency', 'time_pressure', 'now or never', 0.80, 'high'),
  p('urgency', 'time_pressure', 'limited time', 0.65, 'medium'),
  p('urgency', 'time_pressure', 'while you still can', 0.75, 'medium'),
  p('urgency', 'time_pressure', 'before it\'s too late', 0.80, 'high'),
  p('urgency', 'time_pressure', 'do not ignore this', 0.70, 'medium'),
  p('urgency', 'time_pressure', 'do not disregard this', 0.70, 'medium'),
  p('urgency', 'time_pressure', 'time sensitive', 0.75, 'medium'),
  p('urgency', 'time_pressure', 'deadline approaching', 0.80, 'high'),
  p('urgency', 'time_pressure', 'hours remaining', 0.75, 'medium'),
  p('urgency', 'time_pressure', 'respond immediately', 0.75, 'medium'),
  p('urgency', 'time_pressure', 'reply now', 0.70, 'medium'),
  p('urgency', 'time_pressure', 'reply urgently', 0.75, 'medium'),
  p('urgency', 'time_pressure', 'call immediately', 0.75, 'medium'),
  p('urgency', 'time_pressure', 'contact us immediately', 0.75, 'medium'),
  p('urgency', 'time_pressure', 'respond before', 0.70, 'medium'),

  // -- Account / action required --
  p('urgency', 'action_required', 'urgent action required', 0.85, 'high'),
  p('urgency', 'action_required', 'immediate action required', 0.85, 'high'),
  p('urgency', 'action_required', 'action required', 0.80, 'high'),
  p('urgency', 'action_required', 'immediate response required', 0.80, 'high'),
  p('urgency', 'action_required', 'take action now', 0.75, 'medium'),
  p('urgency', 'action_required', 'take action today', 0.70, 'medium'),
  p('urgency', 'action_required', 'do this right now', 0.70, 'medium'),
  p('urgency', 'action_required', 'failure to respond', 0.80, 'high'),
  p('urgency', 'action_required', 'failure to act', 0.80, 'high'),
  p('urgency', 'action_required', 'failure to comply', 0.85, 'high'),
  p('urgency', 'action_required', 'failure to verify', 0.80, 'high'),

  // -- Account closure / suspension threats --
  p('urgency', 'account_threat', 'your account will be closed', 0.90, 'critical'),
  p('urgency', 'account_threat', 'your account will be suspended', 0.90, 'critical'),
  p('urgency', 'account_threat', 'your account will be locked', 0.90, 'critical'),
  p('urgency', 'account_threat', 'your account will be terminated', 0.90, 'critical'),
  p('urgency', 'account_threat', 'your account will be deactivated', 0.85, 'high'),
  p('urgency', 'account_threat', 'your access will be revoked', 0.85, 'high'),
  p('urgency', 'account_threat', 'account termination notice', 0.85, 'high'),
  p('urgency', 'account_threat', 'pending cancellation', 0.75, 'medium'),
  p('urgency', 'account_threat', 'automatic deactivation', 0.80, 'high'),
  p('urgency', 'account_threat', 'service interruption', 0.65, 'medium'),
  p('urgency', 'account_threat', 'scheduled for deletion', 0.85, 'high'),
  p('urgency', 'account_threat', 'your account is at risk', 0.80, 'high'),
  p('urgency', 'account_threat', 'security alert', 0.75, 'medium'),
  p('urgency', 'account_threat', 'security warning', 0.75, 'medium'),
  p('urgency', 'account_threat', 'security breach', 0.80, 'high'),

  // -- Deadline / expiration --
  p('urgency', 'deadline', 'will expire in 24 hours', 0.80, 'high'),
  p('urgency', 'deadline', 'within the next hour', 0.80, 'high'),
  p('urgency', 'deadline', 'within 24 hours', 0.75, 'medium'),
  p('urgency', 'deadline', 'within 48 hours', 0.70, 'medium'),
  p('urgency', 'deadline', 'expires today', 0.80, 'high'),
  p('urgency', 'deadline', 'expires soon', 0.65, 'medium'),
  p('urgency', 'deadline', 'offer ends today', 0.70, 'medium'),
  p('urgency', 'deadline', 'final warning', 0.90, 'critical'),
  p('urgency', 'deadline', 'final attempt', 0.85, 'high'),
  p('urgency', 'deadline', 'final reminder', 0.80, 'high'),

  // -- Financial urgency --
  p('urgency', 'financial_urgency', 'payment overdue', 0.80, 'high'),
  p('urgency', 'financial_urgency', 'past due amount', 0.75, 'medium'),
  p('urgency', 'financial_urgency', 'collection agency', 0.80, 'high'),
  p('urgency', 'financial_urgency', 'balance due immediately', 0.85, 'high'),
  p('urgency', 'financial_urgency', 'second notice', 0.70, 'medium'),
  p('urgency', 'financial_urgency', 'third and final notice', 0.85, 'high'),
  p('urgency', 'financial_urgency', 'overdue balance', 0.75, 'medium'),
  p('urgency', 'financial_urgency', 'outstanding balance', 0.65, 'medium'),

  // -- Legal urgency --
  p('urgency', 'legal_urgency', 'warrant for your arrest', 0.90, 'critical'),
  p('urgency', 'legal_urgency', 'summons to appear', 0.85, 'high'),
  p('urgency', 'legal_urgency', 'legal action', 0.80, 'high'),
  p('urgency', 'legal_urgency', 'facing charges', 0.85, 'high'),
  p('urgency', 'legal_urgency', 'facing prosecution', 0.85, 'high'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 2: FINANCIAL  (80+ patterns)
// ═══════════════════════════════════════════════════════════════════════════
const FINANCIAL: PatternEntry[] = [
  // -- Wire / transfer services --
  p('financial', 'wire_transfer', 'wire transfer', 0.80, 'high'),
  p('financial', 'wire_transfer', 'western union', 0.85, 'high'),
  p('financial', 'wire_transfer', 'moneygram', 0.85, 'high'),
  p('financial', 'wire_transfer', 'telegraphic transfer', 0.80, 'high'),
  p('financial', 'wire_transfer', 'swift transfer', 0.75, 'medium'),
  p('financial', 'wire_transfer', 'swift code', 0.65, 'medium'),
  p('financial', 'wire_transfer', 'money order', 0.70, 'medium'),
  p('financial', 'wire_transfer', 'cashier\'s check', 0.70, 'medium'),
  p('financial', 'wire_transfer', 'certified check', 0.65, 'medium'),

  // -- P2P payment apps --
  p('financial', 'p2p_payment', 'zelle', 0.75, 'medium'),
  p('financial', 'p2p_payment', 'cash app', 0.75, 'medium'),
  p('financial', 'p2p_payment', 'cashapp', 0.75, 'medium'),
  p('financial', 'p2p_payment', 'venmo', 0.65, 'medium'),
  p('financial', 'p2p_payment', 'paypal friends and family', 0.85, 'high'),
  p('financial', 'p2p_payment', 'send money', 0.60, 'medium'),
  p('financial', 'p2p_payment', 'transfer funds', 0.65, 'medium'),
  p('financial', 'p2p_payment', 'send payment to', 0.75, 'medium'),

  // -- Crypto --
  p('financial', 'crypto', 'bitcoin wallet', 0.80, 'high'),
  p('financial', 'crypto', 'ethereum address', 0.80, 'high'),
  p('financial', 'crypto', 'crypto wallet', 0.75, 'medium'),
  p('financial', 'crypto', 'bitcoin payment', 0.80, 'high'),
  p('financial', 'crypto', 'bitcoin address', 0.80, 'high'),
  p('financial', 'crypto', 'send bitcoin', 0.85, 'high'),
  p('financial', 'crypto', 'send btc', 0.85, 'high'),
  p('financial', 'crypto', 'send ethereum', 0.85, 'high'),
  p('financial', 'crypto', 'send eth', 0.80, 'high'),
  p('financial', 'crypto', 'send usdt', 0.85, 'high'),
  p('financial', 'crypto', 'cryptocurrency', 0.60, 'medium'),
  p('financial', 'crypto', 'seed phrase', 0.90, 'critical'),
  p('financial', 'crypto', 'private key', 0.85, 'high'),
  p('financial', 'crypto', 'wallet recovery', 0.80, 'high'),
  p('financial', 'crypto', 'connect wallet', 0.85, 'high'),
  p('financial', 'crypto', 'connect your wallet', 0.90, 'critical'),

  // -- Gift cards --
  p('financial', 'gift_card', 'gift card', 0.85, 'high'),
  p('financial', 'gift_card', 'itunes card', 0.92, 'critical'),
  p('financial', 'gift_card', 'google play card', 0.92, 'critical'),
  p('financial', 'gift_card', 'amazon gift card', 0.90, 'critical'),
  p('financial', 'gift_card', 'steam card', 0.88, 'high'),
  p('financial', 'gift_card', 'target gift card', 0.88, 'high'),
  p('financial', 'gift_card', 'walmart gift card', 0.88, 'high'),
  p('financial', 'gift_card', 'apple gift card', 0.92, 'critical'),
  p('financial', 'gift_card', 'steam wallet code', 0.88, 'high'),
  p('financial', 'gift_card', 'ebay gift card', 0.85, 'high'),
  p('financial', 'gift_card', 'best buy gift card', 0.85, 'high'),
  p('financial', 'gift_card', 'vanilla gift card', 0.85, 'high'),

  // -- Prepaid / reloadable --
  p('financial', 'prepaid', 'prepaid debit card', 0.82, 'high'),
  p('financial', 'prepaid', 'prepaid card', 0.80, 'high'),
  p('financial', 'prepaid', 'green dot card', 0.85, 'high'),
  p('financial', 'prepaid', 'green dot', 0.80, 'high'),
  p('financial', 'prepaid', 'reload pack', 0.85, 'high'),
  p('financial', 'prepaid', 'reload card', 0.80, 'high'),

  // -- Bank details / PII --
  p('financial', 'pii', 'bank routing number', 0.80, 'high'),
  p('financial', 'pii', 'routing number', 0.75, 'medium'),
  p('financial', 'pii', 'account number', 0.70, 'medium'),
  p('financial', 'pii', 'social security number', 0.90, 'critical'),
  p('financial', 'pii', 'ssn', 0.85, 'high'),
  p('financial', 'pii', 'credit card number', 0.85, 'high'),
  p('financial', 'pii', 'card number', 0.70, 'medium'),
  p('financial', 'pii', 'cvv', 0.80, 'high'),
  p('financial', 'pii', 'card verification', 0.75, 'medium'),
  p('financial', 'pii', 'tax id', 0.65, 'medium'),
  p('financial', 'pii', 'sort code', 0.65, 'medium'),
  p('financial', 'pii', 'iban', 0.65, 'medium'),
  p('financial', 'pii', 'debit card', 0.55, 'low'),

  // -- Fees / demands --
  p('financial', 'fees', 'processing fee', 0.80, 'high'),
  p('financial', 'fees', 'handling fee', 0.80, 'high'),
  p('financial', 'fees', 'shipping fee', 0.65, 'medium'),
  p('financial', 'fees', 'customs fee', 0.80, 'high'),
  p('financial', 'fees', 'release fee', 0.85, 'high'),
  p('financial', 'fees', 'clearance fee', 0.85, 'high'),
  p('financial', 'fees', 'insurance fee', 0.70, 'medium'),
  p('financial', 'fees', 'tax payment', 0.65, 'medium'),
  p('financial', 'fees', 'irs payment', 0.80, 'high'),
  p('financial', 'fees', 'pay immediately', 0.80, 'high'),
  p('financial', 'fees', 'advance payment', 0.80, 'high'),
  p('financial', 'fees', 'upfront cost', 0.80, 'high'),
  p('financial', 'fees', 'upfront fee', 0.85, 'high'),
  p('financial', 'fees', 'upfront payment', 0.85, 'high'),
  p('financial', 'fees', 'registration fee', 0.70, 'medium'),
  p('financial', 'fees', 'activation fee', 0.75, 'medium'),
  p('financial', 'fees', 'membership fee', 0.55, 'low'),
  p('financial', 'fees', 'advance fee', 0.85, 'high'),
  p('financial', 'fees', 'deposit required', 0.70, 'medium'),
  p('financial', 'fees', 'delivery fee', 0.60, 'medium'),
  p('financial', 'fees', 'customs duty', 0.75, 'medium'),
  p('financial', 'fees', 'payment confirmation', 0.55, 'low'),

  // -- Financial promises --
  p('financial', 'promise', 'guaranteed return', 0.90, 'critical'),
  p('financial', 'promise', 'guaranteed profit', 0.90, 'critical'),
  p('financial', 'promise', 'guaranteed income', 0.85, 'high'),
  p('financial', 'promise', 'risk free', 0.85, 'high'),
  p('financial', 'promise', 'no risk', 0.75, 'medium'),
  p('financial', 'promise', 'passive income', 0.75, 'medium'),
  p('financial', 'promise', 'financial freedom', 0.70, 'medium'),
  p('financial', 'promise', 'be your own boss', 0.70, 'medium'),
  p('financial', 'promise', 'quit your job', 0.70, 'medium'),
  p('financial', 'promise', 'tax refund', 0.70, 'medium'),
  p('financial', 'promise', 'stimulus payment', 0.70, 'medium'),
  p('financial', 'promise', 'stimulus check', 0.70, 'medium'),
  p('financial', 'promise', 'inheritance', 0.80, 'high'),
  p('financial', 'promise', 'beneficiary', 0.75, 'medium'),
  p('financial', 'promise', 'next of kin', 0.80, 'high'),
  p('financial', 'promise', 'unclaimed funds', 0.85, 'high'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 3: ROMANCE  (80+ patterns — NEW)
// ═══════════════════════════════════════════════════════════════════════════
const ROMANCE: PatternEntry[] = [
  // -- Love bombing --
  p('romance', 'love_bombing', 'i love you already', 0.80, 'high'),
  p('romance', 'love_bombing', 'god sent you to me', 0.85, 'high'),
  p('romance', 'love_bombing', 'god brought us together', 0.85, 'high'),
  p('romance', 'love_bombing', 'my heart belongs to you', 0.80, 'high'),
  p('romance', 'love_bombing', 'you are my soulmate', 0.85, 'high'),
  p('romance', 'love_bombing', 'i have never felt this way', 0.75, 'medium'),
  p('romance', 'love_bombing', 'you complete me', 0.70, 'medium'),
  p('romance', 'love_bombing', 'love at first sight', 0.70, 'medium'),
  p('romance', 'love_bombing', 'destiny brought us together', 0.80, 'high'),
  p('romance', 'love_bombing', 'i can\'t live without you', 0.80, 'high'),
  p('romance', 'love_bombing', 'you are the one', 0.65, 'medium'),
  p('romance', 'love_bombing', 'falling in love with you', 0.65, 'medium'),
  p('romance', 'love_bombing', 'my love for you is real', 0.75, 'medium'),
  p('romance', 'love_bombing', 'i think about you all day', 0.70, 'medium'),
  p('romance', 'love_bombing', 'we were meant to be', 0.75, 'medium'),

  // -- Fake profession / location --
  p('romance', 'fake_identity', 'military deployment', 0.85, 'high'),
  p('romance', 'fake_identity', 'oil rig', 0.90, 'critical'),
  p('romance', 'fake_identity', 'offshore platform', 0.85, 'high'),
  p('romance', 'fake_identity', 'working overseas', 0.60, 'medium'),
  p('romance', 'fake_identity', 'my late wife', 0.75, 'medium'),
  p('romance', 'fake_identity', 'my late husband', 0.75, 'medium'),
  p('romance', 'fake_identity', 'widower with one child', 0.85, 'high'),
  p('romance', 'fake_identity', 'single father', 0.50, 'low'),
  p('romance', 'fake_identity', 'single mother', 0.50, 'low'),
  p('romance', 'fake_identity', 'i am engineer in', 0.75, 'medium'),
  p('romance', 'fake_identity', 'i am doctor in', 0.75, 'medium'),
  p('romance', 'fake_identity', 'i am soldier in', 0.80, 'high'),
  p('romance', 'fake_identity', 'united nations worker', 0.85, 'high'),
  p('romance', 'fake_identity', 'red cross worker', 0.80, 'high'),
  p('romance', 'fake_identity', 'peace keeping mission', 0.85, 'high'),
  p('romance', 'fake_identity', 'deployed overseas', 0.80, 'high'),
  p('romance', 'fake_identity', 'stationed abroad', 0.75, 'medium'),
  p('romance', 'fake_identity', 'working on a ship', 0.70, 'medium'),
  p('romance', 'fake_identity', 'contractor in iraq', 0.85, 'high'),
  p('romance', 'fake_identity', 'contractor in afghanistan', 0.85, 'high'),
  p('romance', 'fake_identity', 'contractor in syria', 0.85, 'high'),

  // -- Emotional crisis / money request --
  p('romance', 'money_request', 'my daughter is sick', 0.80, 'high'),
  p('romance', 'money_request', 'my son needs surgery', 0.85, 'high'),
  p('romance', 'money_request', 'hospital bills', 0.65, 'medium'),
  p('romance', 'money_request', 'medical emergency', 0.70, 'medium'),
  p('romance', 'money_request', 'visa problems', 0.70, 'medium'),
  p('romance', 'money_request', 'passport issues', 0.70, 'medium'),
  p('romance', 'money_request', 'travel documents', 0.55, 'low'),
  p('romance', 'money_request', 'customs holding my package', 0.80, 'high'),
  p('romance', 'money_request', 'inheritance money', 0.85, 'high'),
  p('romance', 'money_request', 'i am sending you a gift', 0.75, 'medium'),
  p('romance', 'money_request', 'package stuck in customs', 0.80, 'high'),
  p('romance', 'money_request', 'need money for flight', 0.85, 'high'),
  p('romance', 'money_request', 'plane ticket', 0.55, 'low'),
  p('romance', 'money_request', 'come visit you soon', 0.65, 'medium'),
  p('romance', 'money_request', 'want to meet you', 0.50, 'low'),
  p('romance', 'money_request', 'prove your love', 0.85, 'high'),
  p('romance', 'money_request', 'if you really love me', 0.85, 'high'),
  p('romance', 'money_request', 'i will pay you back', 0.80, 'high'),
  p('romance', 'money_request', 'temporary loan', 0.75, 'medium'),
  p('romance', 'money_request', 'just until i get paid', 0.80, 'high'),
  p('romance', 'money_request', 'my account is frozen', 0.80, 'high'),
  p('romance', 'money_request', 'can\'t access my funds', 0.80, 'high'),
  p('romance', 'money_request', 'bank won\'t let me', 0.75, 'medium'),
  p('romance', 'money_request', 'stranded overseas', 0.85, 'high'),
  p('romance', 'money_request', 'stuck at the airport', 0.75, 'medium'),
  p('romance', 'money_request', 'robbed while traveling', 0.85, 'high'),
  p('romance', 'money_request', 'wallet was stolen', 0.70, 'medium'),
  p('romance', 'money_request', 'lost my wallet', 0.65, 'medium'),
  p('romance', 'money_request', 'need help urgently', 0.70, 'medium'),

  // -- Secrecy --
  p('romance', 'secrecy', 'trust me with this', 0.70, 'medium'),
  p('romance', 'secrecy', 'don\'t tell anyone', 0.80, 'high'),
  p('romance', 'secrecy', 'keep this between us', 0.80, 'high'),
  p('romance', 'secrecy', 'our little secret', 0.75, 'medium'),
  p('romance', 'secrecy', 'they won\'t understand', 0.70, 'medium'),
  p('romance', 'secrecy', 'people will be jealous', 0.75, 'medium'),
  p('romance', 'secrecy', 'your family wouldn\'t approve', 0.80, 'high'),
  p('romance', 'secrecy', 'only trust me', 0.80, 'high'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 4: CRYPTO_SCAM  (60+ patterns — NEW)
// ═══════════════════════════════════════════════════════════════════════════
const CRYPTO_SCAM: PatternEntry[] = [
  // -- Investment promises --
  p('crypto_scam', 'investment', 'guaranteed returns', 0.90, 'critical'),
  p('crypto_scam', 'investment', '100% profit', 0.90, 'critical'),
  p('crypto_scam', 'investment', 'double your investment', 0.90, 'critical'),
  p('crypto_scam', 'investment', 'double your money', 0.90, 'critical'),
  p('crypto_scam', 'investment', 'double your bitcoin', 0.95, 'critical'),
  p('crypto_scam', 'investment', '5x returns', 0.90, 'critical'),
  p('crypto_scam', 'investment', '10x guaranteed', 0.95, 'critical'),
  p('crypto_scam', 'investment', 'risk-free investment', 0.90, 'critical'),
  p('crypto_scam', 'investment', 'no-risk trading', 0.90, 'critical'),
  p('crypto_scam', 'investment', 'automated trading bot', 0.80, 'high'),
  p('crypto_scam', 'investment', 'ai trading system', 0.75, 'medium'),
  p('crypto_scam', 'investment', 'passive income daily', 0.80, 'high'),
  p('crypto_scam', 'investment', 'earn while you sleep', 0.80, 'high'),
  p('crypto_scam', 'investment', '1000x potential', 0.85, 'high'),
  p('crypto_scam', 'investment', 'next bitcoin', 0.75, 'medium'),
  p('crypto_scam', 'investment', 'going to the moon', 0.65, 'medium'),
  p('crypto_scam', 'investment', 'guaranteed daily profit', 0.90, 'critical'),
  p('crypto_scam', 'investment', 'daily returns', 0.75, 'medium'),
  p('crypto_scam', 'investment', 'weekly returns', 0.75, 'medium'),
  p('crypto_scam', 'investment', 'monthly returns guaranteed', 0.90, 'critical'),
  p('crypto_scam', 'investment', 'minimum investment', 0.55, 'low'),
  p('crypto_scam', 'investment', 'invest and earn', 0.70, 'medium'),
  p('crypto_scam', 'investment', 'high yield investment', 0.85, 'high'),
  p('crypto_scam', 'investment', 'forex trading opportunity', 0.75, 'medium'),
  p('crypto_scam', 'investment', 'binary options', 0.80, 'high'),

  // -- DeFi / wallet scams --
  p('crypto_scam', 'wallet', 'mining pool', 0.65, 'medium'),
  p('crypto_scam', 'wallet', 'liquidity pool', 0.60, 'medium'),
  p('crypto_scam', 'wallet', 'yield farming', 0.60, 'medium'),
  p('crypto_scam', 'wallet', 'staking rewards', 0.55, 'low'),
  p('crypto_scam', 'wallet', 'airdrop claim', 0.80, 'high'),
  p('crypto_scam', 'wallet', 'free tokens', 0.75, 'medium'),
  p('crypto_scam', 'wallet', 'connect your wallet', 0.90, 'critical'),
  p('crypto_scam', 'wallet', 'enter your seed phrase', 0.95, 'critical'),
  p('crypto_scam', 'wallet', 'recovery phrase', 0.85, 'high'),
  p('crypto_scam', 'wallet', 'private key', 0.85, 'high'),
  p('crypto_scam', 'wallet', 'metamask', 0.50, 'low'),
  p('crypto_scam', 'wallet', 'trust wallet', 0.50, 'low'),
  p('crypto_scam', 'wallet', 'binance smart chain', 0.50, 'low'),
  p('crypto_scam', 'wallet', 'uniswap', 0.45, 'low'),
  p('crypto_scam', 'wallet', 'pancakeswap', 0.45, 'low'),
  p('crypto_scam', 'wallet', 'validate your wallet', 0.90, 'critical'),
  p('crypto_scam', 'wallet', 'verify your wallet', 0.85, 'high'),
  p('crypto_scam', 'wallet', 'sync your wallet', 0.85, 'high'),
  p('crypto_scam', 'wallet', 'wallet verification', 0.80, 'high'),
  p('crypto_scam', 'wallet', 'dapp authorization', 0.70, 'medium'),

  // -- Token / presale scams --
  p('crypto_scam', 'presale', 'presale token', 0.80, 'high'),
  p('crypto_scam', 'presale', 'ico opportunity', 0.80, 'high'),
  p('crypto_scam', 'presale', 'pump and dump', 0.85, 'high'),
  p('crypto_scam', 'presale', 'elon musk crypto', 0.90, 'critical'),
  p('crypto_scam', 'presale', 'celebrity endorsed', 0.75, 'medium'),
  p('crypto_scam', 'presale', 'limited token supply', 0.70, 'medium'),
  p('crypto_scam', 'presale', 'whitelist spot', 0.70, 'medium'),
  p('crypto_scam', 'presale', 'early investor access', 0.75, 'medium'),
  p('crypto_scam', 'presale', 'smart contract audit', 0.50, 'low'),
  p('crypto_scam', 'presale', 'decentralized finance opportunity', 0.70, 'medium'),
  p('crypto_scam', 'presale', 'token launch', 0.55, 'low'),
  p('crypto_scam', 'presale', 'presale whitelist', 0.75, 'medium'),
  p('crypto_scam', 'presale', 'nft giveaway', 0.75, 'medium'),
  p('crypto_scam', 'presale', 'free nft mint', 0.80, 'high'),
  p('crypto_scam', 'presale', 'nft airdrop', 0.80, 'high'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 5: TECH_SUPPORT  (50+ patterns — NEW)
// ═══════════════════════════════════════════════════════════════════════════
const TECH_SUPPORT: PatternEntry[] = [
  // -- Fake alerts --
  p('tech_support', 'fake_alert', 'your computer has been compromised', 0.90, 'critical'),
  p('tech_support', 'fake_alert', 'virus detected on your', 0.85, 'high'),
  p('tech_support', 'fake_alert', 'malware found', 0.80, 'high'),
  p('tech_support', 'fake_alert', 'trojan detected', 0.85, 'high'),
  p('tech_support', 'fake_alert', 'your firewall is disabled', 0.80, 'high'),
  p('tech_support', 'fake_alert', 'your antivirus has expired', 0.80, 'high'),
  p('tech_support', 'fake_alert', 'virus detected', 0.80, 'high'),
  p('tech_support', 'fake_alert', 'malware detected', 0.80, 'high'),
  p('tech_support', 'fake_alert', 'spyware detected', 0.80, 'high'),
  p('tech_support', 'fake_alert', 'your device is infected', 0.85, 'high'),
  p('tech_support', 'fake_alert', 'security scan failed', 0.75, 'medium'),
  p('tech_support', 'fake_alert', 'critical security warning', 0.85, 'high'),
  p('tech_support', 'fake_alert', 'your system is at risk', 0.80, 'high'),
  p('tech_support', 'fake_alert', 'your pc is infected', 0.85, 'high'),
  p('tech_support', 'fake_alert', 'your mac is infected', 0.85, 'high'),

  // -- Call / contact --
  p('tech_support', 'call_scam', 'call this number immediately', 0.85, 'high'),
  p('tech_support', 'call_scam', 'microsoft support', 0.70, 'medium'),
  p('tech_support', 'call_scam', 'apple support', 0.65, 'medium'),
  p('tech_support', 'call_scam', 'tech support number', 0.75, 'medium'),
  p('tech_support', 'call_scam', 'call our technicians', 0.80, 'high'),
  p('tech_support', 'call_scam', 'call our support team', 0.70, 'medium'),
  p('tech_support', 'call_scam', 'call our helpline', 0.70, 'medium'),
  p('tech_support', 'call_scam', 'toll free number', 0.55, 'low'),
  p('tech_support', 'call_scam', 'windows help desk', 0.80, 'high'),
  p('tech_support', 'call_scam', 'geek squad', 0.60, 'medium'),

  // -- Remote access --
  p('tech_support', 'remote_access', 'remote access', 0.70, 'medium'),
  p('tech_support', 'remote_access', 'teamviewer', 0.75, 'medium'),
  p('tech_support', 'remote_access', 'anydesk', 0.80, 'high'),
  p('tech_support', 'remote_access', 'remote desktop', 0.65, 'medium'),
  p('tech_support', 'remote_access', 'let me connect to your computer', 0.90, 'critical'),
  p('tech_support', 'remote_access', 'download this software', 0.75, 'medium'),
  p('tech_support', 'remote_access', 'install this program', 0.75, 'medium'),
  p('tech_support', 'remote_access', 'show me your screen', 0.80, 'high'),
  p('tech_support', 'remote_access', 'screen sharing', 0.55, 'low'),
  p('tech_support', 'remote_access', 'ultraviewer', 0.80, 'high'),
  p('tech_support', 'remote_access', 'logmein', 0.70, 'medium'),
  p('tech_support', 'remote_access', 'connectwise', 0.65, 'medium'),

  // -- License / refund scams --
  p('tech_support', 'license_scam', 'license has expired', 0.70, 'medium'),
  p('tech_support', 'license_scam', 'windows activation', 0.65, 'medium'),
  p('tech_support', 'license_scam', 'subscription expired', 0.60, 'medium'),
  p('tech_support', 'license_scam', 'refund department', 0.80, 'high'),
  p('tech_support', 'license_scam', 'accidental refund', 0.85, 'high'),
  p('tech_support', 'license_scam', 'overpayment', 0.70, 'medium'),
  p('tech_support', 'license_scam', 'we sent too much', 0.85, 'high'),
  p('tech_support', 'license_scam', 'log into your bank', 0.90, 'critical'),
  p('tech_support', 'license_scam', 'renew your license', 0.60, 'medium'),
  p('tech_support', 'license_scam', 'software license expired', 0.65, 'medium'),
  p('tech_support', 'license_scam', 'renew your subscription', 0.55, 'low'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 6: PHISHING  (80+ patterns — NEW)
// ═══════════════════════════════════════════════════════════════════════════
const PHISHING: PatternEntry[] = [
  // -- Account verification --
  p('phishing', 'verification', 'verify your account', 0.80, 'high'),
  p('phishing', 'verification', 'confirm your identity', 0.80, 'high'),
  p('phishing', 'verification', 'update your payment', 0.75, 'medium'),
  p('phishing', 'verification', 'confirm your email', 0.65, 'medium'),
  p('phishing', 'verification', 'click here to verify', 0.85, 'high'),
  p('phishing', 'verification', 'enter your password', 0.85, 'high'),
  p('phishing', 'verification', 'reset your credentials', 0.70, 'medium'),
  p('phishing', 'verification', 'login to confirm', 0.75, 'medium'),
  p('phishing', 'verification', 'confirm your information', 0.70, 'medium'),
  p('phishing', 'verification', 'verify within 24 hours', 0.85, 'high'),
  p('phishing', 'verification', 'verify your identity', 0.80, 'high'),
  p('phishing', 'verification', 'verify your information', 0.75, 'medium'),
  p('phishing', 'verification', 'confirm your details', 0.70, 'medium'),
  p('phishing', 'verification', 'update your information', 0.65, 'medium'),
  p('phishing', 'verification', 'update your details', 0.65, 'medium'),
  p('phishing', 'verification', 're-verify your account', 0.80, 'high'),
  p('phishing', 'verification', 're-confirm your identity', 0.80, 'high'),
  p('phishing', 'verification', 'reactivate your account', 0.80, 'high'),
  p('phishing', 'verification', 'restore your account', 0.75, 'medium'),

  // -- Security alerts --
  p('phishing', 'security_alert', 'unusual login attempt', 0.80, 'high'),
  p('phishing', 'security_alert', 'suspicious activity detected', 0.80, 'high'),
  p('phishing', 'security_alert', 'unauthorized access', 0.85, 'high'),
  p('phishing', 'security_alert', 'unauthorized access detected', 0.85, 'high'),
  p('phishing', 'security_alert', 'account locked', 0.75, 'medium'),
  p('phishing', 'security_alert', 'account suspended', 0.80, 'high'),
  p('phishing', 'security_alert', 'temporary restriction', 0.70, 'medium'),
  p('phishing', 'security_alert', 'your account has been compromised', 0.90, 'critical'),
  p('phishing', 'security_alert', 'action required on your account', 0.80, 'high'),
  p('phishing', 'security_alert', 'unusual activity', 0.75, 'medium'),
  p('phishing', 'security_alert', 'suspicious login', 0.80, 'high'),
  p('phishing', 'security_alert', 'suspicious sign-in', 0.80, 'high'),
  p('phishing', 'security_alert', 'unrecognized device', 0.70, 'medium'),
  p('phishing', 'security_alert', 'new device login', 0.55, 'low'),
  p('phishing', 'security_alert', 'someone tried to sign in', 0.70, 'medium'),
  p('phishing', 'security_alert', 'unauthorized transaction', 0.85, 'high'),

  // -- Billing / payment --
  p('phishing', 'billing', 'billing information expired', 0.80, 'high'),
  p('phishing', 'billing', 'payment method declined', 0.75, 'medium'),
  p('phishing', 'billing', 'update credit card', 0.80, 'high'),
  p('phishing', 'billing', 'update billing information', 0.75, 'medium'),
  p('phishing', 'billing', 'payment failed', 0.65, 'medium'),
  p('phishing', 'billing', 'billing error', 0.65, 'medium'),
  p('phishing', 'billing', 'invoice attached', 0.55, 'low'),
  p('phishing', 'billing', 'past due invoice', 0.70, 'medium'),
  p('phishing', 'billing', 'unpaid invoice', 0.70, 'medium'),

  // -- Generic impersonation --
  p('phishing', 'impersonation', 'dear valued customer', 0.65, 'medium'),
  p('phishing', 'impersonation', 'dear account holder', 0.70, 'medium'),
  p('phishing', 'impersonation', 'dear user', 0.55, 'low'),
  p('phishing', 'impersonation', 'dear member', 0.55, 'low'),
  p('phishing', 'impersonation', 'dear client', 0.50, 'low'),
  p('phishing', 'impersonation', 'official notice', 0.70, 'medium'),
  p('phishing', 'impersonation', 'official communication', 0.70, 'medium'),
  p('phishing', 'impersonation', 'this is an automated message', 0.60, 'medium'),
  p('phishing', 'impersonation', 'security team', 0.65, 'medium'),
  p('phishing', 'impersonation', 'fraud department', 0.70, 'medium'),
  p('phishing', 'impersonation', 'fraud prevention', 0.65, 'medium'),
  p('phishing', 'impersonation', 'account recovery team', 0.70, 'medium'),
  p('phishing', 'impersonation', 'we have detected', 0.65, 'medium'),
  p('phishing', 'impersonation', 'we have noticed', 0.60, 'medium'),
  p('phishing', 'impersonation', 'our records indicate', 0.65, 'medium'),
  p('phishing', 'impersonation', 'our system detected', 0.70, 'medium'),
  p('phishing', 'impersonation', 'for your security', 0.55, 'low'),
  p('phishing', 'impersonation', 'for your protection', 0.55, 'low'),
  p('phishing', 'impersonation', 'authorized representative', 0.70, 'medium'),
  p('phishing', 'impersonation', 'certified agent', 0.70, 'medium'),
  p('phishing', 'impersonation', 'official agent', 0.70, 'medium'),
  p('phishing', 'impersonation', 'your account has been flagged', 0.80, 'high'),
  p('phishing', 'impersonation', 'your account has been reported', 0.75, 'medium'),

  // -- Link manipulation --
  p('phishing', 'link', 'click the link below', 0.60, 'medium'),
  p('phishing', 'link', 'click here to update', 0.70, 'medium'),
  p('phishing', 'link', 'click here to confirm', 0.70, 'medium'),
  p('phishing', 'link', 'click here immediately', 0.75, 'medium'),
  p('phishing', 'link', 'click the button below', 0.55, 'low'),
  p('phishing', 'link', 'log in to your account', 0.55, 'low'),
  p('phishing', 'link', 'sign in to verify', 0.70, 'medium'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 7: EMPLOYMENT_SCAM  (50+ patterns — NEW)
// ═══════════════════════════════════════════════════════════════════════════
const EMPLOYMENT_SCAM: PatternEntry[] = [
  // -- Job offers --
  p('employment_scam', 'job_offer', 'work from home', 0.55, 'low'),
  p('employment_scam', 'job_offer', 'earn $500 per day', 0.90, 'critical'),
  p('employment_scam', 'job_offer', 'make money online', 0.65, 'medium'),
  p('employment_scam', 'job_offer', 'no experience needed', 0.70, 'medium'),
  p('employment_scam', 'job_offer', 'no experience required', 0.70, 'medium'),
  p('employment_scam', 'job_offer', 'no skills required', 0.70, 'medium'),
  p('employment_scam', 'job_offer', 'no degree required', 0.65, 'medium'),
  p('employment_scam', 'job_offer', 'start immediately', 0.55, 'low'),
  p('employment_scam', 'job_offer', 'remote position available', 0.50, 'low'),
  p('employment_scam', 'job_offer', 'data entry job', 0.55, 'low'),
  p('employment_scam', 'job_offer', 'mystery shopper', 0.80, 'high'),
  p('employment_scam', 'job_offer', 'package reshipping', 0.90, 'critical'),
  p('employment_scam', 'job_offer', 'check cashing', 0.85, 'high'),
  p('employment_scam', 'job_offer', 'personal assistant needed', 0.70, 'medium'),
  p('employment_scam', 'job_offer', 'flexible hours', 0.40, 'low'),
  p('employment_scam', 'job_offer', 'be your own boss', 0.70, 'medium'),
  p('employment_scam', 'job_offer', 'multiple streams of income', 0.75, 'medium'),
  p('employment_scam', 'job_offer', 'training provided', 0.40, 'low'),
  p('employment_scam', 'job_offer', 'equipment provided', 0.45, 'low'),
  p('employment_scam', 'job_offer', 'send deposit for equipment', 0.90, 'critical'),
  p('employment_scam', 'job_offer', 'hiring immediately', 0.50, 'low'),
  p('employment_scam', 'job_offer', 'easy money', 0.75, 'medium'),
  p('employment_scam', 'job_offer', 'make money fast', 0.80, 'high'),
  p('employment_scam', 'job_offer', 'side hustle', 0.40, 'low'),
  p('employment_scam', 'job_offer', 'weekly paycheck guaranteed', 0.80, 'high'),

  // -- Income claims --
  p('employment_scam', 'income_claim', 'earn up to $1000 daily', 0.90, 'critical'),
  p('employment_scam', 'income_claim', 'earn $1000 per week', 0.85, 'high'),
  p('employment_scam', 'income_claim', 'six figure income', 0.75, 'medium'),
  p('employment_scam', 'income_claim', 'life changing income', 0.75, 'medium'),
  p('employment_scam', 'income_claim', 'life changing opportunity', 0.75, 'medium'),
  p('employment_scam', 'income_claim', 'financial independence', 0.60, 'medium'),
  p('employment_scam', 'income_claim', 'unlimited earning potential', 0.80, 'high'),
  p('employment_scam', 'income_claim', 'residual income', 0.60, 'medium'),

  // -- MLM / pyramid --
  p('employment_scam', 'mlm', 'ground floor opportunity', 0.80, 'high'),
  p('employment_scam', 'mlm', 'build your team', 0.55, 'low'),
  p('employment_scam', 'mlm', 'recruit new members', 0.70, 'medium'),
  p('employment_scam', 'mlm', 'downline', 0.75, 'medium'),
  p('employment_scam', 'mlm', 'upline', 0.75, 'medium'),
  p('employment_scam', 'mlm', 'network marketing', 0.55, 'low'),
  p('employment_scam', 'mlm', 'join my team', 0.60, 'medium'),
  p('employment_scam', 'mlm', 'direct sales opportunity', 0.55, 'low'),

  // -- Advance fee employment --
  p('employment_scam', 'advance_fee', 'direct deposit bonus', 0.70, 'medium'),
  p('employment_scam', 'advance_fee', 'sign-on bonus', 0.50, 'low'),
  p('employment_scam', 'advance_fee', 'pay for training materials', 0.85, 'high'),
  p('employment_scam', 'advance_fee', 'background check fee', 0.80, 'high'),
  p('employment_scam', 'advance_fee', 'onboarding fee', 0.85, 'high'),
  p('employment_scam', 'advance_fee', 'application fee', 0.70, 'medium'),
  p('employment_scam', 'advance_fee', 'certification fee', 0.65, 'medium'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 8: DELIVERY_SCAM  (40+ patterns — NEW)
// ═══════════════════════════════════════════════════════════════════════════
const DELIVERY_SCAM: PatternEntry[] = [
  p('delivery_scam', 'failed_delivery', 'package delivery failed', 0.80, 'high'),
  p('delivery_scam', 'failed_delivery', 'delivery attempt unsuccessful', 0.80, 'high'),
  p('delivery_scam', 'failed_delivery', 'reschedule delivery', 0.65, 'medium'),
  p('delivery_scam', 'failed_delivery', 'shipment on hold', 0.70, 'medium'),
  p('delivery_scam', 'failed_delivery', 'customs clearance required', 0.75, 'medium'),
  p('delivery_scam', 'failed_delivery', 'pay shipping fee', 0.80, 'high'),
  p('delivery_scam', 'failed_delivery', 'unable to deliver', 0.65, 'medium'),
  p('delivery_scam', 'failed_delivery', 'address verification needed', 0.70, 'medium'),
  p('delivery_scam', 'failed_delivery', 'delivery fee required', 0.80, 'high'),
  p('delivery_scam', 'failed_delivery', 'package returned to sender', 0.65, 'medium'),
  p('delivery_scam', 'failed_delivery', 'claim your package', 0.75, 'medium'),
  p('delivery_scam', 'failed_delivery', 'redelivery fee', 0.80, 'high'),
  p('delivery_scam', 'failed_delivery', 'delivery scheduled', 0.40, 'low'),
  p('delivery_scam', 'failed_delivery', 'delivery on hold', 0.70, 'medium'),
  p('delivery_scam', 'failed_delivery', 'package awaiting pickup', 0.60, 'medium'),
  p('delivery_scam', 'failed_delivery', 'confirm delivery address', 0.65, 'medium'),
  p('delivery_scam', 'failed_delivery', 'update shipping address', 0.65, 'medium'),
  p('delivery_scam', 'failed_delivery', 'delivery exception', 0.60, 'medium'),
  p('delivery_scam', 'failed_delivery', 'parcel held at customs', 0.75, 'medium'),

  // -- Carrier impersonation --
  p('delivery_scam', 'carrier', 'usps notification', 0.70, 'medium'),
  p('delivery_scam', 'carrier', 'fedex delivery', 0.55, 'low'),
  p('delivery_scam', 'carrier', 'ups package', 0.55, 'low'),
  p('delivery_scam', 'carrier', 'dhl express', 0.55, 'low'),
  p('delivery_scam', 'carrier', 'amazon delivery', 0.50, 'low'),
  p('delivery_scam', 'carrier', 'your order has shipped', 0.40, 'low'),
  p('delivery_scam', 'carrier', 'tracking number', 0.35, 'low'),
  p('delivery_scam', 'carrier', 'track your package', 0.40, 'low'),
  p('delivery_scam', 'carrier', 'royal mail notification', 0.65, 'medium'),
  p('delivery_scam', 'carrier', 'canada post delivery', 0.55, 'low'),
  p('delivery_scam', 'carrier', 'australia post', 0.55, 'low'),
  p('delivery_scam', 'carrier', 'hermes delivery', 0.55, 'low'),
  p('delivery_scam', 'carrier', 'dpd delivery', 0.55, 'low'),

  // -- Fee demands --
  p('delivery_scam', 'fee', 'small delivery fee', 0.80, 'high'),
  p('delivery_scam', 'fee', 'nominal fee', 0.70, 'medium'),
  p('delivery_scam', 'fee', 'pay customs charges', 0.80, 'high'),
  p('delivery_scam', 'fee', 'import duty payment', 0.75, 'medium'),
  p('delivery_scam', 'fee', 'storage fee', 0.65, 'medium'),
  p('delivery_scam', 'fee', 'handling charges', 0.65, 'medium'),
  p('delivery_scam', 'fee', 'pay to release package', 0.85, 'high'),
  p('delivery_scam', 'fee', 'pay to release shipment', 0.85, 'high'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 9: GOVERNMENT_SCAM  (40+ patterns — NEW)
// ═══════════════════════════════════════════════════════════════════════════
const GOVERNMENT_SCAM: PatternEntry[] = [
  // -- IRS / tax --
  p('government_scam', 'irs', 'irs notice', 0.80, 'high'),
  p('government_scam', 'irs', 'tax refund', 0.70, 'medium'),
  p('government_scam', 'irs', 'tax debt', 0.80, 'high'),
  p('government_scam', 'irs', 'back taxes owed', 0.85, 'high'),
  p('government_scam', 'irs', 'irs audit', 0.75, 'medium'),
  p('government_scam', 'irs', 'irs investigation', 0.80, 'high'),
  p('government_scam', 'irs', 'irs payment', 0.80, 'high'),
  p('government_scam', 'irs', 'tax lien', 0.80, 'high'),
  p('government_scam', 'irs', 'tax levy', 0.80, 'high'),
  p('government_scam', 'irs', 'owe the irs', 0.85, 'high'),
  p('government_scam', 'irs', 'owe back taxes', 0.85, 'high'),

  // -- Social security --
  p('government_scam', 'ssa', 'social security administration', 0.75, 'medium'),
  p('government_scam', 'ssa', 'your benefits suspended', 0.85, 'high'),
  p('government_scam', 'ssa', 'social security suspended', 0.90, 'critical'),
  p('government_scam', 'ssa', 'your social security number has been', 0.90, 'critical'),
  p('government_scam', 'ssa', 'social security fraud', 0.85, 'high'),
  p('government_scam', 'ssa', 'suspend your social security', 0.90, 'critical'),

  // -- Medicare / benefits --
  p('government_scam', 'benefits', 'medicare enrollment', 0.60, 'medium'),
  p('government_scam', 'benefits', 'stimulus payment', 0.70, 'medium'),
  p('government_scam', 'benefits', 'government grant', 0.80, 'high'),
  p('government_scam', 'benefits', 'free government money', 0.90, 'critical'),
  p('government_scam', 'benefits', 'unclaimed government funds', 0.85, 'high'),
  p('government_scam', 'benefits', 'government assistance program', 0.60, 'medium'),
  p('government_scam', 'benefits', 'economic relief payment', 0.70, 'medium'),
  p('government_scam', 'benefits', 'disaster relief fund', 0.60, 'medium'),

  // -- Law enforcement --
  p('government_scam', 'law_enforcement', 'fbi warning', 0.85, 'high'),
  p('government_scam', 'law_enforcement', 'dea investigation', 0.85, 'high'),
  p('government_scam', 'law_enforcement', 'homeland security', 0.75, 'medium'),
  p('government_scam', 'law_enforcement', 'immigration services', 0.60, 'medium'),
  p('government_scam', 'law_enforcement', 'green card lottery', 0.85, 'high'),
  p('government_scam', 'law_enforcement', 'jury duty summons', 0.75, 'medium'),
  p('government_scam', 'law_enforcement', 'court appearance required', 0.80, 'high'),
  p('government_scam', 'law_enforcement', 'bench warrant issued', 0.85, 'high'),
  p('government_scam', 'law_enforcement', 'failure to appear', 0.80, 'high'),
  p('government_scam', 'law_enforcement', 'arrest warrant', 0.85, 'high'),
  p('government_scam', 'law_enforcement', 'police investigation', 0.70, 'medium'),
  p('government_scam', 'law_enforcement', 'under investigation', 0.75, 'medium'),
  p('government_scam', 'law_enforcement', 'department of justice', 0.75, 'medium'),
  p('government_scam', 'law_enforcement', 'drug enforcement', 0.80, 'high'),
  p('government_scam', 'law_enforcement', 'interpol notice', 0.85, 'high'),
  p('government_scam', 'law_enforcement', 'customs and border', 0.60, 'medium'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 10: ISOLATION  (30+ patterns — NEW)
// ═══════════════════════════════════════════════════════════════════════════
const ISOLATION: PatternEntry[] = [
  p('isolation', 'secrecy', 'don\'t tell anyone', 0.80, 'high'),
  p('isolation', 'secrecy', 'keep this between us', 0.80, 'high'),
  p('isolation', 'secrecy', 'do not contact your bank', 0.90, 'critical'),
  p('isolation', 'secrecy', 'don\'t call the police', 0.90, 'critical'),
  p('isolation', 'secrecy', 'this is confidential', 0.65, 'medium'),
  p('isolation', 'secrecy', 'top secret', 0.60, 'medium'),
  p('isolation', 'secrecy', 'classified information', 0.70, 'medium'),
  p('isolation', 'secrecy', 'sworn to secrecy', 0.75, 'medium'),
  p('isolation', 'secrecy', 'non-disclosure', 0.50, 'low'),
  p('isolation', 'secrecy', 'if you tell anyone', 0.80, 'high'),
  p('isolation', 'secrecy', 'our little secret', 0.75, 'medium'),
  p('isolation', 'secrecy', 'they won\'t understand', 0.70, 'medium'),
  p('isolation', 'secrecy', 'people will be jealous', 0.75, 'medium'),
  p('isolation', 'secrecy', 'your family wouldn\'t approve', 0.80, 'high'),
  p('isolation', 'secrecy', 'only trust me', 0.80, 'high'),
  p('isolation', 'secrecy', 'don\'t share this with anyone', 0.80, 'high'),
  p('isolation', 'secrecy', 'do not discuss this', 0.75, 'medium'),
  p('isolation', 'secrecy', 'do not tell your family', 0.85, 'high'),
  p('isolation', 'secrecy', 'do not tell your friends', 0.80, 'high'),
  p('isolation', 'secrecy', 'do not contact anyone', 0.90, 'critical'),
  p('isolation', 'secrecy', 'do not contact the police', 0.90, 'critical'),
  p('isolation', 'secrecy', 'do not go to the police', 0.90, 'critical'),
  p('isolation', 'secrecy', 'do not inform anyone', 0.85, 'high'),
  p('isolation', 'secrecy', 'strictly confidential', 0.65, 'medium'),
  p('isolation', 'secrecy', 'for your eyes only', 0.65, 'medium'),
  p('isolation', 'secrecy', 'private and confidential', 0.55, 'low'),
  p('isolation', 'secrecy', 'tell no one', 0.80, 'high'),
  p('isolation', 'secrecy', 'between you and me', 0.60, 'medium'),
  p('isolation', 'secrecy', 'no one else needs to know', 0.75, 'medium'),
  p('isolation', 'secrecy', 'your bank will try to stop you', 0.90, 'critical'),
  p('isolation', 'secrecy', 'the bank will block this', 0.85, 'high'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 11: SOCIAL_PROOF  (30+ patterns)
// ═══════════════════════════════════════════════════════════════════════════
const SOCIAL_PROOF: PatternEntry[] = [
  p('social_proof', 'popularity', 'millions of users', 0.55, 'low'),
  p('social_proof', 'popularity', 'over 10 million downloads', 0.55, 'low'),
  p('social_proof', 'popularity', 'trusted by thousands', 0.55, 'low'),
  p('social_proof', 'popularity', 'thousands of customers', 0.50, 'low'),
  p('social_proof', 'popularity', 'millions of customers', 0.55, 'low'),
  p('social_proof', 'popularity', 'everyone is doing it', 0.60, 'medium'),
  p('social_proof', 'popularity', 'thousands have already', 0.60, 'medium'),
  p('social_proof', 'popularity', 'join millions', 0.55, 'low'),

  // -- Media / endorsement --
  p('social_proof', 'endorsement', 'as seen on tv', 0.65, 'medium'),
  p('social_proof', 'endorsement', 'featured on fox news', 0.70, 'medium'),
  p('social_proof', 'endorsement', 'featured on cnn', 0.70, 'medium'),
  p('social_proof', 'endorsement', 'featured on bbc', 0.70, 'medium'),
  p('social_proof', 'endorsement', 'endorsed by', 0.60, 'medium'),
  p('social_proof', 'endorsement', 'celebrity approved', 0.70, 'medium'),
  p('social_proof', 'endorsement', 'doctor recommended', 0.55, 'low'),
  p('social_proof', 'endorsement', 'clinically proven', 0.50, 'low'),
  p('social_proof', 'endorsement', 'recommended by experts', 0.50, 'low'),
  p('social_proof', 'endorsement', 'trusted by experts', 0.50, 'low'),
  p('social_proof', 'endorsement', 'as seen on', 0.55, 'low'),
  p('social_proof', 'endorsement', 'featured in', 0.45, 'low'),
  p('social_proof', 'endorsement', 'recommended by', 0.45, 'low'),

  // -- Reviews / ratings --
  p('social_proof', 'reviews', '100% satisfaction', 0.60, 'medium'),
  p('social_proof', 'reviews', 'money back guarantee', 0.55, 'low'),
  p('social_proof', 'reviews', 'five star reviews', 0.55, 'low'),
  p('social_proof', 'reviews', 'award winning', 0.45, 'low'),
  p('social_proof', 'reviews', 'best seller', 0.40, 'low'),
  p('social_proof', 'reviews', 'top rated', 0.40, 'low'),
  p('social_proof', 'reviews', 'customer testimonials', 0.40, 'low'),
  p('social_proof', 'reviews', 'verified reviews', 0.40, 'low'),
  p('social_proof', 'reviews', 'satisfaction guaranteed', 0.55, 'low'),
  p('social_proof', 'reviews', 'proven results', 0.55, 'low'),
  p('social_proof', 'reviews', 'success stories', 0.45, 'low'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 12: TOO_GOOD_TO_BE_TRUE  (40+ patterns)
// ═══════════════════════════════════════════════════════════════════════════
const TOO_GOOD: PatternEntry[] = [
  // -- Winner / prize --
  p('too_good', 'winner', 'you have been selected', 0.85, 'high'),
  p('too_good', 'winner', 'congratulations you won', 0.90, 'critical'),
  p('too_good', 'winner', 'you are a winner', 0.85, 'high'),
  p('too_good', 'winner', 'claim your prize', 0.90, 'critical'),
  p('too_good', 'winner', 'lottery winner', 0.85, 'high'),
  p('too_good', 'winner', 'jackpot notification', 0.85, 'high'),
  p('too_good', 'winner', 'sweepstakes winner', 0.85, 'high'),
  p('too_good', 'winner', 'prize notification', 0.80, 'high'),
  p('too_good', 'winner', 'claim your reward', 0.80, 'high'),
  p('too_good', 'winner', 'you have won', 0.80, 'high'),
  p('too_good', 'winner', 'you\'ve been selected', 0.80, 'high'),
  p('too_good', 'winner', 'winner notification', 0.85, 'high'),
  p('too_good', 'winner', 'grand prize winner', 0.90, 'critical'),
  p('too_good', 'winner', 'lucky winner', 0.85, 'high'),

  // -- Inheritance / funds --
  p('too_good', 'inheritance', 'inheritance from', 0.85, 'high'),
  p('too_good', 'inheritance', 'million dollars', 0.80, 'high'),
  p('too_good', 'inheritance', 'unclaimed funds', 0.85, 'high'),
  p('too_good', 'inheritance', 'dormant account', 0.80, 'high'),
  p('too_good', 'inheritance', 'beneficiary of', 0.80, 'high'),
  p('too_good', 'inheritance', 'share of profits', 0.75, 'medium'),
  p('too_good', 'inheritance', 'compensation fund', 0.75, 'medium'),
  p('too_good', 'inheritance', 'grant approval', 0.70, 'medium'),
  p('too_good', 'inheritance', 'unclaimed inheritance', 0.85, 'high'),
  p('too_good', 'inheritance', 'funds awaiting claim', 0.80, 'high'),
  p('too_good', 'inheritance', 'deceased client', 0.80, 'high'),
  p('too_good', 'inheritance', 'next of kin', 0.80, 'high'),

  // -- Free stuff --
  p('too_good', 'free_stuff', 'free iphone', 0.90, 'critical'),
  p('too_good', 'free_stuff', 'free vacation', 0.85, 'high'),
  p('too_good', 'free_stuff', 'free gift', 0.65, 'medium'),
  p('too_good', 'free_stuff', 'free money', 0.90, 'critical'),
  p('too_good', 'free_stuff', 'free macbook', 0.90, 'critical'),
  p('too_good', 'free_stuff', 'free samsung', 0.85, 'high'),
  p('too_good', 'free_stuff', 'free prize', 0.85, 'high'),
  p('too_good', 'free_stuff', 'completely free', 0.65, 'medium'),
  p('too_good', 'free_stuff', 'totally free', 0.65, 'medium'),
  p('too_good', 'free_stuff', 'zero cost', 0.60, 'medium'),
  p('too_good', 'free_stuff', 'free laptop', 0.85, 'high'),
  p('too_good', 'free_stuff', 'free ipad', 0.85, 'high'),

  // -- Opportunities --
  p('too_good', 'opportunity', 'exclusive offer just for you', 0.75, 'medium'),
  p('too_good', 'opportunity', 'one time opportunity', 0.80, 'high'),
  p('too_good', 'opportunity', 'secret method', 0.80, 'high'),
  p('too_good', 'opportunity', 'secret system', 0.80, 'high'),
  p('too_good', 'opportunity', 'secret formula', 0.80, 'high'),
  p('too_good', 'opportunity', 'they don\'t want you to know', 0.80, 'high'),
  p('too_good', 'opportunity', 'exclusive access', 0.60, 'medium'),
  p('too_good', 'opportunity', 'exclusive invitation', 0.65, 'medium'),
  p('too_good', 'opportunity', 'exclusive offer', 0.60, 'medium'),
  p('too_good', 'opportunity', 'exclusive deal', 0.60, 'medium'),
  p('too_good', 'opportunity', 'exclusive membership', 0.60, 'medium'),
  p('too_good', 'opportunity', 'change your life', 0.70, 'medium'),
  p('too_good', 'opportunity', 'life changing opportunity', 0.75, 'medium'),
  p('too_good', 'opportunity', 'once in a lifetime', 0.75, 'medium'),
  p('too_good', 'opportunity', 'rare opportunity', 0.70, 'medium'),
  p('too_good', 'opportunity', 'pre-approved loan', 0.80, 'high'),
  p('too_good', 'opportunity', 'pre-approved credit', 0.80, 'high'),
  p('too_good', 'opportunity', 'you qualify for', 0.55, 'low'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 13: THREAT  (40+ patterns)
// ═══════════════════════════════════════════════════════════════════════════
const THREAT: PatternEntry[] = [
  // -- Device compromise --
  p('threat', 'device_compromise', 'your computer has been compromised', 0.90, 'critical'),
  p('threat', 'device_compromise', 'your device has been compromised', 0.90, 'critical'),
  p('threat', 'device_compromise', 'your account has been hacked', 0.90, 'critical'),
  p('threat', 'device_compromise', 'you have been hacked', 0.90, 'critical'),
  p('threat', 'device_compromise', 'your computer is infected', 0.85, 'high'),
  p('threat', 'device_compromise', 'unauthorized access detected', 0.85, 'high'),
  p('threat', 'device_compromise', 'security breach detected', 0.85, 'high'),
  p('threat', 'device_compromise', 'account terminated', 0.80, 'high'),
  p('threat', 'device_compromise', 'permanently banned', 0.80, 'high'),
  p('threat', 'device_compromise', 'identity theft', 0.85, 'high'),
  p('threat', 'device_compromise', 'identity stolen', 0.85, 'high'),
  p('threat', 'device_compromise', 'someone is using your identity', 0.85, 'high'),

  // -- Extortion --
  p('threat', 'extortion', 'we have your photos', 0.90, 'critical'),
  p('threat', 'extortion', 'we have your videos', 0.90, 'critical'),
  p('threat', 'extortion', 'we have your data', 0.85, 'high'),
  p('threat', 'extortion', 'we have your browsing history', 0.90, 'critical'),
  p('threat', 'extortion', 'we have your files', 0.85, 'high'),
  p('threat', 'extortion', 'send to all your contacts', 0.90, 'critical'),
  p('threat', 'extortion', 'recorded your screen', 0.90, 'critical'),
  p('threat', 'extortion', 'recorded your webcam', 0.90, 'critical'),
  p('threat', 'extortion', 'recorded you', 0.80, 'high'),
  p('threat', 'extortion', 'your data will be leaked', 0.90, 'critical'),
  p('threat', 'extortion', 'your data will be exposed', 0.90, 'critical'),
  p('threat', 'extortion', 'your data will be published', 0.90, 'critical'),
  p('threat', 'extortion', 'your data will be sold', 0.85, 'high'),
  p('threat', 'extortion', 'we will release your', 0.85, 'high'),
  p('threat', 'extortion', 'private information will be', 0.85, 'high'),
  p('threat', 'extortion', 'embarrassing content', 0.80, 'high'),
  p('threat', 'extortion', 'intimate images', 0.85, 'high'),
  p('threat', 'extortion', 'compromising photos', 0.85, 'high'),

  // -- Legal / authority threats --
  p('threat', 'legal', 'we will report to authorities', 0.75, 'medium'),
  p('threat', 'legal', 'we will notify the police', 0.75, 'medium'),
  p('threat', 'legal', 'we will notify the fbi', 0.80, 'high'),
  p('threat', 'legal', 'we will notify the irs', 0.80, 'high'),
  p('threat', 'legal', 'your credit score will be damaged', 0.75, 'medium'),
  p('threat', 'legal', 'sent to collections', 0.75, 'medium'),
  p('threat', 'legal', 'debt collector', 0.70, 'medium'),
  p('threat', 'legal', 'permanent ban', 0.70, 'medium'),
  p('threat', 'legal', 'permanently delete', 0.75, 'medium'),
  p('threat', 'legal', 'permanently suspend', 0.75, 'medium'),
  p('threat', 'legal', 'blacklisted', 0.70, 'medium'),
  p('threat', 'legal', 'data loss', 0.60, 'medium'),
  p('threat', 'legal', 'payment declined', 0.55, 'low'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 14: IMPERSONATION  (30+ patterns)
// ═══════════════════════════════════════════════════════════════════════════
const IMPERSONATION: PatternEntry[] = [
  p('impersonation', 'brand', 'paypal', 0.30, 'low'),
  p('impersonation', 'brand', 'amazon', 0.25, 'low'),
  p('impersonation', 'brand', 'apple', 0.25, 'low'),
  p('impersonation', 'brand', 'google', 0.25, 'low'),
  p('impersonation', 'brand', 'microsoft', 0.25, 'low'),
  p('impersonation', 'brand', 'netflix', 0.25, 'low'),
  p('impersonation', 'brand', 'facebook', 0.25, 'low'),
  p('impersonation', 'brand', 'instagram', 0.25, 'low'),
  p('impersonation', 'brand', 'office 365', 0.30, 'low'),
  p('impersonation', 'brand', 'outlook', 0.25, 'low'),
  p('impersonation', 'brand', 'onedrive', 0.30, 'low'),
  p('impersonation', 'brand', 'sharepoint', 0.30, 'low'),
  p('impersonation', 'brand', 'coinbase', 0.30, 'low'),
  p('impersonation', 'brand', 'binance', 0.30, 'low'),
  p('impersonation', 'brand', 'docusign', 0.30, 'low'),
  p('impersonation', 'brand', 'linkedin', 0.25, 'low'),
  p('impersonation', 'brand', 'whatsapp', 0.25, 'low'),
  p('impersonation', 'brand', 'spotify', 0.25, 'low'),
  p('impersonation', 'brand', 'dropbox', 0.25, 'low'),

  // -- Authority impersonation --
  p('impersonation', 'authority', 'official notice', 0.70, 'medium'),
  p('impersonation', 'authority', 'official communication', 0.70, 'medium'),
  p('impersonation', 'authority', 'it department', 0.65, 'medium'),
  p('impersonation', 'authority', 'compliance team', 0.65, 'medium'),
  p('impersonation', 'authority', 'compliance officer', 0.70, 'medium'),
  p('impersonation', 'authority', 'regulatory authority', 0.70, 'medium'),
  p('impersonation', 'authority', 'pursuant to', 0.60, 'medium'),
  p('impersonation', 'authority', 'in accordance with', 0.55, 'low'),
  p('impersonation', 'authority', 'by order of', 0.70, 'medium'),
  p('impersonation', 'authority', 'on behalf of', 0.50, 'low'),
  p('impersonation', 'authority', 'badge number', 0.75, 'medium'),
  p('impersonation', 'authority', 'officer id', 0.75, 'medium'),
  p('impersonation', 'authority', 'case number', 0.60, 'medium'),
  p('impersonation', 'authority', 'case file', 0.60, 'medium'),
  p('impersonation', 'authority', 'reference number', 0.45, 'low'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 15: QR_CODE  (10 patterns)
// ═══════════════════════════════════════════════════════════════════════════
const QR_CODE: PatternEntry[] = [
  p('qr_code', 'scan', 'scan this qr', 0.65, 'medium'),
  p('qr_code', 'scan', 'scan this code', 0.55, 'low'),
  p('qr_code', 'scan', 'scan this barcode', 0.55, 'low'),
  p('qr_code', 'scan', 'qr code below', 0.60, 'medium'),
  p('qr_code', 'scan', 'qr code attached', 0.65, 'medium'),
  p('qr_code', 'scan', 'scan to pay', 0.75, 'medium'),
  p('qr_code', 'scan', 'scan to verify', 0.75, 'medium'),
  p('qr_code', 'scan', 'scan to confirm', 0.75, 'medium'),
  p('qr_code', 'scan', 'scan to claim', 0.80, 'high'),
  p('qr_code', 'scan', 'qr code payment', 0.80, 'high'),
  p('qr_code', 'scan', 'point your camera', 0.60, 'medium'),
  p('qr_code', 'scan', 'scan to login', 0.70, 'medium'),
  p('qr_code', 'scan', 'scan to sign in', 0.70, 'medium'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 16: SOCIAL_MEDIA  (15 patterns)
// ═══════════════════════════════════════════════════════════════════════════
const SOCIAL_MEDIA: PatternEntry[] = [
  p('social_media', 'fake_verification', 'verified badge', 0.75, 'medium'),
  p('social_media', 'fake_verification', 'verified account', 0.70, 'medium'),
  p('social_media', 'fake_verification', 'blue check', 0.70, 'medium'),
  p('social_media', 'fake_verification', 'blue badge', 0.70, 'medium'),
  p('social_media', 'fake_verification', 'get verified', 0.70, 'medium'),
  p('social_media', 'official_claim', 'official page', 0.55, 'low'),
  p('social_media', 'official_claim', 'official account', 0.55, 'low'),
  p('social_media', 'official_claim', 'official channel', 0.55, 'low'),
  p('social_media', 'giveaway', 'giveaway', 0.50, 'low'),
  p('social_media', 'giveaway', 'give away', 0.50, 'low'),
  p('social_media', 'copyright', 'copyright strike', 0.70, 'medium'),
  p('social_media', 'copyright', 'copyright violation', 0.70, 'medium'),
  p('social_media', 'copyright', 'dmca notice', 0.70, 'medium'),
  p('social_media', 'copyright', 'dmca takedown', 0.70, 'medium'),
  p('social_media', 'deletion', 'link in bio', 0.40, 'low'),
];

// ═══════════════════════════════════════════════════════════════════════════
// ASSEMBLED MASTER PATTERNS
// ═══════════════════════════════════════════════════════════════════════════

export const MASTER_PATTERNS: PatternEntry[] = [
  ...URGENCY,
  ...FINANCIAL,
  ...ROMANCE,
  ...CRYPTO_SCAM,
  ...TECH_SUPPORT,
  ...PHISHING,
  ...EMPLOYMENT_SCAM,
  ...DELIVERY_SCAM,
  ...GOVERNMENT_SCAM,
  ...ISOLATION,
  ...SOCIAL_PROOF,
  ...TOO_GOOD,
  ...THREAT,
  ...IMPERSONATION,
  ...QR_CODE,
  ...SOCIAL_MEDIA,
];

// ---------------------------------------------------------------------------
// Build the Aho-Corasick automaton ONCE at module load
// ---------------------------------------------------------------------------

/** Map from pattern text (lowercased) to its metadata entries */
const patternIndex = new Map<string, PatternEntry[]>();
for (const entry of MASTER_PATTERNS) {
  const existing = patternIndex.get(entry.text);
  if (existing) {
    existing.push(entry);
  } else {
    patternIndex.set(entry.text, [entry]);
  }
}

/** Deduplicated keyword list for the automaton */
const uniqueKeywords = Array.from(patternIndex.keys());

/** The Aho-Corasick automaton — built once, searched many times */
const automaton = new AhoCorasick(uniqueKeywords);

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Scan a text string against 500+ patterns in a single pass.
 * Returns all matches with full metadata (group, category, weight, severity).
 *
 * Complexity: O(N + M + Z) where N = text length, M = total pattern chars,
 * Z = number of matches.  Replaces the old O(N * P) regex-per-pattern loops.
 */
export function scanPatterns(text: string): PatternMatch[] {
  const lower = text.toLowerCase();
  const raw = automaton.search(lower); // Array<[endIndex, matchedKeywords[]]>

  const matches: PatternMatch[] = [];
  const seen = new Set<string>(); // deduplicate by pattern id

  for (const [endIndex, keywords] of raw) {
    for (const keyword of keywords) {
      const entries = patternIndex.get(keyword);
      if (!entries) continue;
      for (const entry of entries) {
        if (seen.has(entry.id)) continue;
        seen.add(entry.id);
        matches.push({
          id: entry.id,
          text: keyword,
          category: entry.category,
          group: entry.group,
          weight: entry.weight,
          severity: entry.severity,
          position: endIndex,
        });
      }
    }
  }

  return matches;
}

/**
 * Convenience: get a count of matches per group.
 */
export function scanPatternCounts(text: string): Record<string, number> {
  const matches = scanPatterns(text);
  const counts: Record<string, number> = {};
  for (const m of matches) {
    counts[m.group] = (counts[m.group] || 0) + 1;
  }
  return counts;
}

/**
 * Convenience: get the maximum weight from each group.
 */
export function scanPatternMaxWeights(text: string): Record<string, number> {
  const matches = scanPatterns(text);
  const maxWeights: Record<string, number> = {};
  for (const m of matches) {
    if (!maxWeights[m.group] || m.weight > maxWeights[m.group]) {
      maxWeights[m.group] = m.weight;
    }
  }
  return maxWeights;
}

// Export the pattern count for diagnostics
export const PATTERN_COUNT = MASTER_PATTERNS.length;
export const UNIQUE_PATTERN_COUNT = uniqueKeywords.length;
