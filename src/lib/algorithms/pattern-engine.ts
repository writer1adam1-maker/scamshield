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
// EXPANDED: CRYPTO_SCAM additions (30+ new patterns)
// ═══════════════════════════════════════════════════════════════════════════
const CRYPTO_SCAM_EXT: PatternEntry[] = [
  p('crypto_scam', 'nft', 'nft drop', 0.70, 'medium'),
  p('crypto_scam', 'nft', 'mint now', 0.75, 'medium'),
  p('crypto_scam', 'nft', 'presale exclusive', 0.80, 'high'),
  p('crypto_scam', 'nft', 'connect wallet to mint', 0.90, 'critical'),
  p('crypto_scam', 'nft', 'approve transaction', 0.85, 'high'),
  p('crypto_scam', 'nft', 'seed phrase required', 0.95, 'critical'),
  p('crypto_scam', 'nft', 'crypto recovery service', 0.85, 'high'),
  p('crypto_scam', 'nft', 'stolen crypto recovery', 0.85, 'high'),
  p('crypto_scam', 'nft', 'crypto doubler', 0.90, 'critical'),
  p('crypto_scam', 'nft', 'bitcoin generator', 0.90, 'critical'),
  p('crypto_scam', 'nft', 'ethereum giveaway', 0.90, 'critical'),
  p('crypto_scam', 'nft', 'celebrity crypto', 0.85, 'high'),
  p('crypto_scam', 'nft', 'defi rug pull', 0.90, 'critical'),
  p('crypto_scam', 'nft', 'free crypto airdrop', 0.85, 'high'),
  p('crypto_scam', 'nft', 'claim free tokens', 0.85, 'high'),
  p('crypto_scam', 'nft', 'wallet drainer', 0.95, 'critical'),
  p('crypto_scam', 'nft', 'unlimited mining', 0.85, 'high'),
  p('crypto_scam', 'nft', 'cloud mining contract', 0.80, 'high'),
  p('crypto_scam', 'nft', 'bitcoin multiplier', 0.95, 'critical'),
  p('crypto_scam', 'nft', 'crypto signal group', 0.75, 'medium'),
  p('crypto_scam', 'nft', 'vip trading signals', 0.80, 'high'),
  p('crypto_scam', 'nft', 'insider trading tips', 0.80, 'high'),
  p('crypto_scam', 'nft', 'satoshi approved', 0.90, 'critical'),
  p('crypto_scam', 'nft', 'musk endorsed coin', 0.90, 'critical'),
  p('crypto_scam', 'nft', 'send eth get eth back', 0.95, 'critical'),
  p('crypto_scam', 'nft', 'send btc get double btc', 0.95, 'critical'),
  p('crypto_scam', 'nft', 'wallet sync required', 0.90, 'critical'),
  p('crypto_scam', 'nft', 'account rectification', 0.85, 'high'),
  p('crypto_scam', 'nft', 'decentralized profit system', 0.85, 'high'),
  p('crypto_scam', 'nft', 'passive staking rewards guaranteed', 0.85, 'high'),
  p('crypto_scam', 'nft', 'locked liquidity scam', 0.85, 'high'),
];

// ═══════════════════════════════════════════════════════════════════════════
// EXPANDED: PHISHING additions (30+ new patterns)
// ═══════════════════════════════════════════════════════════════════════════
const PHISHING_EXT: PatternEntry[] = [
  p('phishing', 'credential', 'verify your account now', 0.85, 'high'),
  p('phishing', 'credential', 're-enter your password', 0.85, 'high'),
  p('phishing', 'credential', 'update payment method', 0.80, 'high'),
  p('phishing', 'credential', 'billing information required', 0.80, 'high'),
  p('phishing', 'credential', 'credit card verification required', 0.85, 'high'),
  p('phishing', 'credential', 'social security verification', 0.90, 'critical'),
  p('phishing', 'credential', 'date of birth verification', 0.80, 'high'),
  p('phishing', 'credential', 'mother maiden name', 0.85, 'high'),
  p('phishing', 'credential', 'security question answer', 0.80, 'high'),
  p('phishing', 'credential', 'one time password', 0.75, 'medium'),
  p('phishing', 'credential', 'otp code', 0.80, 'high'),
  p('phishing', 'credential', 'authentication code required', 0.80, 'high'),
  p('phishing', 'credential', 'login attempt detected', 0.80, 'high'),
  p('phishing', 'credential', 'unusual sign in detected', 0.80, 'high'),
  p('phishing', 'credential', 'identity confirmation needed', 0.80, 'high'),
  p('phishing', 'credential', 'account ownership verification', 0.80, 'high'),
  p('phishing', 'credential', 'provide your credentials', 0.85, 'high'),
  p('phishing', 'credential', 'enter your username and password', 0.85, 'high'),
  p('phishing', 'credential', 'submit your details here', 0.75, 'medium'),
  p('phishing', 'credential', 'your password has been reset', 0.70, 'medium'),
  p('phishing', 'credential', 'link will expire in', 0.70, 'medium'),
  p('phishing', 'credential', 'complete account verification', 0.80, 'high'),
  p('phishing', 'credential', 'mandatory security update', 0.80, 'high'),
  p('phishing', 'credential', 'click to unlock account', 0.85, 'high'),
  p('phishing', 'credential', 'validate your email address', 0.75, 'medium'),
  p('phishing', 'credential', 'confirm bank account details', 0.90, 'critical'),
  p('phishing', 'credential', 'provide pin number', 0.90, 'critical'),
  p('phishing', 'credential', 'enter your full card details', 0.90, 'critical'),
  p('phishing', 'credential', 'account takeover alert', 0.85, 'high'),
  p('phishing', 'credential', 'suspicious purchase detected', 0.80, 'high'),
  p('phishing', 'credential', 'transaction flagged', 0.75, 'medium'),
];

// ═══════════════════════════════════════════════════════════════════════════
// EXPANDED: TECH_SUPPORT additions (30+ new patterns)
// ═══════════════════════════════════════════════════════════════════════════
const TECH_SUPPORT_EXT: PatternEntry[] = [
  p('tech_support', 'remote_access', 'remote access required', 0.85, 'high'),
  p('tech_support', 'remote_access', 'teamviewer download', 0.80, 'high'),
  p('tech_support', 'remote_access', 'anydesk install', 0.85, 'high'),
  p('tech_support', 'remote_access', 'allow remote control', 0.90, 'critical'),
  p('tech_support', 'remote_access', 'technician will connect', 0.85, 'high'),
  p('tech_support', 'remote_access', 'grant access to your device', 0.90, 'critical'),
  p('tech_support', 'fake_error', 'error code windows', 0.80, 'high'),
  p('tech_support', 'fake_error', 'error code microsoft', 0.80, 'high'),
  p('tech_support', 'fake_error', 'windows error detected', 0.80, 'high'),
  p('tech_support', 'fake_error', 'registry error found', 0.80, 'high'),
  p('tech_support', 'fake_error', 'system32 corrupted', 0.85, 'high'),
  p('tech_support', 'fake_error', 'hard drive failing', 0.80, 'high'),
  p('tech_support', 'fake_error', 'firewall has been disabled', 0.80, 'high'),
  p('tech_support', 'fake_error', 'antivirus subscription expired', 0.80, 'high'),
  p('tech_support', 'fake_error', 'subscription renewal required', 0.70, 'medium'),
  p('tech_support', 'fake_error', 'critical error detected on your pc', 0.85, 'high'),
  p('tech_support', 'fake_error', 'your ip address has been blocked', 0.85, 'high'),
  p('tech_support', 'fake_error', 'microsoft error code 0x', 0.85, 'high'),
  p('tech_support', 'fake_error', 'windows defender alert', 0.80, 'high'),
  p('tech_support', 'fake_error', 'call microsoft immediately', 0.90, 'critical'),
  p('tech_support', 'fake_error', 'call apple support now', 0.90, 'critical'),
  p('tech_support', 'fake_error', 'do not restart your computer', 0.80, 'high'),
  p('tech_support', 'fake_error', 'do not turn off your device', 0.80, 'high'),
  p('tech_support', 'fake_error', 'your data is at risk', 0.80, 'high'),
  p('tech_support', 'fake_error', 'system infected with', 0.85, 'high'),
  p('tech_support', 'fake_error', 'hacker is watching', 0.85, 'high'),
  p('tech_support', 'fake_error', 'hacker is connected', 0.90, 'critical'),
  p('tech_support', 'fake_error', 'microsoft security alert', 0.85, 'high'),
  p('tech_support', 'fake_error', 'apple security breach', 0.85, 'high'),
  p('tech_support', 'fake_error', 'your license key is invalid', 0.70, 'medium'),
  p('tech_support', 'fake_error', 'illegal software detected', 0.85, 'high'),
];

// ═══════════════════════════════════════════════════════════════════════════
// EXPANDED: EMPLOYMENT_SCAM additions (30+ new patterns)
// ═══════════════════════════════════════════════════════════════════════════
const EMPLOYMENT_SCAM_EXT: PatternEntry[] = [
  p('employment_scam', 'job_offer', 'make money from home', 0.65, 'medium'),
  p('employment_scam', 'job_offer', 'work from anywhere', 0.50, 'low'),
  p('employment_scam', 'job_offer', 'flexible hours guaranteed', 0.65, 'medium'),
  p('employment_scam', 'job_offer', 'earn daily from home', 0.80, 'high'),
  p('employment_scam', 'job_offer', 'typing job online', 0.65, 'medium'),
  p('employment_scam', 'job_offer', 'form filling job', 0.65, 'medium'),
  p('employment_scam', 'job_offer', 'survey job online', 0.60, 'medium'),
  p('employment_scam', 'job_offer', 'money transfer agent', 0.85, 'high'),
  p('employment_scam', 'job_offer', 'payment processor job', 0.85, 'high'),
  p('employment_scam', 'job_offer', 'financial agent needed', 0.85, 'high'),
  p('employment_scam', 'job_offer', 'reshipping agent needed', 0.90, 'critical'),
  p('employment_scam', 'job_offer', 'parcel forwarding job', 0.85, 'high'),
  p('employment_scam', 'job_offer', 'virtual assistant job', 0.45, 'low'),
  p('employment_scam', 'job_offer', 'part time online job', 0.50, 'low'),
  p('employment_scam', 'job_offer', 'earn 500 dollars per day', 0.90, 'critical'),
  p('employment_scam', 'job_offer', 'earn 1000 dollars per week', 0.85, 'high'),
  p('employment_scam', 'job_offer', 'earn weekly guaranteed', 0.80, 'high'),
  p('employment_scam', 'job_offer', 'instant payment on completion', 0.75, 'medium'),
  p('employment_scam', 'job_offer', 'get paid to like posts', 0.80, 'high'),
  p('employment_scam', 'job_offer', 'get paid to click', 0.75, 'medium'),
  p('employment_scam', 'job_offer', 'get paid to watch videos', 0.65, 'medium'),
  p('employment_scam', 'job_offer', 'home based business opportunity', 0.65, 'medium'),
  p('employment_scam', 'job_offer', 'unlimited income potential', 0.80, 'high'),
  p('employment_scam', 'job_offer', 'no interview required', 0.65, 'medium'),
  p('employment_scam', 'job_offer', 'hired immediately without interview', 0.80, 'high'),
  p('employment_scam', 'job_offer', 'pay your own training kit', 0.85, 'high'),
  p('employment_scam', 'job_offer', 'buy starter kit', 0.80, 'high'),
  p('employment_scam', 'job_offer', 'registration fee for job', 0.85, 'high'),
  p('employment_scam', 'mlm', 'passive residual income', 0.70, 'medium'),
  p('employment_scam', 'mlm', 'join our team and earn', 0.65, 'medium'),
  p('employment_scam', 'mlm', 'direct referral bonus', 0.70, 'medium'),
];

// ═══════════════════════════════════════════════════════════════════════════
// EXPANDED: DELIVERY_SCAM additions (30+ new patterns)
// ═══════════════════════════════════════════════════════════════════════════
const DELIVERY_SCAM_EXT: PatternEntry[] = [
  p('delivery_scam', 'failed_delivery', 'package held at customs', 0.80, 'high'),
  p('delivery_scam', 'failed_delivery', 'customs clearance fee required', 0.85, 'high'),
  p('delivery_scam', 'failed_delivery', 'address confirmation fee', 0.85, 'high'),
  p('delivery_scam', 'failed_delivery', 'failed delivery attempt', 0.75, 'medium'),
  p('delivery_scam', 'failed_delivery', 'reschedule delivery fee', 0.85, 'high'),
  p('delivery_scam', 'failed_delivery', 'package has been seized', 0.85, 'high'),
  p('delivery_scam', 'failed_delivery', 'import duty payment required', 0.80, 'high'),
  p('delivery_scam', 'failed_delivery', 'tracking number is invalid', 0.75, 'medium'),
  p('delivery_scam', 'carrier', 'dhl delivery failed', 0.75, 'medium'),
  p('delivery_scam', 'carrier', 'fedex delivery failed', 0.75, 'medium'),
  p('delivery_scam', 'carrier', 'usps delivery failed', 0.75, 'medium'),
  p('delivery_scam', 'carrier', 'ups delivery failed', 0.75, 'medium'),
  p('delivery_scam', 'carrier', 'your dhl parcel is held', 0.80, 'high'),
  p('delivery_scam', 'carrier', 'your fedex shipment is on hold', 0.80, 'high'),
  p('delivery_scam', 'carrier', 'your usps package requires action', 0.80, 'high'),
  p('delivery_scam', 'carrier', 'your ups delivery has failed', 0.80, 'high'),
  p('delivery_scam', 'fee', 'pay small fee to release package', 0.85, 'high'),
  p('delivery_scam', 'fee', 'unpaid customs tax', 0.80, 'high'),
  p('delivery_scam', 'fee', 'pay customs now to receive', 0.85, 'high'),
  p('delivery_scam', 'fee', 'delivery address change fee', 0.80, 'high'),
  p('delivery_scam', 'fee', 'insurance charge for delivery', 0.75, 'medium'),
  p('delivery_scam', 'fee', 'quarantine release fee', 0.85, 'high'),
  p('delivery_scam', 'fee', 'shipment clearance fee', 0.80, 'high'),
  p('delivery_scam', 'fee', 'release my parcel fee', 0.85, 'high'),
  p('delivery_scam', 'failed_delivery', 'your parcel has been returned', 0.70, 'medium'),
  p('delivery_scam', 'failed_delivery', 'package undeliverable', 0.70, 'medium'),
  p('delivery_scam', 'failed_delivery', 'delivery blocked', 0.70, 'medium'),
  p('delivery_scam', 'failed_delivery', 'verify address to continue delivery', 0.75, 'medium'),
  p('delivery_scam', 'failed_delivery', 'your shipment requires tax payment', 0.85, 'high'),
  p('delivery_scam', 'failed_delivery', 'click to pay delivery tax', 0.85, 'high'),
];

// ═══════════════════════════════════════════════════════════════════════════
// EXPANDED: GOVERNMENT_SCAM additions (30+ new patterns)
// ═══════════════════════════════════════════════════════════════════════════
const GOVERNMENT_SCAM_EXT: PatternEntry[] = [
  p('government_scam', 'ssa', 'social security number suspended', 0.95, 'critical'),
  p('government_scam', 'benefits', 'medicare fraud investigation', 0.85, 'high'),
  p('government_scam', 'benefits', 'benefits suspension notice', 0.85, 'high'),
  p('government_scam', 'irs', 'tax lien has been filed', 0.85, 'high'),
  p('government_scam', 'irs', 'property seizure notice', 0.85, 'high'),
  p('government_scam', 'irs', 'bank account freeze order', 0.90, 'critical'),
  p('government_scam', 'irs', 'federal investigation opened', 0.85, 'high'),
  p('government_scam', 'irs', 'irs criminal investigation', 0.90, 'critical'),
  p('government_scam', 'law_enforcement', 'interpol warrant issued', 0.90, 'critical'),
  p('government_scam', 'law_enforcement', 'immigration violation detected', 0.85, 'high'),
  p('government_scam', 'law_enforcement', 'visa cancellation notice', 0.85, 'high'),
  p('government_scam', 'law_enforcement', 'deportation notice', 0.90, 'critical'),
  p('government_scam', 'law_enforcement', 'green card rejected', 0.85, 'high'),
  p('government_scam', 'law_enforcement', 'your visa has been flagged', 0.85, 'high'),
  p('government_scam', 'law_enforcement', 'illegal activity on your account', 0.85, 'high'),
  p('government_scam', 'law_enforcement', 'money laundering investigation', 0.90, 'critical'),
  p('government_scam', 'law_enforcement', 'narcotics investigation', 0.85, 'high'),
  p('government_scam', 'law_enforcement', 'cybercrime unit investigation', 0.85, 'high'),
  p('government_scam', 'law_enforcement', 'warrant for your property', 0.85, 'high'),
  p('government_scam', 'irs', 'settle your tax debt now', 0.85, 'high'),
  p('government_scam', 'irs', 'avoid irs collection', 0.85, 'high'),
  p('government_scam', 'irs', 'pay back taxes or be arrested', 0.95, 'critical'),
  p('government_scam', 'ssa', 'your benefits will be discontinued', 0.85, 'high'),
  p('government_scam', 'ssa', 'social security number linked to crime', 0.95, 'critical'),
  p('government_scam', 'benefits', 'unclaimed government benefit', 0.80, 'high'),
  p('government_scam', 'benefits', 'pandemic relief fund pending', 0.75, 'medium'),
  p('government_scam', 'benefits', 'government subsidy available', 0.65, 'medium'),
  p('government_scam', 'law_enforcement', 'evade arrest by paying fine', 0.95, 'critical'),
  p('government_scam', 'law_enforcement', 'pay fine to close case', 0.90, 'critical'),
  p('government_scam', 'irs', 'irs officer will arrest you', 0.95, 'critical'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 17: WEBSITE_SCAM  (80+ patterns)
// ═══════════════════════════════════════════════════════════════════════════
const WEBSITE_SCAM: PatternEntry[] = [
  // -- Fake shopping sites --
  p('website_scam', 'fake_shop', 'order tracking', 0.35, 'low'),
  p('website_scam', 'fake_shop', 'secure checkout here', 0.60, 'medium'),
  p('website_scam', 'fake_shop', 'limited stock available', 0.65, 'medium'),
  p('website_scam', 'fake_shop', 'while supplies last', 0.60, 'medium'),
  p('website_scam', 'fake_shop', 'flash sale ends', 0.65, 'medium'),
  p('website_scam', 'fake_shop', 'buy 2 get 3 free', 0.70, 'medium'),
  p('website_scam', 'fake_shop', 'clearance prices', 0.50, 'low'),
  p('website_scam', 'fake_shop', 'factory direct prices', 0.65, 'medium'),
  p('website_scam', 'fake_shop', 'wholesale prices direct', 0.65, 'medium'),
  p('website_scam', 'fake_shop', 'designer goods at discount', 0.70, 'medium'),
  p('website_scam', 'fake_shop', 'replica luxury', 0.80, 'high'),
  p('website_scam', 'fake_shop', 'authentic replica', 0.80, 'high'),
  p('website_scam', 'fake_shop', 'brand new sealed', 0.50, 'low'),
  p('website_scam', 'fake_shop', 'pay via crypto only', 0.85, 'high'),
  p('website_scam', 'fake_shop', 'no refund policy', 0.65, 'medium'),
  p('website_scam', 'fake_shop', 'ship from overseas warehouse', 0.55, 'low'),
  p('website_scam', 'fake_shop', 'no returns accepted', 0.60, 'medium'),
  p('website_scam', 'fake_shop', 'price drop today only', 0.65, 'medium'),
  p('website_scam', 'fake_shop', 'massive discount expires', 0.65, 'medium'),
  p('website_scam', 'fake_shop', '90% off today', 0.80, 'high'),
  p('website_scam', 'fake_shop', '95% off limited time', 0.85, 'high'),
  p('website_scam', 'fake_shop', 'closing down sale everything must go', 0.75, 'medium'),

  // -- Fake prize / lottery sites --
  p('website_scam', 'fake_prize', 'you have been selected as winner', 0.90, 'critical'),
  p('website_scam', 'fake_prize', 'claim your prize now', 0.90, 'critical'),
  p('website_scam', 'fake_prize', 'prize redemption center', 0.85, 'high'),
  p('website_scam', 'fake_prize', 'sweepstakes prize notification', 0.85, 'high'),
  p('website_scam', 'fake_prize', 'gift card winner', 0.85, 'high'),
  p('website_scam', 'fake_prize', 'congratulations you have been chosen', 0.90, 'critical'),
  p('website_scam', 'fake_prize', 'complete survey to claim prize', 0.85, 'high'),
  p('website_scam', 'fake_prize', 'spin the wheel to win', 0.75, 'medium'),
  p('website_scam', 'fake_prize', 'scratch and win', 0.70, 'medium'),
  p('website_scam', 'fake_prize', 'daily prize giveaway', 0.75, 'medium'),
  p('website_scam', 'fake_prize', 'winner selected randomly', 0.75, 'medium'),
  p('website_scam', 'fake_prize', 'you are our lucky visitor', 0.90, 'critical'),
  p('website_scam', 'fake_prize', 'you are the 1 millionth visitor', 0.95, 'critical'),
  p('website_scam', 'fake_prize', 'claim your amazon voucher', 0.85, 'high'),
  p('website_scam', 'fake_prize', 'click to receive your reward', 0.80, 'high'),

  // -- Fake investment sites --
  p('website_scam', 'fake_investment', 'passive income guaranteed', 0.90, 'critical'),
  p('website_scam', 'fake_investment', 'financial freedom now', 0.80, 'high'),
  p('website_scam', 'fake_investment', 'wealth building system', 0.80, 'high'),
  p('website_scam', 'fake_investment', 'investment returns guaranteed', 0.90, 'critical'),
  p('website_scam', 'fake_investment', 'risk free investment opportunity', 0.90, 'critical'),
  p('website_scam', 'fake_investment', 'double your money in', 0.95, 'critical'),
  p('website_scam', 'fake_investment', 'triple your investment', 0.95, 'critical'),
  p('website_scam', 'fake_investment', 'forex signals guaranteed profit', 0.90, 'critical'),
  p('website_scam', 'fake_investment', 'trading signals profit guaranteed', 0.90, 'critical'),
  p('website_scam', 'fake_investment', 'become a millionaire fast', 0.85, 'high'),
  p('website_scam', 'fake_investment', 'earn 10000 per month', 0.85, 'high'),
  p('website_scam', 'fake_investment', 'guaranteed weekly profits', 0.90, 'critical'),
  p('website_scam', 'fake_investment', 'forex robot profit', 0.85, 'high'),
  p('website_scam', 'fake_investment', 'trading algorithm guaranteed', 0.85, 'high'),
  p('website_scam', 'fake_investment', 'investment platform returns', 0.65, 'medium'),
  p('website_scam', 'fake_investment', 'compound your returns', 0.65, 'medium'),
  p('website_scam', 'fake_investment', 'autopilot income system', 0.85, 'high'),
  p('website_scam', 'fake_investment', 'done for you income', 0.80, 'high'),
  p('website_scam', 'fake_investment', 'copy trading guaranteed', 0.80, 'high'),
  p('website_scam', 'fake_investment', 'managed account returns', 0.70, 'medium'),

  // -- Generic website scam signals --
  p('website_scam', 'site_signal', 'complete the form to proceed', 0.55, 'low'),
  p('website_scam', 'site_signal', 'limited slots available', 0.65, 'medium'),
  p('website_scam', 'site_signal', 'only 3 spots left', 0.70, 'medium'),
  p('website_scam', 'site_signal', 'offer available to select users', 0.70, 'medium'),
  p('website_scam', 'site_signal', 'this page will close in', 0.75, 'medium'),
  p('website_scam', 'site_signal', 'countdown expires', 0.65, 'medium'),
  p('website_scam', 'site_signal', 'submit your details to claim', 0.75, 'medium'),
  p('website_scam', 'site_signal', 'enter email to unlock', 0.70, 'medium'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 18: DOMAIN_TRICKS  (60+ patterns)
// ═══════════════════════════════════════════════════════════════════════════
const DOMAIN_TRICKS: PatternEntry[] = [
  // -- Typosquatting patterns --
  p('domain_tricks', 'typosquat', 'paypa1', 0.95, 'critical'),
  p('domain_tricks', 'typosquat', 'amaz0n', 0.95, 'critical'),
  p('domain_tricks', 'typosquat', 'g00gle', 0.95, 'critical'),
  p('domain_tricks', 'typosquat', 'micros0ft', 0.95, 'critical'),
  p('domain_tricks', 'typosquat', 'app1e', 0.95, 'critical'),
  p('domain_tricks', 'typosquat', 'faceb00k', 0.95, 'critical'),
  p('domain_tricks', 'typosquat', 'netfl1x', 0.95, 'critical'),
  p('domain_tricks', 'typosquat', 'paypa1.com', 0.95, 'critical'),
  p('domain_tricks', 'typosquat', 'amaz0n.com', 0.95, 'critical'),
  p('domain_tricks', 'typosquat', 'g00gle.com', 0.95, 'critical'),
  p('domain_tricks', 'typosquat', 'microsofft', 0.90, 'critical'),
  p('domain_tricks', 'typosquat', 'micosoft', 0.90, 'critical'),
  p('domain_tricks', 'typosquat', 'amazzon', 0.90, 'critical'),
  p('domain_tricks', 'typosquat', 'paypal-secure', 0.90, 'critical'),
  p('domain_tricks', 'typosquat', 'amazon-secure', 0.90, 'critical'),
  p('domain_tricks', 'typosquat', 'appleid-verify', 0.90, 'critical'),
  p('domain_tricks', 'typosquat', 'google-security', 0.85, 'high'),
  p('domain_tricks', 'typosquat', 'microsoft-help', 0.85, 'high'),

  // -- Suspicious subdomain/TLD combos --
  p('domain_tricks', 'suspicious_domain', '-secure.com', 0.80, 'high'),
  p('domain_tricks', 'suspicious_domain', '-official.com', 0.80, 'high'),
  p('domain_tricks', 'suspicious_domain', '-login.com', 0.85, 'high'),
  p('domain_tricks', 'suspicious_domain', '-verify.com', 0.85, 'high'),
  p('domain_tricks', 'suspicious_domain', '-update.com', 0.80, 'high'),
  p('domain_tricks', 'suspicious_domain', '-account.com', 0.80, 'high'),
  p('domain_tricks', 'suspicious_domain', '-support.com', 0.75, 'medium'),
  p('domain_tricks', 'suspicious_domain', '-help.com', 0.65, 'medium'),
  p('domain_tricks', 'suspicious_domain', '-service.com', 0.60, 'medium'),
  p('domain_tricks', 'suspicious_domain', 'secure-login', 0.85, 'high'),
  p('domain_tricks', 'suspicious_domain', 'login-secure', 0.85, 'high'),
  p('domain_tricks', 'suspicious_domain', 'account-verify', 0.85, 'high'),
  p('domain_tricks', 'suspicious_domain', 'verify-account', 0.85, 'high'),
  p('domain_tricks', 'suspicious_domain', 'update-account', 0.80, 'high'),
  p('domain_tricks', 'suspicious_domain', 'account-update', 0.80, 'high'),
  p('domain_tricks', 'suspicious_domain', 'support-center', 0.65, 'medium'),
  p('domain_tricks', 'suspicious_domain', 'help-center', 0.55, 'low'),
  p('domain_tricks', 'suspicious_domain', 'official-site', 0.75, 'medium'),
  p('domain_tricks', 'suspicious_domain', 'customer-service', 0.55, 'low'),

  // -- Fake security domains --
  p('domain_tricks', 'fake_secure', 'ssl-secure', 0.85, 'high'),
  p('domain_tricks', 'fake_secure', 'https-secure', 0.85, 'high'),
  p('domain_tricks', 'fake_secure', 'safe-payment', 0.85, 'high'),
  p('domain_tricks', 'fake_secure', 'verified-site', 0.85, 'high'),
  p('domain_tricks', 'fake_secure', 'trusted-payment', 0.85, 'high'),
  p('domain_tricks', 'fake_secure', 'secure-payments', 0.80, 'high'),
  p('domain_tricks', 'fake_secure', 'safe-checkout', 0.80, 'high'),
  p('domain_tricks', 'fake_secure', 'safe-browsing', 0.70, 'medium'),
  p('domain_tricks', 'fake_secure', 'encrypted-checkout', 0.75, 'medium'),
  p('domain_tricks', 'fake_secure', 'protected-login', 0.80, 'high'),

  // -- IP address / numeric domain signals --
  p('domain_tricks', 'ip_hosting', 'hosted on ip address', 0.80, 'high'),
  p('domain_tricks', 'ip_hosting', 'numeric domain', 0.70, 'medium'),
  p('domain_tricks', 'ip_hosting', 'click here visit site', 0.60, 'medium'),
  p('domain_tricks', 'ip_hosting', 'shortened url', 0.55, 'low'),
  p('domain_tricks', 'ip_hosting', 'bit.ly redirect', 0.60, 'medium'),
  p('domain_tricks', 'ip_hosting', 'tinyurl redirect', 0.60, 'medium'),
  p('domain_tricks', 'ip_hosting', 'click this shortened link', 0.70, 'medium'),
  p('domain_tricks', 'ip_hosting', 'masked url', 0.75, 'medium'),
  p('domain_tricks', 'ip_hosting', 'redirect link', 0.60, 'medium'),
  p('domain_tricks', 'ip_hosting', 'forwarding url', 0.60, 'medium'),
  p('domain_tricks', 'ip_hosting', 'obfuscated link', 0.75, 'medium'),
  p('domain_tricks', 'ip_hosting', 'suspicious redirect', 0.75, 'medium'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 19: FAKE_AUTHORITY  (70+ patterns)
// ═══════════════════════════════════════════════════════════════════════════
const FAKE_AUTHORITY: PatternEntry[] = [
  // -- Impersonating official sites --
  p('fake_authority', 'govt_impersonation', 'official government website', 0.80, 'high'),
  p('fake_authority', 'govt_impersonation', 'government authorized site', 0.85, 'high'),
  p('fake_authority', 'govt_impersonation', 'irs official website', 0.85, 'high'),
  p('fake_authority', 'govt_impersonation', 'fbi official notice', 0.85, 'high'),
  p('fake_authority', 'govt_impersonation', 'interpol official', 0.85, 'high'),
  p('fake_authority', 'govt_impersonation', 'bank official notice', 0.80, 'high'),
  p('fake_authority', 'govt_impersonation', 'official apple site', 0.80, 'high'),
  p('fake_authority', 'govt_impersonation', 'official microsoft site', 0.80, 'high'),
  p('fake_authority', 'govt_impersonation', 'official amazon site', 0.80, 'high'),
  p('fake_authority', 'govt_impersonation', 'official paypal site', 0.80, 'high'),
  p('fake_authority', 'govt_impersonation', 'official google site', 0.80, 'high'),
  p('fake_authority', 'govt_impersonation', 'department of treasury', 0.75, 'medium'),
  p('fake_authority', 'govt_impersonation', 'federal bureau of investigation', 0.80, 'high'),
  p('fake_authority', 'govt_impersonation', 'central intelligence agency', 0.80, 'high'),
  p('fake_authority', 'govt_impersonation', 'national security agency', 0.80, 'high'),
  p('fake_authority', 'govt_impersonation', 'white house notification', 0.85, 'high'),
  p('fake_authority', 'govt_impersonation', 'government security clearance', 0.80, 'high'),
  p('fake_authority', 'govt_impersonation', 'federal trade commission', 0.70, 'medium'),
  p('fake_authority', 'govt_impersonation', 'securities exchange commission', 0.70, 'medium'),
  p('fake_authority', 'govt_impersonation', 'financial crimes enforcement', 0.80, 'high'),

  // -- Fake certifications --
  p('fake_authority', 'fake_cert', 'certified by google', 0.85, 'high'),
  p('fake_authority', 'fake_cert', 'approved by microsoft', 0.85, 'high'),
  p('fake_authority', 'fake_cert', 'verified by amazon', 0.85, 'high'),
  p('fake_authority', 'fake_cert', 'endorsed by government', 0.85, 'high'),
  p('fake_authority', 'fake_cert', 'licensed by federal', 0.85, 'high'),
  p('fake_authority', 'fake_cert', 'certified by apple', 0.85, 'high'),
  p('fake_authority', 'fake_cert', 'approved by fbi', 0.85, 'high'),
  p('fake_authority', 'fake_cert', 'government certified', 0.80, 'high'),
  p('fake_authority', 'fake_cert', 'fda approved supplement', 0.70, 'medium'),
  p('fake_authority', 'fake_cert', 'who certified', 0.70, 'medium'),
  p('fake_authority', 'fake_cert', 'internationally certified', 0.65, 'medium'),
  p('fake_authority', 'fake_cert', 'iso certified scam', 0.65, 'medium'),
  p('fake_authority', 'fake_cert', 'bbb accredited', 0.60, 'medium'),
  p('fake_authority', 'fake_cert', 'registered with government', 0.70, 'medium'),
  p('fake_authority', 'fake_cert', 'licensed financial institution', 0.75, 'medium'),
  p('fake_authority', 'fake_cert', 'regulated by financial authority', 0.70, 'medium'),
  p('fake_authority', 'fake_cert', 'sec registered', 0.70, 'medium'),
  p('fake_authority', 'fake_cert', 'finra registered', 0.70, 'medium'),

  // -- Fake security badges --
  p('fake_authority', 'fake_badge', 'norton secured', 0.80, 'high'),
  p('fake_authority', 'fake_badge', 'mcafee secure', 0.80, 'high'),
  p('fake_authority', 'fake_badge', 'ssl verified site', 0.75, 'medium'),
  p('fake_authority', 'fake_badge', 'hack proof website', 0.80, 'high'),
  p('fake_authority', 'fake_badge', 'virus free guaranteed', 0.80, 'high'),
  p('fake_authority', 'fake_badge', 'trust pilot verified', 0.70, 'medium'),
  p('fake_authority', 'fake_badge', '256 bit encryption', 0.60, 'medium'),
  p('fake_authority', 'fake_badge', 'bank level security', 0.65, 'medium'),
  p('fake_authority', 'fake_badge', 'military grade encryption', 0.65, 'medium'),
  p('fake_authority', 'fake_badge', 'zero risk guarantee', 0.80, 'high'),
  p('fake_authority', 'fake_badge', '100% secure transaction', 0.75, 'medium'),
  p('fake_authority', 'fake_badge', 'verified secure payment', 0.75, 'medium'),
  p('fake_authority', 'fake_badge', 'protected by ssl', 0.55, 'low'),
  p('fake_authority', 'fake_badge', 'comodo secure', 0.70, 'medium'),
  p('fake_authority', 'fake_badge', 'verisign secured', 0.75, 'medium'),

  // -- Authority abuse --
  p('fake_authority', 'authority_abuse', 'as recommended by who', 0.70, 'medium'),
  p('fake_authority', 'authority_abuse', 'doctor approved method', 0.70, 'medium'),
  p('fake_authority', 'authority_abuse', 'scientifically proven formula', 0.65, 'medium'),
  p('fake_authority', 'authority_abuse', 'harvard study confirms', 0.75, 'medium'),
  p('fake_authority', 'authority_abuse', 'stanford researchers discovered', 0.75, 'medium'),
  p('fake_authority', 'authority_abuse', 'nasa technology', 0.70, 'medium'),
  p('fake_authority', 'authority_abuse', 'pentagon approved', 0.80, 'high'),
  p('fake_authority', 'authority_abuse', 'endorsed by doctors', 0.60, 'medium'),
  p('fake_authority', 'authority_abuse', 'government backed program', 0.75, 'medium'),
  p('fake_authority', 'authority_abuse', 'banks hate this', 0.80, 'high'),
  p('fake_authority', 'authority_abuse', 'they tried to hide this', 0.80, 'high'),
  p('fake_authority', 'authority_abuse', 'loophole they don\'t want you to know', 0.80, 'high'),
  p('fake_authority', 'authority_abuse', 'secret the rich use', 0.80, 'high'),
  p('fake_authority', 'authority_abuse', 'big pharma doesn\'t want you to know', 0.75, 'medium'),
  p('fake_authority', 'authority_abuse', 'wall street secret', 0.75, 'medium'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 20: SOCIAL_ENGINEERING_WEB  (60+ patterns)
// ═══════════════════════════════════════════════════════════════════════════
const SOCIAL_ENGINEERING_WEB: PatternEntry[] = [
  // -- Browser notification scams --
  p('social_engineering_web', 'browser_notif', 'click allow to continue', 0.85, 'high'),
  p('social_engineering_web', 'browser_notif', 'click allow to watch', 0.85, 'high'),
  p('social_engineering_web', 'browser_notif', 'press allow to verify', 0.85, 'high'),
  p('social_engineering_web', 'browser_notif', 'allow notifications to proceed', 0.85, 'high'),
  p('social_engineering_web', 'browser_notif', 'you must allow to continue', 0.85, 'high'),
  p('social_engineering_web', 'browser_notif', 'enable notifications to access', 0.80, 'high'),
  p('social_engineering_web', 'browser_notif', 'press allow if you are not a robot', 0.90, 'critical'),
  p('social_engineering_web', 'browser_notif', 'click allow to confirm you are human', 0.90, 'critical'),
  p('social_engineering_web', 'browser_notif', 'allow to verify your age', 0.80, 'high'),
  p('social_engineering_web', 'browser_notif', 'click allow to download', 0.80, 'high'),
  p('social_engineering_web', 'browser_notif', 'allow to start playing', 0.75, 'medium'),
  p('social_engineering_web', 'browser_notif', 'enable push notifications to continue', 0.80, 'high'),

  // -- Fake warning pages --
  p('social_engineering_web', 'fake_warning', 'your computer is infected', 0.85, 'high'),
  p('social_engineering_web', 'fake_warning', 'virus detected on your device', 0.85, 'high'),
  p('social_engineering_web', 'fake_warning', 'your device has been compromised', 0.90, 'critical'),
  p('social_engineering_web', 'fake_warning', 'malware has been detected', 0.85, 'high'),
  p('social_engineering_web', 'fake_warning', 'spyware alert on your system', 0.85, 'high'),
  p('social_engineering_web', 'fake_warning', 'system at risk do not close', 0.85, 'high'),
  p('social_engineering_web', 'fake_warning', 'call microsoft immediately', 0.90, 'critical'),
  p('social_engineering_web', 'fake_warning', 'call apple support now', 0.90, 'critical'),
  p('social_engineering_web', 'fake_warning', 'call tech support', 0.80, 'high'),
  p('social_engineering_web', 'fake_warning', 'do not close this window', 0.80, 'high'),
  p('social_engineering_web', 'fake_warning', 'warning your browser is outdated', 0.75, 'medium'),
  p('social_engineering_web', 'fake_warning', 'your system is sending error reports', 0.80, 'high'),
  p('social_engineering_web', 'fake_warning', 'windows has detected a problem', 0.85, 'high'),
  p('social_engineering_web', 'fake_warning', 'apple has blocked your device', 0.85, 'high'),
  p('social_engineering_web', 'fake_warning', 'your icloud has been hacked', 0.85, 'high'),
  p('social_engineering_web', 'fake_warning', 'critical battery error', 0.75, 'medium'),
  p('social_engineering_web', 'fake_warning', 'ransomware detected on', 0.90, 'critical'),
  p('social_engineering_web', 'fake_warning', 'hackers are watching your screen', 0.85, 'high'),

  // -- Fake update pages --
  p('social_engineering_web', 'fake_update', 'update required to continue', 0.80, 'high'),
  p('social_engineering_web', 'fake_update', 'flash player required', 0.80, 'high'),
  p('social_engineering_web', 'fake_update', 'java update required', 0.80, 'high'),
  p('social_engineering_web', 'fake_update', 'browser update required', 0.75, 'medium'),
  p('social_engineering_web', 'fake_update', 'plugin required to play', 0.75, 'medium'),
  p('social_engineering_web', 'fake_update', 'codec required to play video', 0.75, 'medium'),
  p('social_engineering_web', 'fake_update', 'download video player', 0.70, 'medium'),
  p('social_engineering_web', 'fake_update', 'your version is outdated', 0.70, 'medium'),
  p('social_engineering_web', 'fake_update', 'install to continue watching', 0.75, 'medium'),
  p('social_engineering_web', 'fake_update', 'chrome update available click here', 0.80, 'high'),
  p('social_engineering_web', 'fake_update', 'firefox update required', 0.80, 'high'),
  p('social_engineering_web', 'fake_update', 'safari update click here', 0.80, 'high'),
  p('social_engineering_web', 'fake_update', 'your media player is outdated', 0.75, 'medium'),
  p('social_engineering_web', 'fake_update', 'download to fix your device', 0.80, 'high'),

  // -- Clickbait / redirect tricks --
  p('social_engineering_web', 'clickbait', 'you will not believe this', 0.60, 'medium'),
  p('social_engineering_web', 'clickbait', 'doctors are shocked', 0.70, 'medium'),
  p('social_engineering_web', 'clickbait', 'one weird trick', 0.70, 'medium'),
  p('social_engineering_web', 'clickbait', 'this video will be removed', 0.75, 'medium'),
  p('social_engineering_web', 'clickbait', 'government is trying to ban this', 0.75, 'medium'),
  p('social_engineering_web', 'clickbait', 'watch before it gets deleted', 0.75, 'medium'),
  p('social_engineering_web', 'clickbait', 'what they don\'t want you to see', 0.70, 'medium'),
  p('social_engineering_web', 'clickbait', 'click to find out', 0.40, 'low'),
  p('social_engineering_web', 'clickbait', 'tap here to claim', 0.70, 'medium'),
  p('social_engineering_web', 'clickbait', 'you must see this', 0.55, 'low'),
  p('social_engineering_web', 'clickbait', 'breaking news your area', 0.65, 'medium'),
  p('social_engineering_web', 'clickbait', 'this expires in minutes', 0.75, 'medium'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 21: ROMANCE_WEBSITE  (50+ patterns)
// ═══════════════════════════════════════════════════════════════════════════
const ROMANCE_WEBSITE: PatternEntry[] = [
  // -- Dating site manipulation --
  p('romance_website', 'love_manipulation', 'i fell in love with your profile', 0.85, 'high'),
  p('romance_website', 'love_manipulation', 'you are different from others', 0.80, 'high'),
  p('romance_website', 'love_manipulation', 'i want to meet you in person', 0.55, 'low'),
  p('romance_website', 'love_manipulation', 'send me your number', 0.65, 'medium'),
  p('romance_website', 'love_manipulation', 'let\'s move to whatsapp', 0.80, 'high'),
  p('romance_website', 'love_manipulation', 'let\'s move to telegram', 0.80, 'high'),
  p('romance_website', 'love_manipulation', 'let\'s move off this site', 0.80, 'high'),
  p('romance_website', 'love_manipulation', 'let\'s talk on another platform', 0.75, 'medium'),
  p('romance_website', 'love_manipulation', 'i don\'t use this app much', 0.65, 'medium'),
  p('romance_website', 'love_manipulation', 'my subscription is ending here', 0.70, 'medium'),
  p('romance_website', 'love_manipulation', 'you are so beautiful i can\'t stop thinking', 0.80, 'high'),
  p('romance_website', 'love_manipulation', 'i\'ve never felt this connection before', 0.75, 'medium'),
  p('romance_website', 'love_manipulation', 'fate brought us together', 0.70, 'medium'),

  // -- Military / overseas scams --
  p('romance_website', 'fake_location', 'i am deployed overseas', 0.85, 'high'),
  p('romance_website', 'fake_location', 'military deployment', 0.85, 'high'),
  p('romance_website', 'fake_location', 'working on oil rig offshore', 0.90, 'critical'),
  p('romance_website', 'fake_location', 'stranded abroad urgently', 0.85, 'high'),
  p('romance_website', 'fake_location', 'i am a soldier stationed', 0.80, 'high'),
  p('romance_website', 'fake_location', 'peacekeeping mission overseas', 0.80, 'high'),
  p('romance_website', 'fake_location', 'working offshore cannot access bank', 0.90, 'critical'),
  p('romance_website', 'fake_location', 'my unit is deployed to', 0.80, 'high'),
  p('romance_website', 'fake_location', 'international contractor', 0.55, 'low'),
  p('romance_website', 'fake_location', 'cannot access my account overseas', 0.80, 'high'),

  // -- Money requests via dating --
  p('romance_website', 'money_request', 'send money urgent emergency', 0.90, 'critical'),
  p('romance_website', 'money_request', 'western union gift for travel', 0.90, 'critical'),
  p('romance_website', 'money_request', 'moneygram to help me travel', 0.90, 'critical'),
  p('romance_website', 'money_request', 'gift cards for travel expenses', 0.90, 'critical'),
  p('romance_website', 'money_request', 'i need funds to come see you', 0.85, 'high'),
  p('romance_website', 'money_request', 'help me get out of this country', 0.85, 'high'),
  p('romance_website', 'money_request', 'medical emergency send money', 0.85, 'high'),
  p('romance_website', 'money_request', 'loan until i return', 0.80, 'high'),
  p('romance_website', 'money_request', 'i will pay you back everything', 0.80, 'high'),
  p('romance_website', 'money_request', 'investment opportunity together', 0.80, 'high'),
  p('romance_website', 'money_request', 'i have discovered a trading platform', 0.85, 'high'),
  p('romance_website', 'money_request', 'let me show you how to invest', 0.80, 'high'),
  p('romance_website', 'money_request', 'pig butchering scam', 0.95, 'critical'),
  p('romance_website', 'money_request', 'crypto investment together', 0.85, 'high'),
  p('romance_website', 'money_request', 'my uncle works at exchange', 0.80, 'high'),

  // -- Fake profiles --
  p('romance_website', 'fake_profile', 'model looking for love', 0.65, 'medium'),
  p('romance_website', 'fake_profile', 'successful businessman single', 0.65, 'medium'),
  p('romance_website', 'fake_profile', 'doctor working abroad', 0.70, 'medium'),
  p('romance_website', 'fake_profile', 'army general overseas', 0.80, 'high'),
  p('romance_website', 'fake_profile', 'widowed with young child', 0.70, 'medium'),
  p('romance_website', 'fake_profile', 'engineer on international project', 0.65, 'medium'),
  p('romance_website', 'fake_profile', 'i lost my wife to cancer', 0.65, 'medium'),
  p('romance_website', 'fake_profile', 'i have been hurt before', 0.50, 'low'),
  p('romance_website', 'fake_profile', 'my daughter needs surgery', 0.80, 'high'),
  p('romance_website', 'fake_profile', 'just moved to your country', 0.45, 'low'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 22: FINANCIAL_FRAUD_WEB  (70+ patterns)
// ═══════════════════════════════════════════════════════════════════════════
const FINANCIAL_FRAUD_WEB: PatternEntry[] = [
  // -- Wire transfer fraud --
  p('financial_fraud_web', 'wire_fraud', 'bank wire transfer required', 0.80, 'high'),
  p('financial_fraud_web', 'wire_fraud', 'international wire transfer', 0.80, 'high'),
  p('financial_fraud_web', 'wire_fraud', 'swift transfer urgently', 0.80, 'high'),
  p('financial_fraud_web', 'wire_fraud', 'iban transfer required', 0.75, 'medium'),
  p('financial_fraud_web', 'wire_fraud', 'wire funds immediately', 0.85, 'high'),
  p('financial_fraud_web', 'wire_fraud', 'bank transfer to release', 0.85, 'high'),
  p('financial_fraud_web', 'wire_fraud', 'transfer fee to unlock funds', 0.85, 'high'),
  p('financial_fraud_web', 'wire_fraud', 'wire payment to our account', 0.85, 'high'),
  p('financial_fraud_web', 'wire_fraud', 'international bank account number', 0.70, 'medium'),

  // -- Advance fee fraud --
  p('financial_fraud_web', 'advance_fee', 'processing fee required to release', 0.85, 'high'),
  p('financial_fraud_web', 'advance_fee', 'release fee required', 0.85, 'high'),
  p('financial_fraud_web', 'advance_fee', 'clearance fee to receive funds', 0.85, 'high'),
  p('financial_fraud_web', 'advance_fee', 'insurance fee to release funds', 0.85, 'high'),
  p('financial_fraud_web', 'advance_fee', 'tax payment to receive prize', 0.90, 'critical'),
  p('financial_fraud_web', 'advance_fee', 'custom fee to release package', 0.80, 'high'),
  p('financial_fraud_web', 'advance_fee', 'duty fee to release funds', 0.85, 'high'),
  p('financial_fraud_web', 'advance_fee', 'administration fee required', 0.80, 'high'),
  p('financial_fraud_web', 'advance_fee', 'legal fee to transfer funds', 0.85, 'high'),
  p('financial_fraud_web', 'advance_fee', 'notarization fee required', 0.80, 'high'),
  p('financial_fraud_web', 'advance_fee', 'certificate fee to unlock', 0.80, 'high'),
  p('financial_fraud_web', 'advance_fee', 'small fee to receive large sum', 0.90, 'critical'),
  p('financial_fraud_web', 'advance_fee', 'pay fee first to receive', 0.90, 'critical'),
  p('financial_fraud_web', 'advance_fee', 'transfer tax must be paid', 0.85, 'high'),
  p('financial_fraud_web', 'advance_fee', 'anti-money laundering clearance fee', 0.90, 'critical'),

  // -- Fake refund schemes --
  p('financial_fraud_web', 'fake_refund', 'overpayment refund owed to you', 0.85, 'high'),
  p('financial_fraud_web', 'fake_refund', 'you are owed a refund', 0.80, 'high'),
  p('financial_fraud_web', 'fake_refund', 'claim your refund now', 0.80, 'high'),
  p('financial_fraud_web', 'fake_refund', 'tax refund pending claim', 0.80, 'high'),
  p('financial_fraud_web', 'fake_refund', 'cashback claim available', 0.75, 'medium'),
  p('financial_fraud_web', 'fake_refund', 'rebate claim pending', 0.75, 'medium'),
  p('financial_fraud_web', 'fake_refund', 'government rebate pending', 0.80, 'high'),
  p('financial_fraud_web', 'fake_refund', 'insurance rebate claim', 0.75, 'medium'),
  p('financial_fraud_web', 'fake_refund', 'we owe you money click here', 0.85, 'high'),
  p('financial_fraud_web', 'fake_refund', 'unclaimed tax refund', 0.80, 'high'),

  // -- Ponzi / pyramid indicators --
  p('financial_fraud_web', 'ponzi', 'referral bonus guaranteed', 0.85, 'high'),
  p('financial_fraud_web', 'ponzi', 'downline earnings system', 0.85, 'high'),
  p('financial_fraud_web', 'ponzi', 'pyramid bonus structure', 0.85, 'high'),
  p('financial_fraud_web', 'ponzi', 'matrix system earnings', 0.85, 'high'),
  p('financial_fraud_web', 'ponzi', 'multi level earning guaranteed', 0.85, 'high'),
  p('financial_fraud_web', 'ponzi', 'network marketing guaranteed income', 0.80, 'high'),
  p('financial_fraud_web', 'ponzi', 'recruit two earn forever', 0.85, 'high'),
  p('financial_fraud_web', 'ponzi', 'join and earn from referrals', 0.75, 'medium'),
  p('financial_fraud_web', 'ponzi', 'unlimited referral commissions', 0.80, 'high'),
  p('financial_fraud_web', 'ponzi', 'residual passive earnings system', 0.75, 'medium'),
  p('financial_fraud_web', 'ponzi', 'ponzi platform investment', 0.95, 'critical'),
  p('financial_fraud_web', 'ponzi', 'chain letter investment', 0.90, 'critical'),
  p('financial_fraud_web', 'ponzi', 'high yield program', 0.85, 'high'),
  p('financial_fraud_web', 'ponzi', 'hyip investment', 0.85, 'high'),

  // -- Business email compromise --
  p('financial_fraud_web', 'bec', 'change payment details', 0.85, 'high'),
  p('financial_fraud_web', 'bec', 'new bank account details', 0.85, 'high'),
  p('financial_fraud_web', 'bec', 'updated wire details', 0.85, 'high'),
  p('financial_fraud_web', 'bec', 'please update vendor banking', 0.85, 'high'),
  p('financial_fraud_web', 'bec', 'ceo wire transfer request', 0.90, 'critical'),
  p('financial_fraud_web', 'bec', 'urgent invoice payment', 0.75, 'medium'),
  p('financial_fraud_web', 'bec', 'confidential wire request', 0.85, 'high'),
  p('financial_fraud_web', 'bec', 'executive payment request', 0.80, 'high'),
  p('financial_fraud_web', 'bec', 'payment must be done today', 0.80, 'high'),
  p('financial_fraud_web', 'bec', 'do not discuss with anyone', 0.85, 'high'),
  p('financial_fraud_web', 'bec', 'payment confirmed awaiting transfer', 0.80, 'high'),
  p('financial_fraud_web', 'bec', 'approve this transfer now', 0.80, 'high'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 24: MALWARE_DISTRIBUTION  (60 patterns)
// Phrases used to trick users into downloading malware
// ═══════════════════════════════════════════════════════════════════════════
const MALWARE_DISTRIBUTION: PatternEntry[] = [
  // -- Download trigger phrases --
  p('malware_dist', 'download_trigger', 'download required to continue', 0.90, 'critical'),
  p('malware_dist', 'download_trigger', 'install required to view', 0.90, 'critical'),
  p('malware_dist', 'download_trigger', 'plugin required to play', 0.85, 'high'),
  p('malware_dist', 'download_trigger', 'update required to access', 0.85, 'high'),
  p('malware_dist', 'download_trigger', 'download the player to continue', 0.85, 'high'),
  p('malware_dist', 'download_trigger', 'install codec to watch', 0.90, 'critical'),
  p('malware_dist', 'download_trigger', 'flash player update required', 0.95, 'critical'),
  p('malware_dist', 'download_trigger', 'java plugin required', 0.90, 'critical'),
  p('malware_dist', 'download_trigger', 'media player update download', 0.85, 'high'),
  p('malware_dist', 'download_trigger', 'browser extension required', 0.80, 'high'),
  p('malware_dist', 'download_trigger', 'click to download setup', 0.80, 'high'),
  p('malware_dist', 'download_trigger', 'download installer to unlock', 0.85, 'high'),
  p('malware_dist', 'download_trigger', 'run the file to continue', 0.85, 'high'),
  p('malware_dist', 'download_trigger', 'execute the downloaded file', 0.90, 'critical'),
  p('malware_dist', 'download_trigger', 'allow all permissions', 0.80, 'high'),
  p('malware_dist', 'download_trigger', 'disable antivirus to install', 0.95, 'critical'),
  p('malware_dist', 'download_trigger', 'turn off windows defender', 0.95, 'critical'),
  p('malware_dist', 'download_trigger', 'add to exceptions list', 0.75, 'medium'),
  p('malware_dist', 'download_trigger', 'false positive warning ignore', 0.85, 'high'),
  p('malware_dist', 'download_trigger', 'antivirus will flag this', 0.90, 'critical'),

  // -- Malicious file type indicators --
  p('malware_dist', 'file_type', 'download .exe file', 0.85, 'high'),
  p('malware_dist', 'file_type', 'download setup.exe', 0.80, 'high'),
  p('malware_dist', 'file_type', 'click to open .bat file', 0.90, 'critical'),
  p('malware_dist', 'file_type', 'run .vbs script', 0.90, 'critical'),
  p('malware_dist', 'file_type', 'open macro enabled document', 0.90, 'critical'),
  p('malware_dist', 'file_type', 'enable macros to view', 0.95, 'critical'),
  p('malware_dist', 'file_type', 'enable content to view document', 0.95, 'critical'),
  p('malware_dist', 'file_type', 'enable editing to view', 0.85, 'high'),
  p('malware_dist', 'file_type', 'protected document enable', 0.85, 'high'),
  p('malware_dist', 'file_type', 'zip password infected', 0.80, 'high'),

  // -- Drive-by download indicators --
  p('malware_dist', 'drive_by', 'your computer is infected', 0.90, 'critical'),
  p('malware_dist', 'drive_by', 'virus detected on your device', 0.90, 'critical'),
  p('malware_dist', 'drive_by', 'malware found scan now', 0.90, 'critical'),
  p('malware_dist', 'drive_by', 'critical error detected', 0.80, 'high'),
  p('malware_dist', 'drive_by', 'performance issue detected', 0.70, 'medium'),
  p('malware_dist', 'drive_by', 'your browser is outdated', 0.80, 'high'),
  p('malware_dist', 'drive_by', 'security risk detected', 0.80, 'high'),
  p('malware_dist', 'drive_by', 'click allow to prove you are not a robot', 0.90, 'critical'),
  p('malware_dist', 'drive_by', 'press allow to continue', 0.80, 'high'),
  p('malware_dist', 'drive_by', 'click allow to watch video', 0.85, 'high'),

  // -- Fake software/update distribution --
  p('malware_dist', 'fake_software', 'free download crack', 0.85, 'high'),
  p('malware_dist', 'fake_software', 'full version free download', 0.80, 'high'),
  p('malware_dist', 'fake_software', 'keygen free download', 0.85, 'high'),
  p('malware_dist', 'fake_software', 'serial number generator', 0.80, 'high'),
  p('malware_dist', 'fake_software', 'license key generator free', 0.85, 'high'),
  p('malware_dist', 'fake_software', 'patch download free', 0.75, 'medium'),
  p('malware_dist', 'fake_software', 'cracked version download', 0.85, 'high'),
  p('malware_dist', 'fake_software', 'nulled script download', 0.80, 'high'),
  p('malware_dist', 'fake_software', 'pirated software download', 0.85, 'high'),
  p('malware_dist', 'fake_software', 'bypass activation download', 0.85, 'high'),
  p('malware_dist', 'fake_software', 'warez download', 0.85, 'high'),
  p('malware_dist', 'fake_software', 'torrent direct download', 0.65, 'medium'),
  p('malware_dist', 'fake_software', 'offline installer direct link', 0.65, 'medium'),
  p('malware_dist', 'fake_software', 'portable version no install', 0.60, 'low'),
  p('malware_dist', 'fake_software', 'repack compressed download', 0.65, 'medium'),
  p('malware_dist', 'fake_software', 'fitgirl repacks download', 0.70, 'medium'),
  p('malware_dist', 'fake_software', 'igg games download', 0.70, 'medium'),
  p('malware_dist', 'fake_software', 'oceanofgames download', 0.70, 'medium'),
  p('malware_dist', 'fake_software', 'skidrow codex download', 0.75, 'medium'),
  p('malware_dist', 'fake_software', 'razor1911 download', 0.75, 'medium'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 25: RANSOMWARE_DELIVERY  (50 patterns)
// Ransomware pretexts, macro-enabled docs, dropper language
// ═══════════════════════════════════════════════════════════════════════════
const RANSOMWARE_DELIVERY: PatternEntry[] = [
  // -- Invoice / document lures (most common delivery vector) --
  p('ransomware', 'invoice_lure', 'invoice attached enable macros', 0.95, 'critical'),
  p('ransomware', 'invoice_lure', 'payment confirmation attached', 0.80, 'high'),
  p('ransomware', 'invoice_lure', 'open attached invoice document', 0.75, 'medium'),
  p('ransomware', 'invoice_lure', 'enable content to view invoice', 0.95, 'critical'),
  p('ransomware', 'invoice_lure', 'protected document click enable', 0.95, 'critical'),
  p('ransomware', 'invoice_lure', 'word document with macros', 0.90, 'critical'),
  p('ransomware', 'invoice_lure', 'excel file enable editing', 0.90, 'critical'),
  p('ransomware', 'invoice_lure', 'docm file download', 0.90, 'critical'),
  p('ransomware', 'invoice_lure', 'xlsm attachment open', 0.90, 'critical'),
  p('ransomware', 'invoice_lure', 'pdf with javascript', 0.85, 'high'),

  // -- Ransomware note phrases --
  p('ransomware', 'ransom_note', 'your files are encrypted', 0.98, 'critical'),
  p('ransomware', 'ransom_note', 'all your files have been encrypted', 0.98, 'critical'),
  p('ransomware', 'ransom_note', 'your personal files are encrypted', 0.98, 'critical'),
  p('ransomware', 'ransom_note', 'pay ransom to decrypt files', 0.98, 'critical'),
  p('ransomware', 'ransom_note', 'pay to restore your files', 0.95, 'critical'),
  p('ransomware', 'ransom_note', 'bitcoin payment for decryption', 0.95, 'critical'),
  p('ransomware', 'ransom_note', 'decryption key will be provided', 0.90, 'critical'),
  p('ransomware', 'ransom_note', 'contact us to recover files', 0.85, 'high'),
  p('ransomware', 'ransom_note', 'unique decryption key', 0.90, 'critical'),
  p('ransomware', 'ransom_note', 'files will be deleted permanently', 0.85, 'high'),
  p('ransomware', 'ransom_note', 'ransom payment deadline', 0.95, 'critical'),
  p('ransomware', 'ransom_note', 'price increases every 24 hours', 0.90, 'critical'),
  p('ransomware', 'ransom_note', 'do not rename encrypted files', 0.90, 'critical'),
  p('ransomware', 'ransom_note', 'do not try to decrypt files yourself', 0.90, 'critical'),
  p('ransomware', 'ransom_note', 'we have your data leaked', 0.90, 'critical'),
  p('ransomware', 'ransom_note', 'double extortion payment', 0.90, 'critical'),

  // -- Known ransomware family indicators --
  p('ransomware', 'family_indicator', 'wanna cry ransomware', 0.95, 'critical'),
  p('ransomware', 'family_indicator', 'lockbit ransomware', 0.95, 'critical'),
  p('ransomware', 'family_indicator', 'ryuk infection', 0.95, 'critical'),
  p('ransomware', 'family_indicator', 'maze ransomware', 0.95, 'critical'),
  p('ransomware', 'family_indicator', 'revil sodinokibi', 0.95, 'critical'),
  p('ransomware', 'family_indicator', 'darkside ransomware attack', 0.95, 'critical'),
  p('ransomware', 'family_indicator', 'conti ransomware', 0.95, 'critical'),
  p('ransomware', 'family_indicator', 'blackcat ransomware', 0.95, 'critical'),
  p('ransomware', 'family_indicator', 'clop ransomware', 0.95, 'critical'),
  p('ransomware', 'family_indicator', 'medusa ransomware', 0.95, 'critical'),

  // -- Social engineering delivery --
  p('ransomware', 'social_eng', 'urgent security patch attached', 0.85, 'high'),
  p('ransomware', 'social_eng', 'fbi cybercrime division notice', 0.85, 'high'),
  p('ransomware', 'social_eng', 'court summons attached document', 0.85, 'high'),
  p('ransomware', 'social_eng', 'irs tax document attached', 0.80, 'high'),
  p('ransomware', 'social_eng', 'shipping label attached click', 0.75, 'medium'),
  p('ransomware', 'social_eng', 'your order confirmation attached', 0.65, 'medium'),
  p('ransomware', 'social_eng', 'bank statement attached open', 0.70, 'medium'),
  p('ransomware', 'social_eng', 'hr document requires signature', 0.70, 'medium'),
  p('ransomware', 'social_eng', 'contract attached please sign', 0.65, 'medium'),
  p('ransomware', 'social_eng', 'scan result attached click', 0.75, 'medium'),
  p('ransomware', 'social_eng', 'voicemail attached listen', 0.70, 'medium'),
  p('ransomware', 'social_eng', 'fax notification attached', 0.70, 'medium'),
  p('ransomware', 'social_eng', 'shared file click to view', 0.65, 'medium'),
  p('ransomware', 'social_eng', 'dropbox shared file click', 0.65, 'medium'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 26: FAKE_ANTIVIRUS / SCAREWARE  (50 patterns)
// Fake security alert pages, rogue AV, browser lockers
// ═══════════════════════════════════════════════════════════════════════════
const FAKE_ANTIVIRUS: PatternEntry[] = [
  // -- Fake virus alerts --
  p('fake_av', 'fake_alert', 'your pc is infected with virus', 0.95, 'critical'),
  p('fake_av', 'fake_alert', 'virus detected on your computer', 0.95, 'critical'),
  p('fake_av', 'fake_alert', 'trojan detected immediately remove', 0.95, 'critical'),
  p('fake_av', 'fake_alert', 'spyware detected remove now', 0.95, 'critical'),
  p('fake_av', 'fake_alert', 'malware infection detected', 0.90, 'critical'),
  p('fake_av', 'fake_alert', 'critical virus alert', 0.90, 'critical'),
  p('fake_av', 'fake_alert', 'ransomware detected on your pc', 0.90, 'critical'),
  p('fake_av', 'fake_alert', 'hacker is watching you', 0.85, 'high'),
  p('fake_av', 'fake_alert', 'your ip has been hacked', 0.85, 'high'),
  p('fake_av', 'fake_alert', 'identity theft detected', 0.85, 'high'),
  p('fake_av', 'fake_alert', 'windows security alert virus', 0.95, 'critical'),
  p('fake_av', 'fake_alert', 'apple security alert virus', 0.95, 'critical'),
  p('fake_av', 'fake_alert', 'microsoft virus warning', 0.90, 'critical'),
  p('fake_av', 'fake_alert', 'google security warning virus', 0.90, 'critical'),
  p('fake_av', 'fake_alert', 'call microsoft support now', 0.95, 'critical'),

  // -- Tech support scam triggers --
  p('fake_av', 'tech_support', 'call toll free immediately', 0.85, 'high'),
  p('fake_av', 'tech_support', 'call this number to fix', 0.85, 'high'),
  p('fake_av', 'tech_support', 'do not restart your computer', 0.90, 'critical'),
  p('fake_av', 'tech_support', 'do not close this window', 0.85, 'high'),
  p('fake_av', 'tech_support', 'your computer is locked', 0.90, 'critical'),
  p('fake_av', 'tech_support', 'your browser has been blocked', 0.90, 'critical'),
  p('fake_av', 'tech_support', 'windows has been suspended', 0.90, 'critical'),
  p('fake_av', 'tech_support', 'error code 0x80070', 0.90, 'critical'),
  p('fake_av', 'tech_support', 'error code ox800xxxx', 0.90, 'critical'),
  p('fake_av', 'tech_support', 'microsoft error code call', 0.95, 'critical'),

  // -- Rogue AV download lures --
  p('fake_av', 'rogue_av', 'free virus scan download', 0.80, 'high'),
  p('fake_av', 'rogue_av', 'download free antivirus now', 0.75, 'medium'),
  p('fake_av', 'rogue_av', 'best free malware remover', 0.70, 'medium'),
  p('fake_av', 'rogue_av', 'remove virus free tool', 0.75, 'medium'),
  p('fake_av', 'rogue_av', 'pc cleaner download free', 0.75, 'medium'),
  p('fake_av', 'rogue_av', 'registry cleaner download', 0.70, 'medium'),
  p('fake_av', 'rogue_av', 'junk cleaner download', 0.65, 'medium'),
  p('fake_av', 'rogue_av', 'system optimizer download free', 0.65, 'medium'),
  p('fake_av', 'rogue_av', 'scan complete threats found', 0.85, 'high'),
  p('fake_av', 'rogue_av', 'your scan results threats', 0.80, 'high'),
  p('fake_av', 'rogue_av', 'fix all issues automatically', 0.75, 'medium'),

  // -- Browser locker patterns --
  p('fake_av', 'browser_locker', 'your browser is locked', 0.90, 'critical'),
  p('fake_av', 'browser_locker', 'access to device is blocked', 0.85, 'high'),
  p('fake_av', 'browser_locker', 'illegal activity detected on pc', 0.90, 'critical'),
  p('fake_av', 'browser_locker', 'fbi warning your computer blocked', 0.90, 'critical'),
  p('fake_av', 'browser_locker', 'police cybercrime unit warning', 0.90, 'critical'),
  p('fake_av', 'browser_locker', 'your ip has been blocked', 0.85, 'high'),
  p('fake_av', 'browser_locker', 'pay fine to unlock computer', 0.90, 'critical'),
  p('fake_av', 'browser_locker', 'pay penalty to restore access', 0.90, 'critical'),
  p('fake_av', 'browser_locker', 'copyright violation detected', 0.80, 'high'),
  p('fake_av', 'browser_locker', 'child pornography detected warning', 0.95, 'critical'),
  p('fake_av', 'browser_locker', 'press f1 for tech support', 0.80, 'high'),
  p('fake_av', 'browser_locker', 'press ok to remove virus', 0.80, 'high'),
  p('fake_av', 'browser_locker', 'this page is dangerous', 0.65, 'medium'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 27: CREDENTIAL_STEALER  (50 patterns)
// Info-stealer delivery, form-jacking, browser extension abuse
// ═══════════════════════════════════════════════════════════════════════════
const CREDENTIAL_STEALER: PatternEntry[] = [
  // -- Fake login / credential harvest --
  p('cred_steal', 'fake_login', 'your account has been suspended', 0.80, 'high'),
  p('cred_steal', 'fake_login', 'verify your account to continue', 0.80, 'high'),
  p('cred_steal', 'fake_login', 'confirm your identity below', 0.80, 'high'),
  p('cred_steal', 'fake_login', 'enter your password to verify', 0.85, 'high'),
  p('cred_steal', 'fake_login', 'login to verify your identity', 0.80, 'high'),
  p('cred_steal', 'fake_login', 're-enter your credentials', 0.80, 'high'),
  p('cred_steal', 'fake_login', 'sign in with google to continue', 0.70, 'medium'),
  p('cred_steal', 'fake_login', 'two factor verification required', 0.65, 'medium'),
  p('cred_steal', 'fake_login', 'enter otp to verify', 0.65, 'medium'),
  p('cred_steal', 'fake_login', 'google login required to view', 0.75, 'medium'),

  // -- Stealer payload indicators --
  p('cred_steal', 'stealer_payload', 'redline stealer', 0.95, 'critical'),
  p('cred_steal', 'stealer_payload', 'raccoon stealer', 0.95, 'critical'),
  p('cred_steal', 'stealer_payload', 'azorult stealer', 0.95, 'critical'),
  p('cred_steal', 'stealer_payload', 'vidar stealer', 0.95, 'critical'),
  p('cred_steal', 'stealer_payload', 'formbook stealer', 0.95, 'critical'),
  p('cred_steal', 'stealer_payload', 'agent tesla stealer', 0.95, 'critical'),
  p('cred_steal', 'stealer_payload', 'lokibot stealer', 0.95, 'critical'),
  p('cred_steal', 'stealer_payload', 'trickbot banker', 0.95, 'critical'),
  p('cred_steal', 'stealer_payload', 'emotet loader', 0.95, 'critical'),
  p('cred_steal', 'stealer_payload', 'qakbot infection', 0.95, 'critical'),
  p('cred_steal', 'stealer_payload', 'icedid banker', 0.95, 'critical'),
  p('cred_steal', 'stealer_payload', 'dridex banker', 0.95, 'critical'),

  // -- Social engineering credential theft --
  p('cred_steal', 'social_eng', 'update your payment details', 0.80, 'high'),
  p('cred_steal', 'social_eng', 'confirm billing information', 0.75, 'medium'),
  p('cred_steal', 'social_eng', 'card declined update now', 0.80, 'high'),
  p('cred_steal', 'social_eng', 'unusual sign in attempt', 0.75, 'medium'),
  p('cred_steal', 'social_eng', 'someone tried to access your account', 0.75, 'medium'),
  p('cred_steal', 'social_eng', 'suspicious login from new device', 0.75, 'medium'),
  p('cred_steal', 'social_eng', 'password reset required immediately', 0.80, 'high'),
  p('cred_steal', 'social_eng', 'account recovery verify now', 0.80, 'high'),
  p('cred_steal', 'social_eng', 'locked out of account verify', 0.80, 'high'),
  p('cred_steal', 'social_eng', 'security code verify identity', 0.75, 'medium'),

  // -- Browser extension abuse --
  p('cred_steal', 'browser_ext', 'add extension to access content', 0.85, 'high'),
  p('cred_steal', 'browser_ext', 'install chrome extension to proceed', 0.85, 'high'),
  p('cred_steal', 'browser_ext', 'extension required to view page', 0.85, 'high'),
  p('cred_steal', 'browser_ext', 'add to chrome unlock content', 0.80, 'high'),
  p('cred_steal', 'browser_ext', 'download browser extension', 0.75, 'medium'),
  p('cred_steal', 'browser_ext', 'chrome extension download free', 0.70, 'medium'),
  p('cred_steal', 'browser_ext', 'add extension for better experience', 0.65, 'medium'),

  // -- Form-jacking / data theft indicators --
  p('cred_steal', 'formjack', 'enter card number to verify', 0.85, 'high'),
  p('cred_steal', 'formjack', 'confirm credit card details', 0.85, 'high'),
  p('cred_steal', 'formjack', 'enter ssn to verify identity', 0.90, 'critical'),
  p('cred_steal', 'formjack', 'social security number required', 0.85, 'high'),
  p('cred_steal', 'formjack', 'enter cvv code to verify', 0.85, 'high'),
  p('cred_steal', 'formjack', 'enter bank routing number', 0.85, 'high'),
  p('cred_steal', 'formjack', 'enter account pin to confirm', 0.85, 'high'),
  p('cred_steal', 'formjack', 'submit full card details', 0.90, 'critical'),
  p('cred_steal', 'formjack', 'billing address and card', 0.70, 'medium'),
  p('cred_steal', 'formjack', 'mother maiden name security', 0.80, 'high'),
  p('cred_steal', 'formjack', 'date of birth verification', 0.65, 'medium'),
];

// ═══════════════════════════════════════════════════════════════════════════
// GROUP 28: URL_MALWARE_PATTERNS  (60 patterns)
// URL path/param patterns specific to malware delivery and phishing
// ═══════════════════════════════════════════════════════════════════════════
const URL_MALWARE_PATTERNS: PatternEntry[] = [
  // -- Malicious URL path components --
  p('url_malware', 'path_pattern', '/download/setup.exe', 0.85, 'high'),
  p('url_malware', 'path_pattern', '/files/payload', 0.80, 'high'),
  p('url_malware', 'path_pattern', '/wp-content/uploads/malware', 0.80, 'high'),
  p('url_malware', 'path_pattern', '/gate.php', 0.80, 'high'),
  p('url_malware', 'path_pattern', '/panel/gate', 0.80, 'high'),
  p('url_malware', 'path_pattern', '/c2/beacon', 0.90, 'critical'),
  p('url_malware', 'path_pattern', '/rat/connect', 0.90, 'critical'),
  p('url_malware', 'path_pattern', '/bot/check', 0.85, 'high'),
  p('url_malware', 'path_pattern', '/loader/payload', 0.85, 'high'),
  p('url_malware', 'path_pattern', '/drop/download', 0.85, 'high'),

  // -- Exploit kit landing pages --
  p('url_malware', 'exploit_kit', 'rig exploit kit', 0.95, 'critical'),
  p('url_malware', 'exploit_kit', 'fallout exploit kit', 0.95, 'critical'),
  p('url_malware', 'exploit_kit', 'magnitude exploit kit', 0.95, 'critical'),
  p('url_malware', 'exploit_kit', 'purple fox exploit', 0.95, 'critical'),
  p('url_malware', 'exploit_kit', 'angler exploit kit', 0.95, 'critical'),
  p('url_malware', 'exploit_kit', 'nuclear exploit kit', 0.95, 'critical'),
  p('url_malware', 'exploit_kit', 'neutrino exploit kit', 0.95, 'critical'),
  p('url_malware', 'exploit_kit', 'drive by exploit landing', 0.90, 'critical'),
  p('url_malware', 'exploit_kit', 'cve exploit payload', 0.85, 'high'),
  p('url_malware', 'exploit_kit', 'zero day exploit download', 0.90, 'critical'),

  // -- Malware C2 / beacon patterns --
  p('url_malware', 'c2_pattern', 'cobalt strike beacon', 0.95, 'critical'),
  p('url_malware', 'c2_pattern', 'metasploit payload', 0.90, 'critical'),
  p('url_malware', 'c2_pattern', 'meterpreter session', 0.90, 'critical'),
  p('url_malware', 'c2_pattern', 'reverse shell connect', 0.90, 'critical'),
  p('url_malware', 'c2_pattern', 'netcat listener', 0.85, 'high'),
  p('url_malware', 'c2_pattern', 'command and control server', 0.90, 'critical'),
  p('url_malware', 'c2_pattern', 'c2 server callback', 0.90, 'critical'),
  p('url_malware', 'c2_pattern', 'botnet command server', 0.90, 'critical'),
  p('url_malware', 'c2_pattern', 'rat remote access trojan', 0.90, 'critical'),
  p('url_malware', 'c2_pattern', 'keylogger activity detected', 0.85, 'high'),

  // -- Spam / phishing URL indicators --
  p('url_malware', 'phish_url', 'login-verify.', 0.85, 'high'),
  p('url_malware', 'phish_url', 'account-confirm.', 0.85, 'high'),
  p('url_malware', 'phish_url', 'secure-update.', 0.85, 'high'),
  p('url_malware', 'phish_url', 'verify-account.', 0.85, 'high'),
  p('url_malware', 'phish_url', 'signin-page.', 0.85, 'high'),
  p('url_malware', 'phish_url', 'account-suspended.', 0.85, 'high'),
  p('url_malware', 'phish_url', 'password-reset.', 0.80, 'high'),
  p('url_malware', 'phish_url', 'billing-update.', 0.80, 'high'),
  p('url_malware', 'phish_url', 'payment-confirm.', 0.80, 'high'),
  p('url_malware', 'phish_url', 'prize-claim.', 0.85, 'high'),

  // -- Redirect chain / obfuscation indicators --
  p('url_malware', 'redirect_chain', 'click tracking redirect', 0.65, 'medium'),
  p('url_malware', 'redirect_chain', 'url redirect exploit', 0.80, 'high'),
  p('url_malware', 'redirect_chain', 'open redirect vulnerability', 0.80, 'high'),
  p('url_malware', 'redirect_chain', 'malicious redirect chain', 0.85, 'high'),
  p('url_malware', 'redirect_chain', 'cloaked landing page', 0.80, 'high'),
  p('url_malware', 'redirect_chain', 'seo cloaking technique', 0.75, 'medium'),
  p('url_malware', 'redirect_chain', 'javascript redirect malware', 0.80, 'high'),
  p('url_malware', 'redirect_chain', 'iframe injection redirect', 0.80, 'high'),
  p('url_malware', 'redirect_chain', 'malicious javascript code', 0.80, 'high'),
  p('url_malware', 'redirect_chain', 'script injection detected', 0.80, 'high'),

  // -- Compromised/hacked website indicators --
  p('url_malware', 'hacked_site', 'wp-includes/malware', 0.85, 'high'),
  p('url_malware', 'hacked_site', 'wp-admin/gate.php', 0.85, 'high'),
  p('url_malware', 'hacked_site', 'hacked website malware', 0.85, 'high'),
  p('url_malware', 'hacked_site', 'compromised site phishing', 0.80, 'high'),
  p('url_malware', 'hacked_site', 'watering hole attack', 0.85, 'high'),
  p('url_malware', 'hacked_site', 'malicious code injected', 0.85, 'high'),
  p('url_malware', 'hacked_site', 'cross site scripting xss', 0.80, 'high'),
  p('url_malware', 'hacked_site', 'sql injection attack', 0.80, 'high'),
  p('url_malware', 'hacked_site', 'file inclusion exploit', 0.80, 'high'),
  p('url_malware', 'hacked_site', 'remote code execution exploit', 0.85, 'high'),
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
  // Expansions of existing groups
  ...CRYPTO_SCAM_EXT,
  ...PHISHING_EXT,
  ...TECH_SUPPORT_EXT,
  ...EMPLOYMENT_SCAM_EXT,
  ...DELIVERY_SCAM_EXT,
  ...GOVERNMENT_SCAM_EXT,
  // New website-focused groups
  ...WEBSITE_SCAM,
  ...DOMAIN_TRICKS,
  ...FAKE_AUTHORITY,
  ...SOCIAL_ENGINEERING_WEB,
  ...ROMANCE_WEBSITE,
  ...FINANCIAL_FRAUD_WEB,
  // New malware/virus/URL threat groups
  ...MALWARE_DISTRIBUTION,
  ...RANSOMWARE_DELIVERY,
  ...FAKE_ANTIVIRUS,
  ...CREDENTIAL_STEALER,
  ...URL_MALWARE_PATTERNS,
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
