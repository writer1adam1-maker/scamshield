// ============================================================================
// ScamShield Scam Template Similarity Engine
// Proprietary algorithm: trigram Jaccard, TF-IDF cosine similarity, and
// structural pattern matching against 50+ curated scam templates.
// ============================================================================

import {
  ThreatCategory,
  ThreatLevel,
  ScamTemplate,
  TemplateStructureTag,
  TemplateMatch,
  SimilarityResult,
} from './types';

// ---------------------------------------------------------------------------
// Weights
// ---------------------------------------------------------------------------

const TRIGRAM_WEIGHT = 0.35;
const TFIDF_WEIGHT = 0.40;
const STRUCTURAL_WEIGHT = 0.25;
const TOP_N = 3;

// ---------------------------------------------------------------------------
// Trigram Jaccard Similarity
// ---------------------------------------------------------------------------

function extractTrigrams(text: string): Set<string> {
  const norm = text.toLowerCase().replace(/[^a-z0-9 ]/g, '');
  const set = new Set<string>();
  for (let i = 0; i <= norm.length - 3; i++) {
    set.add(norm.substring(i, i + 3));
  }
  return set;
}

function jaccardSimilarity(a: Set<string>, b: Set<string>): number {
  if (a.size === 0 && b.size === 0) return 0;
  let intersection = 0;
  for (const item of a) {
    if (b.has(item)) intersection++;
  }
  const union = a.size + b.size - intersection;
  return union > 0 ? intersection / union : 0;
}

// ---------------------------------------------------------------------------
// TF-IDF Cosine Similarity
// ---------------------------------------------------------------------------

interface TfIdfVector {
  terms: Map<string, number>;
  magnitude: number;
}

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9']/g, ' ')
    .split(/\s+/)
    .filter((t) => t.length > 1);
}

function computeTF(tokens: string[]): Map<string, number> {
  const freq = new Map<string, number>();
  for (const token of tokens) {
    freq.set(token, (freq.get(token) || 0) + 1);
  }
  const maxFreq = Math.max(...freq.values(), 1);
  for (const [term, count] of freq) {
    freq.set(term, 0.5 + 0.5 * (count / maxFreq));
  }
  return freq;
}

function buildIDF(documents: string[]): Map<string, number> {
  const n = documents.length;
  const docFreq = new Map<string, number>();
  for (const doc of documents) {
    const unique = new Set(tokenize(doc));
    for (const token of unique) {
      docFreq.set(token, (docFreq.get(token) || 0) + 1);
    }
  }
  const idf = new Map<string, number>();
  for (const [term, df] of docFreq) {
    idf.set(term, Math.log((n + 1) / (df + 1)) + 1);
  }
  return idf;
}

function buildTfIdfVector(text: string, idf: Map<string, number>): TfIdfVector {
  const tokens = tokenize(text);
  const tf = computeTF(tokens);
  const terms = new Map<string, number>();
  let magSq = 0;
  for (const [term, tfVal] of tf) {
    const idfVal = idf.get(term) ?? 1;
    const weight = tfVal * idfVal;
    terms.set(term, weight);
    magSq += weight * weight;
  }
  return { terms, magnitude: Math.sqrt(magSq) };
}

function cosineSimilarity(a: TfIdfVector, b: TfIdfVector): number {
  if (a.magnitude === 0 || b.magnitude === 0) return 0;
  let dot = 0;
  for (const [term, wA] of a.terms) {
    const wB = b.terms.get(term);
    if (wB !== undefined) {
      dot += wA * wB;
    }
  }
  return dot / (a.magnitude * b.magnitude);
}

// ---------------------------------------------------------------------------
// Structural Similarity
// ---------------------------------------------------------------------------

const STRUCTURE_PATTERNS: Record<TemplateStructureTag, RegExp[]> = {
  greeting: [
    /^(dear|hello|hi|greetings|attention)\b/i,
    /valued (customer|member|user)/i,
  ],
  urgency: [
    /\b(urgent|immediate(ly)?|right away|asap|time.?sensitive)\b/i,
    /\b(act now|don't delay|hurry|limited time|expires? (today|soon|in \d))\b/i,
    /\b(within \d+ (hours?|minutes?|days?))\b/i,
  ],
  authority: [
    /\b(official|authorized|verified|department|bureau|federal|government)\b/i,
    /\b(compliance|regulation|enforcement|investigation)\b/i,
  ],
  action: [
    /\b(click|tap|visit|go to|navigate|open|follow)\b.*\b(link|url|button|here)\b/i,
    /\b(verify|confirm|update|validate|secure)\b.*\b(account|identity|information|details)\b/i,
  ],
  deadline: [
    /\b(deadline|expires?|by (today|tomorrow|\w+day))\b/i,
    /\b(within|before|no later than)\b.*\b(\d+ (hours?|days?|minutes?))\b/i,
    /\b(last chance|final notice|final warning)\b/i,
  ],
  threat: [
    /\b(suspend(ed)?|terminat(e|ed)|clos(e|ed)|lock(ed)?|restrict(ed)?|disable[d]?)\b/i,
    /\b(legal action|arrest|warrant|prosecution|penalty|fine)\b/i,
    /\b(lose access|permanently|irreversible)\b/i,
  ],
  reward: [
    /\b(congratulations|winner|won|selected|chosen|lucky)\b/i,
    /\b(prize|reward|gift|bonus|cashback|refund|grant)\b/i,
    /\$[\d,]+/,
  ],
  link: [
    /https?:\/\/[^\s]+/i,
    /\bwww\.[^\s]+/i,
    /\b(bit\.ly|tinyurl|t\.co|goo\.gl|is\.gd)\b/i,
  ],
  personal_info_request: [
    /\b(ssn|social security|date of birth|dob|mother'?s? maiden)\b/i,
    /\b(credit card|bank account|routing number|password|pin)\b/i,
    /\b(provide|enter|send|submit|share)\b.*\b(information|details|credentials)\b/i,
  ],
  closing: [
    /\b(sincerely|regards|thank you|respectfully)\b/i,
    /\b(customer (service|support)|help desk|team)\b/i,
  ],
};

function detectStructure(text: string): TemplateStructureTag[] {
  const tags: TemplateStructureTag[] = [];
  for (const [tag, patterns] of Object.entries(STRUCTURE_PATTERNS) as [
    TemplateStructureTag,
    RegExp[],
  ][]) {
    if (patterns.some((rx) => rx.test(text))) {
      tags.push(tag);
    }
  }
  return tags;
}

/**
 * Structural similarity using Jaccard over detected structure tags,
 * with bonus weighting for the urgency->action->deadline "scam flow".
 */
function structuralSimilarity(
  inputTags: TemplateStructureTag[],
  templateTags: TemplateStructureTag[],
): number {
  const setA = new Set(inputTags);
  const setB = new Set(templateTags);
  if (setA.size === 0 && setB.size === 0) return 0;

  let intersection = 0;
  for (const tag of setA) {
    if (setB.has(tag)) intersection++;
  }
  const union = new Set([...setA, ...setB]).size;
  const baseScore = union > 0 ? intersection / union : 0;

  // Bonus for the classic scam flow: urgency + action + deadline
  const scamFlowTags: TemplateStructureTag[] = ['urgency', 'action', 'deadline'];
  const inputHasFlow = scamFlowTags.every((t) => setA.has(t));
  const templateHasFlow = scamFlowTags.every((t) => setB.has(t));
  const flowBonus = inputHasFlow && templateHasFlow ? 0.15 : 0;

  return Math.min(1, baseScore + flowBonus);
}

// ---------------------------------------------------------------------------
// Scam Template Database (50+ templates)
// ---------------------------------------------------------------------------

let _templateDb: ScamTemplate[] | null = null;
let _idf: Map<string, number> | null = null;
let _templateVectors: Map<string, TfIdfVector> | null = null;
let _templateTrigrams: Map<string, Set<string>> | null = null;

function createTemplate(
  id: string,
  name: string,
  category: ThreatCategory,
  riskLevel: ThreatLevel,
  text: string,
  structure: TemplateStructureTag[],
  keywords: string[],
): ScamTemplate {
  return { id, name, category, riskLevel, text, structure, keywords };
}

export function getTemplateDatabase(): ScamTemplate[] {
  if (_templateDb) return _templateDb;

  _templateDb = [
    // --- PACKAGE DELIVERY (6 templates) ---
    createTemplate('pkg-usps-01', 'USPS Delivery Failed', ThreatCategory.PACKAGE_DELIVERY, 'HIGH',
      'USPS: Your package could not be delivered due to an incomplete address. Please update your delivery details within 24 hours to avoid return to sender. Click here to verify: http://usps-delivery-update.com/verify',
      ['urgency', 'action', 'deadline', 'link'], ['usps', 'package', 'delivery', 'address', 'verify']),
    createTemplate('pkg-fedex-01', 'FedEx Customs Fee', ThreatCategory.PACKAGE_DELIVERY, 'HIGH',
      'FedEx: Your shipment #FX8492731 is being held at customs. A fee of $3.99 is required for processing. Pay now to release your package: http://fedex-customs-pay.com/release',
      ['urgency', 'action', 'link'], ['fedex', 'customs', 'fee', 'shipment', 'pay']),
    createTemplate('pkg-ups-01', 'UPS Redelivery', ThreatCategory.PACKAGE_DELIVERY, 'HIGH',
      'UPS: We attempted delivery but no one was available. Schedule a redelivery or your package will be returned. Confirm at: http://ups-reschedule.net/confirm',
      ['urgency', 'action', 'deadline', 'link'], ['ups', 'delivery', 'reschedule', 'package']),
    createTemplate('pkg-amazon-01', 'Amazon Delivery Issue', ThreatCategory.PACKAGE_DELIVERY, 'MEDIUM',
      'Amazon: There is a problem with your recent order delivery. Your package is being held. Please verify your shipping address to proceed: http://amzn-ship-verify.com/address',
      ['urgency', 'action', 'link'], ['amazon', 'order', 'delivery', 'shipping', 'verify']),
    createTemplate('pkg-dhl-01', 'DHL Express Fee', ThreatCategory.PACKAGE_DELIVERY, 'HIGH',
      'DHL Express: Your parcel is waiting for payment of import duties ($4.50). Pay immediately or it will be returned to sender within 48 hours.',
      ['urgency', 'action', 'deadline', 'threat'], ['dhl', 'parcel', 'import', 'duties', 'payment']),
    createTemplate('pkg-generic-01', 'Generic Missed Delivery', ThreatCategory.PACKAGE_DELIVERY, 'MEDIUM',
      'You have a package waiting! We tried to deliver but missed you. Confirm delivery details here to get your package.',
      ['action', 'link'], ['package', 'deliver', 'confirm', 'details']),

    // --- BANK / FINANCIAL (8 templates) ---
    createTemplate('bank-alert-01', 'Bank Fraud Alert', ThreatCategory.PHISHING, 'CRITICAL',
      'ALERT: Suspicious activity detected on your bank account. Your account has been temporarily locked for security. Verify your identity immediately to restore access: http://secure-bank-verify.com/auth',
      ['urgency', 'authority', 'action', 'threat', 'link'], ['bank', 'suspicious', 'locked', 'verify', 'identity', 'account']),
    createTemplate('bank-alert-02', 'Wire Transfer Alert', ThreatCategory.PHISHING, 'CRITICAL',
      'URGENT: A wire transfer of $2,499.00 was initiated from your account. If you did not authorize this, click here immediately to cancel: http://bank-wire-cancel.com/stop',
      ['urgency', 'action', 'link', 'threat'], ['wire', 'transfer', 'authorize', 'cancel', 'account']),
    createTemplate('bank-alert-03', 'Account Verification', ThreatCategory.PHISHING, 'HIGH',
      'Your online banking access will expire unless you verify your account information. Complete verification within 24 hours to maintain access: http://banking-verify.net/update',
      ['urgency', 'deadline', 'action', 'threat', 'link'], ['banking', 'verify', 'expire', 'access', 'account']),
    createTemplate('bank-paypal-01', 'PayPal Limitation', ThreatCategory.PHISHING, 'HIGH',
      'PayPal: Your account has been limited due to unusual activity. Please log in and complete the steps to remove the limitation. Visit: http://paypal-secure-resolve.com/limit',
      ['authority', 'action', 'threat', 'link'], ['paypal', 'limited', 'unusual', 'activity', 'account']),
    createTemplate('bank-paypal-02', 'PayPal Payment Received', ThreatCategory.PHISHING, 'MEDIUM',
      'You received a payment of $350.00 on PayPal. Due to the high amount, verification is required before the funds are available. Verify here: http://paypal-verify-payment.com',
      ['reward', 'action', 'link'], ['paypal', 'payment', 'received', 'verification', 'funds']),
    createTemplate('bank-venmo-01', 'Venmo Suspicious Login', ThreatCategory.PHISHING, 'HIGH',
      'Venmo Security: Someone attempted to log in to your Venmo account from an unrecognized device. If this wasn\'t you, secure your account now: http://venmo-secure-login.com',
      ['authority', 'urgency', 'action', 'threat', 'link'], ['venmo', 'login', 'unrecognized', 'device', 'secure']),
    createTemplate('bank-zelle-01', 'Zelle Payment Fraud', ThreatCategory.PHISHING, 'CRITICAL',
      'Zelle: A payment of $500.00 is pending from your account. Reply YES to confirm or visit http://zelle-fraud-alert.com to dispute this transaction immediately.',
      ['urgency', 'action', 'link'], ['zelle', 'payment', 'pending', 'confirm', 'dispute']),
    createTemplate('bank-cashapp-01', 'Cash App Verification', ThreatCategory.PHISHING, 'HIGH',
      'Cash App: Your account requires verification to continue sending and receiving money. Complete identity verification: http://cashapp-id-verify.com',
      ['authority', 'action', 'link', 'personal_info_request'], ['cashapp', 'verification', 'identity', 'sending', 'receiving']),

    // --- IRS / GOVERNMENT (5 templates) ---
    createTemplate('irs-01', 'IRS Tax Refund', ThreatCategory.IRS_GOV, 'CRITICAL',
      'IRS Notice: You have an unclaimed tax refund of $1,247.00. To receive your refund, you must verify your identity and provide your bank details. Visit: http://irs-refund-claim.com/verify',
      ['authority', 'reward', 'action', 'personal_info_request', 'link'], ['irs', 'tax', 'refund', 'identity', 'bank', 'verify']),
    createTemplate('irs-02', 'IRS Audit Threat', ThreatCategory.IRS_GOV, 'CRITICAL',
      'FINAL NOTICE: The IRS has filed a lawsuit against you for unpaid taxes. Failure to respond within 24 hours will result in arrest and asset seizure. Call immediately: 1-800-555-0199',
      ['authority', 'urgency', 'deadline', 'threat'], ['irs', 'lawsuit', 'unpaid', 'taxes', 'arrest', 'seizure']),
    createTemplate('ssa-01', 'Social Security Suspension', ThreatCategory.IRS_GOV, 'CRITICAL',
      'Social Security Administration: Your SSN has been suspended due to suspicious activity. Call 1-800-555-0342 immediately to reactivate or face legal consequences.',
      ['authority', 'urgency', 'threat', 'action'], ['social security', 'ssn', 'suspended', 'suspicious', 'reactivate']),
    createTemplate('irs-03', 'Stimulus Payment', ThreatCategory.IRS_GOV, 'HIGH',
      'U.S. Government: You are eligible for a special stimulus payment of $1,400. Submit your information to claim: http://gov-stimulus-claim.com/apply',
      ['authority', 'reward', 'action', 'link', 'personal_info_request'], ['government', 'stimulus', 'payment', 'eligible', 'claim']),
    createTemplate('dmv-01', 'DMV License Suspension', ThreatCategory.IRS_GOV, 'HIGH',
      'DMV ALERT: Your driver\'s license will be suspended due to an outstanding violation. Pay the fine immediately to avoid suspension: http://dmv-fine-pay.com',
      ['authority', 'urgency', 'threat', 'action', 'link'], ['dmv', 'license', 'suspended', 'violation', 'fine']),

    // --- TECH SUPPORT (5 templates) ---
    createTemplate('tech-ms-01', 'Microsoft Security Alert', ThreatCategory.TECH_SUPPORT, 'HIGH',
      'MICROSOFT WARNING: Your computer has been compromised. We have detected a virus that is stealing your personal data. Call Microsoft Support immediately at 1-888-555-0147 to remove the threat.',
      ['authority', 'urgency', 'threat', 'action'], ['microsoft', 'virus', 'compromised', 'support', 'call']),
    createTemplate('tech-apple-01', 'Apple ID Locked', ThreatCategory.TECH_SUPPORT, 'HIGH',
      'Your Apple ID has been locked for security reasons. Someone tried to access your account from an unknown location. Unlock your account: http://apple-id-unlock.com/verify',
      ['authority', 'urgency', 'threat', 'action', 'link'], ['apple', 'id', 'locked', 'security', 'unlock']),
    createTemplate('tech-antivirus-01', 'Antivirus Expiry', ThreatCategory.SUBSCRIPTION_TRAP, 'MEDIUM',
      'Your Norton Antivirus subscription has expired! Your computer is no longer protected. Renew immediately for $49.99 to stay protected: http://norton-renew-now.com',
      ['urgency', 'threat', 'action', 'deadline', 'link'], ['norton', 'antivirus', 'expired', 'renew', 'subscription']),
    createTemplate('tech-google-01', 'Google Account Recovery', ThreatCategory.TECH_SUPPORT, 'HIGH',
      'Google Security Alert: Unusual sign-in attempt on your Google account. If this wasn\'t you, your account may be compromised. Review activity: http://google-security-check.com',
      ['authority', 'urgency', 'action', 'threat', 'link'], ['google', 'sign-in', 'unusual', 'compromised', 'security']),
    createTemplate('tech-popup-01', 'Browser Virus Alert', ThreatCategory.TECH_SUPPORT, 'HIGH',
      'WARNING! Your computer is infected with 3 viruses. Your personal and banking information is at risk. Do NOT shut down your computer. Call toll-free: 1-877-555-0198 for immediate removal.',
      ['urgency', 'threat', 'action'], ['infected', 'viruses', 'banking', 'risk', 'call', 'removal']),

    // --- CRYPTO (5 templates) ---
    createTemplate('crypto-invest-01', 'Crypto Investment Return', ThreatCategory.CRYPTO, 'CRITICAL',
      'Exclusive opportunity: Our AI trading bot guarantees 300% returns on Bitcoin investment. Minimum deposit $500. Join 10,000+ members earning passive income daily. Start now: http://crypto-ai-profits.com',
      ['reward', 'urgency', 'action', 'link'], ['bitcoin', 'crypto', 'investment', 'returns', 'guaranteed', 'deposit']),
    createTemplate('crypto-giveaway-01', 'Crypto Giveaway', ThreatCategory.CRYPTO, 'CRITICAL',
      'Elon Musk is giving away 5,000 BTC! Send 0.1 BTC to participate and receive 1 BTC back. Limited time offer. Wallet: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh',
      ['reward', 'urgency', 'deadline', 'action'], ['bitcoin', 'btc', 'giveaway', 'send', 'receive', 'wallet']),
    createTemplate('crypto-wallet-01', 'Wallet Verification', ThreatCategory.CRYPTO, 'HIGH',
      'Your MetaMask wallet requires immediate verification due to a new security update. Enter your seed phrase to continue using your wallet: http://metamask-verify-wallet.com',
      ['authority', 'urgency', 'action', 'personal_info_request', 'link'], ['metamask', 'wallet', 'seed phrase', 'verification', 'security']),
    createTemplate('crypto-airdrop-01', 'Token Airdrop', ThreatCategory.CRYPTO, 'HIGH',
      'Congratulations! You have been selected for an exclusive token airdrop worth $2,500. Connect your wallet to claim: http://claim-airdrop-tokens.com',
      ['reward', 'action', 'link'], ['airdrop', 'token', 'wallet', 'claim', 'selected']),
    createTemplate('crypto-exchange-01', 'Exchange Account Lock', ThreatCategory.CRYPTO, 'HIGH',
      'Binance: Your account has been flagged for suspicious activity. Withdrawal has been disabled. Verify your identity to restore access: http://binance-verify-id.com',
      ['authority', 'urgency', 'threat', 'action', 'link'], ['binance', 'exchange', 'flagged', 'suspicious', 'verify', 'withdrawal']),

    // --- ROMANCE (4 templates) ---
    createTemplate('romance-01', 'Military Romance', ThreatCategory.ROMANCE, 'HIGH',
      'I am a US Army officer stationed overseas. I have fallen deeply in love with you. I need $2,000 for my leave application so we can finally meet. Please wire the money through Western Union.',
      ['personal_info_request', 'action'], ['army', 'officer', 'love', 'money', 'wire', 'western union']),
    createTemplate('romance-02', 'Investment Pitch Romance', ThreatCategory.ROMANCE, 'CRITICAL',
      'My uncle works at a top investment firm and shared a guaranteed crypto opportunity with me. I want us to invest together and build our future. Start with just $5,000 on this platform.',
      ['reward', 'action'], ['invest', 'crypto', 'guaranteed', 'platform', 'future', 'uncle']),
    createTemplate('romance-03', 'Emergency Money Request', ThreatCategory.ROMANCE, 'HIGH',
      'Baby I\'m so sorry to ask but I\'m stranded at the airport and my wallet was stolen. I need $500 for a ticket home. Can you send it via gift card? I\'ll pay you back tomorrow I promise.',
      ['urgency', 'action'], ['stranded', 'wallet', 'stolen', 'gift card', 'money', 'send']),
    createTemplate('romance-04', 'Inheritance Scam Romance', ThreatCategory.ROMANCE, 'CRITICAL',
      'I have a large inheritance from my late father but I need to pay legal fees of $10,000 to release the funds. Once released, I will share everything with you. Please help me.',
      ['reward', 'action', 'personal_info_request'], ['inheritance', 'legal fees', 'funds', 'share', 'help']),

    // --- PRIZE / LOTTERY (5 templates) ---
    createTemplate('prize-01', 'Lottery Winner', ThreatCategory.ADVANCE_FEE, 'HIGH',
      'CONGRATULATIONS! You have been selected as the winner of the International Lottery Program. You have won $1,500,000.00. To claim, pay the processing fee of $299 and send your full name, address, and bank details.',
      ['greeting', 'reward', 'action', 'personal_info_request'], ['lottery', 'winner', 'claim', 'processing fee', 'bank details']),
    createTemplate('prize-02', 'Survey Prize', ThreatCategory.ADVANCE_FEE, 'MEDIUM',
      'You\'ve been selected to participate in our customer satisfaction survey! Complete it now and receive a $100 Walmart gift card. Limited to first 50 respondents.',
      ['reward', 'urgency', 'deadline', 'action', 'link'], ['survey', 'gift card', 'selected', 'walmart', 'reward']),
    createTemplate('prize-03', 'Sweepstakes Winner', ThreatCategory.ADVANCE_FEE, 'HIGH',
      'Dear Winner, You have won $750,000 in the Publisher\'s Clearing House sweepstakes. To receive your check, pay taxes and handling of $450 via money order.',
      ['greeting', 'reward', 'action'], ['sweepstakes', 'winner', 'check', 'taxes', 'money order']),
    createTemplate('prize-04', 'Free iPhone', ThreatCategory.ADVANCE_FEE, 'MEDIUM',
      'You are our lucky visitor today! You have been selected to get a FREE iPhone 16 Pro. Click OK to claim before the offer expires!',
      ['reward', 'urgency', 'deadline', 'action'], ['free', 'iphone', 'lucky', 'selected', 'claim', 'expires']),
    createTemplate('prize-05', 'Car Winner', ThreatCategory.ADVANCE_FEE, 'HIGH',
      'You\'ve won a brand new Toyota Camry! Reference #TC-2024-8839. Contact our claims department at claims@prize-auto-winner.com with your shipping address and $199 title transfer fee.',
      ['reward', 'action', 'personal_info_request'], ['won', 'car', 'toyota', 'claims', 'fee', 'shipping']),

    // --- JOB SCAM (4 templates) ---
    createTemplate('job-01', 'Work From Home', ThreatCategory.ADVANCE_FEE, 'MEDIUM',
      'HIRING: Work from home and earn $500-$1000 per day! No experience needed. We provide full training. Just pay a one-time registration fee of $99 to get started. Limited positions available.',
      ['reward', 'urgency', 'action', 'deadline'], ['work from home', 'earn', 'no experience', 'registration fee', 'training']),
    createTemplate('job-02', 'Fake Recruiter', ThreatCategory.PHISHING, 'HIGH',
      'Hi, I\'m a recruiter from Google. We found your resume and would like to offer you a Senior Developer position at $200K/year. Please fill out this onboarding form with your SSN and bank info for direct deposit setup.',
      ['greeting', 'reward', 'action', 'personal_info_request'], ['recruiter', 'google', 'resume', 'position', 'ssn', 'bank', 'onboarding']),
    createTemplate('job-03', 'Mystery Shopper', ThreatCategory.ADVANCE_FEE, 'HIGH',
      'You have been selected as a mystery shopper! We will send you a $3,000 check. Deposit it, keep $500 as your fee, and wire the remaining $2,500 to our vendor for evaluation.',
      ['reward', 'action'], ['mystery shopper', 'check', 'deposit', 'wire', 'vendor', 'fee']),
    createTemplate('job-04', 'Data Entry Job', ThreatCategory.ADVANCE_FEE, 'MEDIUM',
      'Easy data entry job! Earn $25/hour working from home. All you need is a computer. Send $49 for the training materials and software package to begin immediately.',
      ['reward', 'action'], ['data entry', 'earn', 'home', 'training', 'software', 'send']),

    // --- RENTAL / HOUSING (3 templates) ---
    createTemplate('rental-01', 'Too Good Rental', ThreatCategory.RENTAL_HOUSING, 'HIGH',
      'Beautiful 3BR apartment in downtown, only $800/month! I\'m currently overseas for work and can\'t show the property. Send first month rent and deposit via Zelle and I\'ll mail the keys.',
      ['reward', 'action'], ['apartment', 'rent', 'overseas', 'deposit', 'zelle', 'keys']),
    createTemplate('rental-02', 'Security Deposit Rush', ThreatCategory.RENTAL_HOUSING, 'HIGH',
      'This property has 5 people interested. If you want it, I need a $1,500 security deposit TODAY to hold it for you. Wire transfer only. No need to see it first, I\'ll send videos.',
      ['urgency', 'deadline', 'action', 'threat'], ['deposit', 'wire transfer', 'today', 'interested', 'hold']),
    createTemplate('rental-03', 'Application Fee Scam', ThreatCategory.RENTAL_HOUSING, 'MEDIUM',
      'To process your rental application, we require a $200 non-refundable application fee plus your SSN, bank statements, and copies of your ID for the background check.',
      ['action', 'personal_info_request'], ['application fee', 'non-refundable', 'ssn', 'bank statements', 'background check']),

    // --- SOCIAL MEDIA (3 templates) ---
    createTemplate('social-01', 'Instagram Verification', ThreatCategory.SOCIAL_MEDIA, 'MEDIUM',
      'Instagram: Your account is eligible for verification (blue checkmark). Complete the process now before it expires: http://insta-verify-badge.com/apply',
      ['reward', 'urgency', 'action', 'deadline', 'link'], ['instagram', 'verification', 'blue checkmark', 'eligible', 'expires']),
    createTemplate('social-02', 'Copyright Violation', ThreatCategory.SOCIAL_MEDIA, 'HIGH',
      'Facebook Alert: Your account has been reported for copyright violation and will be permanently deleted within 24 hours unless you verify your identity: http://fb-copyright-appeal.com',
      ['authority', 'urgency', 'deadline', 'threat', 'action', 'link'], ['facebook', 'copyright', 'violation', 'deleted', 'verify']),
    createTemplate('social-03', 'TikTok Creator Fund', ThreatCategory.SOCIAL_MEDIA, 'MEDIUM',
      'TikTok: You qualify for the Creator Fund bonus of $5,000! Verify your account and payment method to receive your bonus: http://tiktok-creator-pay.com/claim',
      ['reward', 'action', 'link'], ['tiktok', 'creator fund', 'bonus', 'verify', 'payment']),

    // --- CHARITY (2 templates) ---
    createTemplate('charity-01', 'Disaster Relief Scam', ThreatCategory.FAKE_CHARITY, 'HIGH',
      'Please donate to help earthquake victims. Every dollar counts. Send your donation via gift cards, crypto, or wire transfer to help immediately. God bless you.',
      ['urgency', 'action', 'closing'], ['donate', 'earthquake', 'victims', 'gift cards', 'wire transfer']),
    createTemplate('charity-02', 'Veteran Charity Scam', ThreatCategory.FAKE_CHARITY, 'HIGH',
      'Support our brave veterans! The American Veterans Relief Fund needs your help. 90% of your donation goes directly to vets. Donate now: http://amer-vets-fund.com/donate',
      ['authority', 'urgency', 'action', 'link'], ['veterans', 'donate', 'fund', 'support']),

    // --- STUDENT LOAN (2 templates) ---
    createTemplate('loan-01', 'Student Loan Forgiveness', ThreatCategory.STUDENT_LOAN, 'HIGH',
      'BREAKING: New student loan forgiveness program! You may qualify to have your entire loan balance eliminated. Apply now before the program closes. Processing fee: $299.',
      ['authority', 'urgency', 'reward', 'deadline', 'action'], ['student loan', 'forgiveness', 'eliminated', 'qualify', 'processing fee']),
    createTemplate('loan-02', 'Debt Consolidation', ThreatCategory.STUDENT_LOAN, 'MEDIUM',
      'Lower your monthly student loan payments by 60%! Our government-approved consolidation program can help. Call now for a free consultation: 1-800-555-0234. Limited spots.',
      ['authority', 'reward', 'urgency', 'deadline', 'action'], ['student loan', 'consolidation', 'lower', 'government', 'payments']),

    // --- SUBSCRIPTION TRAP (3 templates) ---
    createTemplate('sub-01', 'Free Trial Auto-Charge', ThreatCategory.SUBSCRIPTION_TRAP, 'MEDIUM',
      'Your free trial has ended and you have been charged $89.99/month. To cancel, call 1-800-555-0177 within 2 hours or you will be charged again for the next billing cycle.',
      ['urgency', 'deadline', 'threat', 'action'], ['free trial', 'charged', 'cancel', 'billing', 'monthly']),
    createTemplate('sub-02', 'Streaming Account Renewal', ThreatCategory.SUBSCRIPTION_TRAP, 'MEDIUM',
      'Netflix: Your payment method has failed. Your subscription will be canceled unless you update your billing information within 48 hours: http://netflix-billing-update.com',
      ['urgency', 'deadline', 'threat', 'action', 'link'], ['netflix', 'payment', 'subscription', 'canceled', 'billing']),
    createTemplate('sub-03', 'Antivirus Auto-Renewal', ThreatCategory.SUBSCRIPTION_TRAP, 'MEDIUM',
      'Your McAfee subscription will auto-renew for $499.99 today. If you did not authorize this charge, call 1-888-555-0321 immediately to cancel and get a full refund.',
      ['urgency', 'threat', 'action'], ['mcafee', 'auto-renew', 'authorize', 'cancel', 'refund']),

    // --- TOLL ROAD SCAMS (3 templates) ---
    createTemplate('toll-sunpass-01', 'SunPass Unpaid Toll', ThreatCategory.PHISHING, 'HIGH',
      'SunPass Alert: You have an unpaid toll of $3.25. Pay now to avoid additional fees: http://sunpass-toll-pay.com/pay',
      ['urgency', 'threat', 'action', 'link'], ['sunpass', 'toll', 'unpaid', 'fees', 'pay']),
    createTemplate('toll-ezpass-01', 'E-ZPass Outstanding Balance', ThreatCategory.PHISHING, 'HIGH',
      'E-ZPass: Outstanding toll balance of $4.15. Pay within 24 hours to avoid late fees: http://ezpass-balance.com/pay',
      ['urgency', 'deadline', 'threat', 'action', 'link'], ['ezpass', 'toll', 'balance', 'late fees', 'pay']),
    createTemplate('toll-generic-01', 'State Toll Services Balance', ThreatCategory.PHISHING, 'HIGH',
      '[State] Toll Services: Your vehicle has an outstanding balance. Visit http://toll-services-pay.com to pay and avoid collections.',
      ['urgency', 'threat', 'action', 'link'], ['toll', 'vehicle', 'outstanding', 'balance', 'collections']),

    // --- WRONG NUMBER / PIG BUTCHERING OPENERS (6 templates) ---
    createTemplate('pig-wrongnum-01', 'Wrong Number Opener', ThreatCategory.ROMANCE, 'MEDIUM',
      'Hi, is this [Name]? Sorry, wrong number - but you seem nice. What do you do for work?',
      ['greeting'], ['wrong number', 'seem nice', 'work']),
    createTemplate('pig-wrongnum-02', 'Long Time No See', ThreatCategory.ROMANCE, 'MEDIUM',
      'Long time no see',
      ['greeting'], ['long time', 'see']),
    createTemplate('pig-wrongnum-03', 'Bill Dog Food', ThreatCategory.ROMANCE, 'MEDIUM',
      'Hey Bill, did you pick up the dog food on your way home?',
      ['greeting'], ['bill', 'dog food', 'home']),
    createTemplate('pig-wrongnum-04', 'Vicky Ho Introduction', ThreatCategory.ROMANCE, 'MEDIUM',
      "Hi David, I'm Vicky Ho. Don't you remember me?",
      ['greeting'], ['david', 'remember', 'wrong contact']),
    createTemplate('pig-wrongnum-05', 'Charity Event', ThreatCategory.ROMANCE, 'MEDIUM',
      'Kathy, it was a pleasure meeting you at the charity event last week.',
      ['greeting', 'closing'], ['kathy', 'charity event', 'pleasure meeting']),
    createTemplate('pig-wrongnum-06', 'Been A While', ThreatCategory.ROMANCE, 'LOW',
      "Hi, it's been a while, how are you doing? Let's get together this weekend.",
      ['greeting'], ['been a while', 'get together', 'weekend']),

    // --- BOSS / BEC IMPERSONATION (2 templates) ---
    createTemplate('bec-giftcard-01', 'Boss Gift Card Request', ThreatCategory.ADVANCE_FEE, 'CRITICAL',
      "Hi, it's [Boss's Name], and I need you to purchase $500 in gift cards as soon as possible for a client and send me the codes.",
      ['urgency', 'action'], ['boss', 'gift cards', 'purchase', 'codes', 'client']),
    createTemplate('bec-wire-01', 'Urgent Wire Transfer BEC', ThreatCategory.ADVANCE_FEE, 'CRITICAL',
      'This is urgent and confidential. I need you to process a wire transfer of $[amount] immediately. Don\'t discuss this with anyone.',
      ['urgency', 'action'], ['urgent', 'confidential', 'wire transfer', 'immediately', 'discuss']),

    // --- TECH SUPPORT POPUPS (6 templates) ---
    createTemplate('tech-popup-02', 'PC Blocked Security', ThreatCategory.TECH_SUPPORT, 'HIGH',
      'Access To This PC Has Been Blocked For Security Reasons',
      ['authority', 'threat'], ['pc', 'blocked', 'security']),
    createTemplate('tech-popup-03', 'Windows Defender Threat', ThreatCategory.TECH_SUPPORT, 'HIGH',
      'Windows Defender - Threat Detected',
      ['authority', 'urgency', 'threat'], ['windows defender', 'threat', 'detected']),
    createTemplate('tech-popup-04', 'Firewall Credentials Compromised', ThreatCategory.TECH_SUPPORT, 'HIGH',
      'Firewall Notification - Credentials Compromised',
      ['authority', 'threat'], ['firewall', 'credentials', 'compromised']),
    createTemplate('tech-popup-05', 'Call Support Computer Disabled', ThreatCategory.TECH_SUPPORT, 'HIGH',
      'Call Support Immediately - Computer Disabled',
      ['urgency', 'action', 'threat'], ['call support', 'computer', 'disabled']),
    createTemplate('tech-popup-06', 'Unusual Activity System', ThreatCategory.TECH_SUPPORT, 'HIGH',
      'Your System Detected Some Unusual Activity. It might harm your computer data and track your financial activities.',
      ['urgency', 'threat'], ['unusual activity', 'computer data', 'financial activities', 'system']),
    createTemplate('tech-popup-07', 'Computer Locked Error Code', ThreatCategory.TECH_SUPPORT, 'HIGH',
      'your computer has been locked! Error Code: #DY2309X03. Call Microsoft Support: 1-844-XXX-XXXX',
      ['urgency', 'threat', 'action'], ['computer', 'locked', 'error code', 'microsoft support', 'call']),

    // --- MICROSOFT 365 PHISHING (1 template) ---
    createTemplate('ms365-pw-01', 'Microsoft 365 Password Expiry', ThreatCategory.PHISHING, 'HIGH',
      'Urgent: Your password expires in 24 hours. To avoid losing access to your email and files, please update your password immediately.',
      ['urgency', 'deadline', 'threat', 'action'], ['password', 'expires', '24 hours', 'email', 'files', 'update']),

    // --- REFUND / OVERPAYMENT SCAMS (2 templates) ---
    createTemplate('refund-01', 'Click Here Refund', ThreatCategory.ADVANCE_FEE, 'HIGH',
      "You've overpaid $50 for a recent transaction. Click here to process your refund: http://refund-portal.com/claim",
      ['reward', 'action', 'link'], ['overpaid', 'refund', 'transaction', 'process']),
    createTemplate('refund-02', 'Bank Details Refund', ThreatCategory.ADVANCE_FEE, 'CRITICAL',
      'Our records show you overpaid for (a product or service). Kindly supply your bank routing and account number',
      ['authority', 'action', 'personal_info_request'], ['overpaid', 'bank routing', 'account number', 'records']),

    // --- UTILITY THREATS (1 template) ---
    createTemplate('utility-01', 'Electricity Disconnection', ThreatCategory.PHISHING, 'HIGH',
      'Your electricity service will be disconnected due to non-payment. Pay now to avoid service interruption: http://utility-pay-now.com',
      ['urgency', 'deadline', 'threat', 'action', 'link'], ['electricity', 'disconnected', 'non-payment', 'service interruption', 'pay']),

    // --- FAMILY EMERGENCY SCAMS (2 templates) ---
    createTemplate('family-01', 'Grandchild Accident', ThreatCategory.ADVANCE_FEE, 'HIGH',
      "Hi Grandma, it's your grandson. I got into a car accident and need money for the hospital, please send $500 to this CashApp",
      ['urgency', 'action'], ['grandma', 'grandson', 'car accident', 'hospital', 'cashapp', 'send']),
    createTemplate('family-02', 'Mom Lost Phone', ThreatCategory.ADVANCE_FEE, 'HIGH',
      "Mom, I lost my phone and I'm in trouble. I need you to send money urgently to [payment method].",
      ['urgency', 'action'], ['mom', 'lost phone', 'trouble', 'send money', 'urgently']),

    // --- DIGITAL ARREST SCAMS (2 templates) ---
    createTemplate('arrest-01', 'FBI Phone Linked Illegal', ThreatCategory.IRS_GOV, 'CRITICAL',
      'This is the Federal Bureau of Investigation. Your phone number has been linked to illegal activities. You must cooperate with our investigation immediately or face arrest.',
      ['authority', 'urgency', 'threat', 'action'], ['fbi', 'phone number', 'illegal', 'investigation', 'arrest', 'cooperate']),
    createTemplate('arrest-02', 'Money Laundering Deposit', ThreatCategory.IRS_GOV, 'CRITICAL',
      'You are being investigated for money laundering. To avoid arrest, you must deposit funds into a secure government account.',
      ['authority', 'urgency', 'threat', 'action'], ['money laundering', 'arrest', 'deposit', 'government account', 'investigated']),

    // --- RECOVERY SCAMS (1 template) ---
    createTemplate('recovery-01', 'Fund Recovery Service', ThreatCategory.ADVANCE_FEE, 'HIGH',
      'We can help you recover funds lost to scammers. Our team has a 95% success rate. Pay a small upfront fee to begin your case.',
      ['reward', 'action'], ['recover funds', 'scammers', 'success rate', 'upfront fee', 'case']),

    // --- v2: MARKETPLACE FRAUD (4 templates) ---
    createTemplate('mkt-advance-01', 'Marketplace Advance Payment', ThreatCategory.MARKETPLACE_FRAUD, 'HIGH',
      'Hi, I saw your listing on Facebook Marketplace. I am very interested! I can pay via Zelle right now, just send me your Zelle info and I will send the money immediately before pickup.',
      ['action', 'urgency'], ['marketplace', 'interested', 'zelle', 'pay', 'send money', 'before pickup']),
    createTemplate('mkt-overpay-01', 'Overpayment Check Scam', ThreatCategory.MARKETPLACE_FRAUD, 'CRITICAL',
      'I am sending you a check for $2,500 but it is a little over the asking price. Please cash it and send back the difference of $800 via Zelle or Western Union. The item will be picked up next week.',
      ['action', 'reward'], ['check', 'over asking price', 'send back', 'difference', 'western union', 'zelle']),
    createTemplate('mkt-ticket-01', 'Fake Ticket Sale', ThreatCategory.TICKET_SCAM, 'HIGH',
      'Selling 2 concert tickets for this Saturday. Can\'t make it anymore. Selling below face value, $80 each. Payment via Venmo or CashApp only, will send PDF tickets once paid. Act fast!',
      ['urgency', 'action'], ['tickets', 'concert', 'below face value', 'venmo', 'cashapp', 'pdf tickets', 'once paid']),
    createTemplate('mkt-car-01', 'Vehicle Deposit Scam', ThreatCategory.MARKETPLACE_FRAUD, 'HIGH',
      'I have a 2019 Honda Accord for sale at $8,500 — way below book value because I\'m deployed overseas. Send a $500 deposit via Zelle to hold it and I\'ll ship the car and title to you.',
      ['authority', 'reward', 'action'], ['deployed', 'overseas', 'deposit', 'zelle', 'ship the car', 'title']),

    // --- v2: ELDER / GRANDPARENT SCAMS (3 templates) ---
    createTemplate('elder-gp-01', 'Grandparent Emergency Bail', ThreatCategory.ELDER_SCAM, 'CRITICAL',
      'Grandma, it\'s me, your grandson. I\'ve been in an accident and I\'m in jail. Please don\'t tell Mom and Dad. My lawyer says if you can send $3,000 for bail through a courier I\'ll be out tonight.',
      ['urgency', 'threat', 'action'], ['grandma', 'accident', 'jail', 'don\'t tell', 'bail', 'courier', 'lawyer']),
    createTemplate('elder-lawyer-01', 'Fake Lawyer Bail Call', ThreatCategory.ELDER_SCAM, 'CRITICAL',
      'Good afternoon, I am Attorney James Walsh. I represent your granddaughter who was involved in a car accident. She asked me to call you directly and keep this confidential. The bail is $4,500.',
      ['authority', 'urgency', 'action'], ['attorney', 'granddaughter', 'accident', 'confidential', 'bail', 'represent']),
    createTemplate('elder-medicare-01', 'Medicare Card Replacement', ThreatCategory.ELDER_SCAM, 'HIGH',
      'This is Medicare calling about your new card. Due to recent system upgrades, we need to verify your Social Security number and bank account to send you a replacement card.',
      ['authority', 'action', 'personal_info_request'], ['medicare', 'new card', 'social security', 'bank account', 'verify', 'replacement']),

    // --- v2: INVESTMENT FRAUD (4 templates) ---
    createTemplate('inv-crypto-01', 'Crypto Investment Platform', ThreatCategory.INVESTMENT_FRAUD, 'CRITICAL',
      'Join our exclusive AI-powered trading platform and earn 15% daily returns on your Bitcoin investment. Our algorithm has a 98% win rate. Minimum deposit $500. Withdraw anytime.',
      ['reward', 'authority', 'action'], ['trading platform', 'daily returns', 'bitcoin', 'algorithm', 'win rate', 'deposit', 'withdraw']),
    createTemplate('inv-forex-01', 'Forex Trading Guarantee', ThreatCategory.INVESTMENT_FRAUD, 'CRITICAL',
      'Our professional forex traders have been generating consistent profits for over 5 years. We guarantee a minimum 20% monthly return. Start with as little as $1,000. Capital protected.',
      ['reward', 'authority'], ['forex', 'traders', 'consistent profits', 'guarantee', 'monthly return', 'capital protected']),
    createTemplate('inv-ponzi-01', 'Pyramid Recruitment Scheme', ThreatCategory.INVESTMENT_FRAUD, 'CRITICAL',
      'Join our team and earn $200-$500 per day just by referring others! The more people you bring in, the higher your earnings. This is not MLM, it\'s a proven investment system.',
      ['reward', 'action'], ['referring others', 'bring in', 'earnings', 'not mlm', 'proven', 'per day']),
    createTemplate('inv-stock-01', 'Pump and Dump Stock Tip', ThreatCategory.INVESTMENT_FRAUD, 'HIGH',
      'CONFIDENTIAL: Our analysts predict ticker XYZC will explode 400% in the next 10 days based on inside knowledge. Buy now before the public announcement. Limited shares available.',
      ['urgency', 'authority', 'reward'], ['confidential', 'ticker', 'explode', 'inside', 'buy now', 'limited shares']),

    // --- v2: BANK OTP BYPASS (3 templates) ---
    createTemplate('otp-banker-01', 'Fake Bank Security Call', ThreatCategory.BANK_OTP, 'CRITICAL',
      'Hello, this is the fraud prevention team at Chase Bank. We\'ve detected an unauthorized transfer on your account and need to verify your identity. Please provide the 6-digit code we just sent to your phone.',
      ['authority', 'urgency', 'action', 'personal_info_request'], ['fraud prevention', 'chase', 'unauthorized', 'verify identity', '6-digit code', 'sent to your phone']),
    createTemplate('otp-safe-account-01', 'Safe Account Transfer', ThreatCategory.BANK_OTP, 'CRITICAL',
      'Your bank account has been compromised. To protect your funds, we need you to transfer your balance to a temporary secure account we have set up. Ignore any warnings from your bank.',
      ['authority', 'urgency', 'threat', 'action'], ['compromised', 'protect your funds', 'temporary', 'secure account', 'ignore warnings']),
    createTemplate('otp-sim-01', 'SIM Swap Attack', ThreatCategory.BANK_OTP, 'CRITICAL',
      'AT&T: To complete your SIM transfer request, please confirm your account PIN and the verification code sent to your current device. This will not interrupt your service.',
      ['authority', 'action', 'personal_info_request'], ['sim transfer', 'account pin', 'verification code', 'current device']),

    // --- v2: EMPLOYMENT SCAMS (3 templates) ---
    createTemplate('emp-reship-01', 'Reshipping Mule Offer', ThreatCategory.EMPLOYMENT_SCAM, 'CRITICAL',
      'Work from home opportunity! Receive packages at your address, inspect them, and reship to our overseas warehouse. Earn $2,000/week. No experience needed. Start immediately.',
      ['reward', 'action', 'urgency'], ['work from home', 'receive packages', 'reship', 'overseas', 'earn', 'no experience']),
    createTemplate('emp-payroll-01', 'Fake Payroll Check Scam', ThreatCategory.EMPLOYMENT_SCAM, 'CRITICAL',
      'Congratulations on your new remote position! Your first paycheck of $4,800 has been deposited. Due to an accounting error, you received $1,200 extra. Please return this amount via Zelle immediately.',
      ['reward', 'urgency', 'action'], ['paycheck', 'deposited', 'accounting error', 'return', 'zelle', 'immediately']),
    createTemplate('emp-job-harvest-01', 'Job Offer Identity Harvest', ThreatCategory.EMPLOYMENT_SCAM, 'HIGH',
      'Congratulations! You have been selected for a remote customer service position. Before we can proceed, please provide your Social Security number, bank account for direct deposit, and a copy of your ID.',
      ['authority', 'reward', 'personal_info_request'], ['selected', 'remote', 'social security', 'bank account', 'direct deposit', 'copy of id']),
  ];

  return _templateDb;
}

// ---------------------------------------------------------------------------
// Index building (lazy init)
// ---------------------------------------------------------------------------

function ensureIndex(): {
  idf: Map<string, number>;
  vectors: Map<string, TfIdfVector>;
  trigrams: Map<string, Set<string>>;
} {
  if (_idf && _templateVectors && _templateTrigrams) {
    return { idf: _idf, vectors: _templateVectors, trigrams: _templateTrigrams };
  }

  const db = getTemplateDatabase();
  _idf = buildIDF(db.map((t) => t.text));
  _templateVectors = new Map();
  _templateTrigrams = new Map();

  for (const tmpl of db) {
    _templateVectors.set(tmpl.id, buildTfIdfVector(tmpl.text, _idf));
    _templateTrigrams.set(tmpl.id, extractTrigrams(tmpl.text));
  }

  return { idf: _idf, vectors: _templateVectors, trigrams: _templateTrigrams };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Computes all three similarity scores between input text and a single template.
 */
export function computeSimilarity(text: string, template: ScamTemplate): TemplateMatch {
  const { idf, vectors, trigrams } = ensureIndex();

  const inputTrigrams = extractTrigrams(text);
  const templateTri = trigrams.get(template.id) ?? extractTrigrams(template.text);
  const trigramScore = jaccardSimilarity(inputTrigrams, templateTri);

  const inputVec = buildTfIdfVector(text, idf);
  const templateVec = vectors.get(template.id) ?? buildTfIdfVector(template.text, idf);
  const tfidfScore = cosineSimilarity(inputVec, templateVec);

  const inputTags = detectStructure(text);
  const structuralScore = structuralSimilarity(inputTags, template.structure);

  const compositeScore =
    TRIGRAM_WEIGHT * trigramScore +
    TFIDF_WEIGHT * tfidfScore +
    STRUCTURAL_WEIGHT * structuralScore;

  return { template, trigramScore, tfidfScore, structuralScore, compositeScore };
}

/**
 * Finds the top-N closest scam templates for the given text.
 */
export function findClosestTemplates(text: string): SimilarityResult {
  const startTime = performance.now();
  const db = getTemplateDatabase();

  const matches: TemplateMatch[] = db.map((tmpl) => computeSimilarity(text, tmpl));
  matches.sort((a, b) => b.compositeScore - a.compositeScore);

  const topMatches = matches.slice(0, TOP_N);
  const best = topMatches[0];

  // Determine highest risk level from top matches
  const riskOrder: ThreatLevel[] = ['SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  let highestRiskLevel: ThreatLevel = 'SAFE';
  for (const m of topMatches) {
    if (riskOrder.indexOf(m.template.riskLevel) > riskOrder.indexOf(highestRiskLevel)) {
      highestRiskLevel = m.template.riskLevel;
    }
  }

  return {
    topMatches,
    highestCategory: best?.template.category ?? ThreatCategory.GENERIC,
    highestRiskLevel,
    bestScore: best?.compositeScore ?? 0,
    processingTimeMs: performance.now() - startTime,
  };
}
