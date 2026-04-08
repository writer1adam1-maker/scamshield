// ============================================================================
// VERIDICT Scoring Algorithm - Core Types
// ============================================================================

export enum SignalType {
  URL = 'URL',
  EMAIL = 'EMAIL',
  SMS = 'SMS',
  SCREENSHOT = 'SCREENSHOT',
  DOMAIN = 'DOMAIN',
  SSL = 'SSL',
  WHOIS = 'WHOIS',
  TEXT = 'TEXT',
}

export enum ThreatCategory {
  PHISHING = 'PHISHING',
  ADVANCE_FEE = 'ADVANCE_FEE',
  TECH_SUPPORT = 'TECH_SUPPORT',
  ROMANCE = 'ROMANCE',
  CRYPTO = 'CRYPTO',
  IRS_GOV = 'IRS_GOV',
  PACKAGE_DELIVERY = 'PACKAGE_DELIVERY',
  SOCIAL_MEDIA = 'SOCIAL_MEDIA',
  SUBSCRIPTION_TRAP = 'SUBSCRIPTION_TRAP',
  FAKE_CHARITY = 'FAKE_CHARITY',
  RENTAL_HOUSING = 'RENTAL_HOUSING',
  STUDENT_LOAN = 'STUDENT_LOAN',
  GENERIC = 'GENERIC',
  // v2 — expanded dataset
  MARKETPLACE_FRAUD = 'MARKETPLACE_FRAUD',   // FB Marketplace, Craigslist, eBay fraud
  ELDER_SCAM = 'ELDER_SCAM',                 // Grandparent / senior-targeted scams
  TICKET_SCAM = 'TICKET_SCAM',               // Fake event / concert / sports tickets
  INVESTMENT_FRAUD = 'INVESTMENT_FRAUD',     // Ponzi, securities fraud, Forex
  EMPLOYMENT_SCAM = 'EMPLOYMENT_SCAM',       // Fake job offers, reshipping mules
  BANK_OTP = 'BANK_OTP',                     // OTP/2FA bypass, imposter banker calls
}

export type ThreatLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface Signal {
  type: SignalType;
  value: string;
  confidence: number; // 0-1
  rawData: Record<string, unknown>;
  label: string;
  cost: number; // computational cost 0-10
}

export interface ConservationViolation {
  lawIndex: number;
  lawName: string;
  description: string;
  severity: number; // 0-1
  evidence: string;
}

export interface CascadeBreakdown {
  triggerCategory: string;
  triggersFound: string[];
  preTrustScore: number;
  postRemovalTrustScore: number;
  fragility: number; // ratio, higher = more suspicious
  secondOrderTriggers: string[];
}

export interface FisherLayerResult {
  score: number; // 0-100
  signalsEvaluated: Signal[];
  accumulatedFisherInfo: number;
  earlyStopTriggered: boolean;
  details: string[];
}

export interface ConservationLayerResult {
  score: number; // 0-100
  violationTensor: number[][]; // 6x6 matrix (expanded from 5x5)
  frobeniusNorm: number;
  violations: ConservationViolation[];
  details: string[];
}

export interface CascadeBreakerResult {
  score: number; // 0-100
  breakdowns: CascadeBreakdown[];
  overallFragility: number;
  details: string[];
}

export interface ImmuneRepertoireResult {
  score: number; // 0-100
  matchedAntibodies: AntibodyMatch[];
  activationGated: boolean;
  details: string[];
}

export interface AntibodyMatch {
  antibodyId: string;
  name: string;
  pattern: string;
  affinity: number;
  matchedText: string;
  category: ThreatCategory;
}

export interface Antibody {
  id: string;
  name: string;
  pattern: RegExp;
  affinity: number; // 0-1, how strongly this indicates a scam
  generation: number;
  falsePositiveRate: number;
  category: ThreatCategory;
  description: string;
}

export interface EvidenceItem {
  layer: string;
  finding: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  detail: string;
}

export interface ConfidenceInterval {
  lower: number;
  upper: number;
  confidence: number; // e.g. 0.95 for 95% CI
}

export interface LayerScores {
  fisher: number;
  conservation: number;
  cascadeBreaker: number;
  immune: number;
}

export interface VERIDICTResult {
  score: number; // 0-100, composite scam likelihood
  threatLevel: ThreatLevel;
  category: ThreatCategory;
  evidence: EvidenceItem[];
  layerScores: LayerScores;
  confidenceInterval: ConfidenceInterval;
  processingTimeMs: number;
  threatSeverity: ThreatSeverityInfo;
  metaAnalysis: MetaAnalysisResult;
  similarKnownScam: string | null;
  layerDetails: {
    fisher: FisherLayerResult;
    conservation: ConservationLayerResult;
    cascadeBreaker: CascadeBreakerResult;
    immune: ImmuneRepertoireResult;
  };
  // Extended analysis (populated when applicable)
  urlDeepAnalysis?: DeepUrlResult;
  similarityAnalysis?: SimilarityResult;
  financialRisk?: FinancialRiskResult;
  multilingualDetection?: MultilingualDetectionResult;
  phoneAnalysis?: PhoneAnalysisResult;
  linguisticDeception?: LinguisticDeceptionResult;
  conversationArc?: import('./conversation-arc').ConversationArcResult;
}

export interface AnalysisInput {
  url?: string;
  text?: string;
  emailHeaders?: Record<string, string>;
  emailBody?: string;
  smsBody?: string;
  screenshotOcrText?: string;
  whoisData?: WhoisData;
  sslData?: SslData;
  /** Email sender domain scanning mode — weights URL analysis heavily since only metadata is available */
  emailMode?: boolean;
}

export interface WhoisData {
  domainName: string;
  registrar: string;
  creationDate: string;
  expirationDate: string;
  registrantCountry: string;
  privacyProtected: boolean;
  nameServers: string[];
}

export interface SslData {
  issuer: string;
  validFrom: string;
  validTo: string;
  selfSigned: boolean;
  expired: boolean;
  subjectAltNames: string[];
}

export interface UrlAnalysis {
  protocol: string;
  hostname: string;
  path: string;
  query: string;
  tld: string;
  subdomains: string[];
  hasIpAddress: boolean;
  entropy: number;
  length: number;
  hasEncodedChars: boolean;
  isShortener: boolean;
  hasSuspiciousTld: boolean;
  hasHomoglyphs: boolean;
  excessiveSubdomains: boolean;
}

// ---------------------------------------------------------------------------
// New types for VERIDICT upgrades
// ---------------------------------------------------------------------------

export enum ThreatSeverity {
  INFORMATIONAL = 'INFORMATIONAL',
  LOW_FINANCIAL = 'LOW_FINANCIAL',
  MODERATE_FINANCIAL = 'MODERATE_FINANCIAL',
  HIGH_FINANCIAL = 'HIGH_FINANCIAL',
  CATASTROPHIC_FINANCIAL = 'CATASTROPHIC_FINANCIAL',
}

export interface ThreatSeverityInfo {
  severity: ThreatSeverity;
  estimatedMaxLoss: string;
  description: string;
}

export interface MetaAnalysisResult {
  crossLayerAgreement: number;
  conflictingLayers: string[];
  dominantSignalType: string;
  anomalyPatterns: string[];
  overallConfidenceBoost: number;
}

export interface KnownScamTemplate {
  id: string;
  name: string;
  category: ThreatCategory;
  keywords: string[];
  structure: string;
  similarityThreshold: number;
}

export interface AntibodyCluster {
  clusterId: string;
  name: string;
  antibodyIds: string[];
  clusterActivation: number;
  dominantCategory: ThreatCategory;
}

export interface EmotionalExploitationResult {
  score: number;
  dominantEmotion: string;
  emotionBreakdown: Record<string, number>;
  manipulationIntensity: number;
}

export interface PhoneAnalysis {
  number: string;
  isTollFree: boolean;
  isPremiumRate: boolean;
  isInternational: boolean;
  suspicionLevel: number;
  reason: string;
}

export interface CryptoWalletDetection {
  type: 'BTC' | 'ETH' | 'XMR' | 'LTC' | 'BCH' | 'USDT_TRC20' | 'SOL';
  address: string;
  confidence: number;
}

export interface EmailHeaderAnomaly {
  anomalyType: string;
  description: string;
  severity: number;
  evidence: string;
}

// ============================================================================
// Threat Intelligence Types
// ============================================================================

export interface TrendDataPoint {
  timestamp: number;
  category: ThreatCategory;
  pattern: string;
  signals: string[];
}

export interface TrendVelocity {
  pattern: string;
  category: ThreatCategory;
  velocity: number;
  acceleration: number;
  ema: number;
  isOutbreak: boolean;
  zScore: number;
}

export interface ThreatPrediction {
  category: ThreatCategory;
  pattern: string;
  confidence: number;
  predictedPeakTime: number;
  currentVelocity: number;
  riskLevel: ThreatLevel;
}

export interface ThreatIntelligenceResult {
  trendingCategories: {
    category: ThreatCategory;
    velocity: number;
    count: number;
  }[];
  emergingPatterns: TrendVelocity[];
  outbreaks: TrendVelocity[];
  predictions: ThreatPrediction[];
  analysisWindowMs: number;
  dataPointCount: number;
  generatedAt: number;
}

// ============================================================================
// Similarity Engine Types
// ============================================================================

export interface ScamTemplate {
  id: string;
  name: string;
  category: ThreatCategory;
  riskLevel: ThreatLevel;
  text: string;
  structure: TemplateStructureTag[];
  keywords: string[];
}

export type TemplateStructureTag =
  | 'greeting'
  | 'urgency'
  | 'authority'
  | 'action'
  | 'deadline'
  | 'threat'
  | 'reward'
  | 'link'
  | 'personal_info_request'
  | 'closing';

export interface TemplateMatch {
  template: ScamTemplate;
  trigramScore: number;
  tfidfScore: number;
  structuralScore: number;
  compositeScore: number;
}

export interface SimilarityResult {
  topMatches: TemplateMatch[];
  highestCategory: ThreatCategory;
  highestRiskLevel: ThreatLevel;
  bestScore: number;
  processingTimeMs: number;
}

// ============================================================================
// Financial Risk Assessment Types
// ============================================================================

export type FinancialRiskType =
  | 'credential_theft'
  | 'direct_payment'
  | 'identity_theft'
  | 'subscription_trap'
  | 'investment_fraud'
  | 'advance_fee'
  | 'unknown';

export interface LossRange {
  min: number;
  max: number;
  median: number;
}

export interface FinancialRiskResult {
  riskScore: number;
  riskType: FinancialRiskType;
  estimatedLoss: LossRange;
  urgencyScore: number;
  targetingScore: number;
  sophisticationScore: number;
  recommendedActions: string[];
  breakdown: {
    categoryRisk: number;
    sophisticationRisk: number;
    urgencyRisk: number;
    targetingRisk: number;
  };
}

// ============================================================================
// Community Trust Scoring Types
// ============================================================================

export interface CommunityReport {
  reportId: string;
  reporterId: string;
  targetIdentifier: string;
  isScam: boolean;
  category: ThreatCategory;
  timestamp: number;
  reporterAccountAge: number;
  reporterTotalReports: number;
  reporterAccuracy: number;
}

export interface ReporterReliability {
  reporterId: string;
  reliabilityScore: number;
  totalReports: number;
  accurateReports: number;
  averageAgreement: number;
  accountAgeDays: number;
  isSuspicious: boolean;
}

export interface CommunityTrustResult {
  trustScore: number;
  confidenceLevel: number;
  wilsonLower: number;
  wilsonUpper: number;
  totalReports: number;
  weightedReports: number;
  gamingDetected: boolean;
  gamingDetails: string[];
  reportQuality: 'low' | 'medium' | 'high';
  topReporterReliability: number;
}

// ============================================================================
// Deep URL Analysis Types
// ============================================================================

export interface DeepUrlBreakdown {
  entropyScore: number;
  pathDepthScore: number;
  parameterScore: number;
  redirectScore: number;
  dgaScore: number;
  homographScore: number;
  brandDistanceScore: number;
  subdomainScore: number;
  phishingKitScore?: number;
}

export interface DeepUrlResult {
  overallRiskScore: number;
  threatLevel: ThreatLevel;
  breakdown: DeepUrlBreakdown;
  detectedBrands: { brand: string; distance: number }[];
  suspiciousParams: string[];
  homoglyphsDetected: { original: string; lookalike: string }[];
  flags: string[];
  processingTimeMs: number;
}

// ============================================================================
// Multilingual Detection Types
// ============================================================================

export interface MultilingualMatch {
  language: string;      // 'es' | 'fr' | 'pt' | 'ar' | 'zh' | 'de'
  languageName: string;
  patternId: string;
  patternName: string;
  matchedText: string;
  confidence: number;
  category: ThreatCategory;
}

export interface MultilingualDetectionResult {
  detected: boolean;
  dominantLanguage: string | null;
  matches: MultilingualMatch[];
  riskScore: number;       // 0-1
  flags: string[];
  processingTimeMs: number;
}

// ============================================================================
// Phone Analysis Types
// ============================================================================

export interface PhoneMatch {
  number: string;
  normalizedNumber: string;
  country: string;
  isPremiumRate: boolean;
  isTollFree: boolean;
  isVoIP: boolean;
  isSuspiciousAreaCode: boolean;
  scamAssociationScore: number;  // 0-1
  flags: string[];
}

export interface PhoneAnalysisResult {
  detected: boolean;
  phones: PhoneMatch[];
  highestRisk: number;     // 0-1
  flags: string[];
  processingTimeMs: number;
}

// ============================================================================
// Linguistic Deception Detection Types (VERIDICT Layer 5)
// ============================================================================

export interface DeceptionTactic {
  tacticId: string;
  tacticName: string;
  category: 'authority' | 'urgency' | 'fear' | 'greed' | 'isolation' | 'reciprocity' | 'social_proof';
  evidence: string;
  severity: number;   // 0-1
}

export interface LinguisticDeceptionResult {
  score: number;               // 0-100
  deceptionTactics: DeceptionTactic[];
  manipulationScore: number;   // 0-1
  authorityFakingScore: number;
  emotionalExploitScore: number;
  isolationAttemptScore: number;
  reciprocityScore: number;
  flags: string[];
  details: string[];
  processingTimeMs: number;
}
