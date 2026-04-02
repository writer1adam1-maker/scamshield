/**
 * Website Vaccine System Types
 * Core interfaces for the threat detection and injection system
 */

export enum VaccineThreatType {
  // Phishing threats
  PHISHING_FORM = "phishing_form",
  CREDENTIAL_HARVESTER = "credential_harvester",
  PAYMENT_FORM_FAKE = "payment_form_fake",

  // Malware threats
  MALWARE_SIGNATURE = "malware_signature",
  EXPLOIT_KIT = "exploit_kit",
  CRYPTOMINER = "cryptominer",
  KEYLOGGER = "keylogger",
  RANSOMWARE = "ransomware",

  // Script-based threats
  OBFUSCATED_CODE = "obfuscated_code",
  IFRAME_INJECTION = "iframe_injection",
  REDIRECT_CHAIN = "redirect_chain",
  XSS_PAYLOAD = "xss_payload",

  // Scam patterns
  URGENCY_LANGUAGE = "urgency_language",
  FAKE_TRUST_BADGE = "fake_trust_badge",
  SPOOFED_BRANDING = "spoofed_branding",
  FAKE_REVIEWS = "fake_reviews",

  // Social engineering
  FAKE_SUPPORT_CHAT = "fake_support_chat",
  FAKE_URGENCY = "fake_urgency",
  CLIPBOARD_HIJACK = "clipboard_hijack",
  POPUP_SPAM = "popup_spam",
}

export interface ScrapedWebsiteAnalysis {
  url: string;
  timestamp: number;
  httpStatusCode: number;
  title: string;
  domain: string;
  html: string; // Full HTML content (truncated for safety)
  scripts: ScrapedScript[];
  forms: ScrapedForm[];
  links: ScrapedLink[];
  mediaElements: ScrapedMedia[];
  metaTags: Record<string, string>;
  textContent: string; // Extracted text for linguistic analysis
  isDomainMatch: boolean; // Does domain match claimed business?
}

export interface ScrapedScript {
  src?: string;
  inline: boolean;
  content: string;
  isObfuscated: boolean;
  suspicionScore: number;
}

export interface ScrapedForm {
  id?: string;
  action?: string;
  method: string;
  fields: FormField[];
  targetDomain?: string;
}

export interface FormField {
  name: string;
  type: string;
  fieldSuspicionScore: number;
}

export interface ScrapedLink {
  url: string;
  text: string;
  isExternal: boolean;
  targetDomain?: string;
  redirectCount?: number;
}

export interface ScrapedMedia {
  type: "image" | "video" | "audio";
  src: string;
  alt?: string;
}

export interface VaccineThreat {
  type: VaccineThreatType;
  severity: "low" | "medium" | "high" | "critical";
  description: string;
  targetElement?: string;
  location?: string;
  evidence: string;
  injectionRule: InjectionRule;
}

export interface InjectionRule {
  id: string;
  type: "block" | "warn" | "sandbox" | "disable" | "monitor";
  selector?: string;
  attribute?: string;
  targetUrl?: string;
  scriptContent?: string;
  message?: string;
  expiresAt: number; // Unix timestamp, 24h from creation
}

export interface SynergosAnalysisResult {
  verdict: 'BLOCK' | 'WARN' | 'ALLOW';
  confidence: number;        // 0-1: confidence in verdict
  nextAttackPrediction: {
    tactics: string[];       // Predicted attack tactics
    likelihood: number;      // 0-1: confidence in prediction
  };
  recommendedDefense: string[]; // Suggested countermeasures
}

export interface VaccineReport {
  url: string;
  timestamp: number;
  threatLevel: "safe" | "low" | "medium" | "high" | "critical";
  threatScore: number; // 0-100
  threatsDetected: VaccineThreat[] | string[]; // String[] for simple description list
  injectionRules: InjectionRule[];
  scrapedAnalysis?: ScrapedWebsiteAnalysis;
  vericticScore?: number; // Integration with VERIDICT engine
  recommendations?: string[];
  synergosAnalysis?: SynergosAnalysisResult; // SYNERGOS deep analysis results
  latencyMs?: number;        // Time taken for analysis
}

export interface InjectionPayload {
  ruleId: string;
  type: "block" | "warn" | "sandbox" | "disable" | "monitor";
  selector?: string;
  targetUrl?: string;
  message?: string;
  scriptContent?: string;
}

export interface VaccineStore {
  url: string;
  report: VaccineReport;
  injectionRules: InjectionRule[];
  expiresAt: number;
  createdAt: number;
  status: "active" | "expired" | "cleaned";
}

export interface WebsiteScraperOptions {
  timeout?: number;
  maxContentLength?: number;
  includeScreenshot?: boolean;
  headless?: boolean;
}

export interface MalwareSignature {
  name: string;
  pattern: RegExp;
  severity: "low" | "medium" | "high" | "critical";
  category: "exploit" | "cryptominer" | "keylogger" | "ransomware";
}

export interface PhishingPattern {
  name: string;
  fields: string[];
  actions?: string[];
  suspicion: number;
}
