/**
 * Threat Detection Engine
 * Analyzes scraped content for phishing, malware, and scam patterns
 */

import {
  ScrapedWebsiteAnalysis,
  VaccineThreat,
  VaccineThreatType,
  MalwareSignature,
  PhishingPattern,
} from "./types";

export class ThreatDetector {
  private malwareSignatures: MalwareSignature[] = this.initMalwareSignatures();
  private phishingPatterns: PhishingPattern[] = this.initPhishingPatterns();

  /**
   * Analyze scraped website and detect threats
   */
  detectThreats(analysis: ScrapedWebsiteAnalysis): VaccineThreat[] {
    const threats: VaccineThreat[] = [];

    // Run all detection modules
    threats.push(...this.detectPhishingForms(analysis));
    threats.push(...this.detectMalwareSignatures(analysis));
    threats.push(...this.detectSuspiciousScripts(analysis));
    threats.push(...this.detectScamPatterns(analysis));
    threats.push(...this.detectSocialEngineering(analysis));
    threats.push(...this.detectDomainSpoofing(analysis));
    threats.push(...this.detectHighEntropyScripts(analysis));
    threats.push(...this.detectHomoglyphDomain(analysis));

    return threats;
  }

  /**
   * Phishing Form Detection
   */
  private detectPhishingForms(analysis: ScrapedWebsiteAnalysis): VaccineThreat[] {
    const threats: VaccineThreat[] = [];

    analysis.forms.forEach((form, formIndex) => {
      // Check 1: Form submits to external domain
      if (form.targetDomain && form.targetDomain !== analysis.domain) {
        threats.push({
          type: VaccineThreatType.PHISHING_FORM,
          severity: "high",
          description: `Form submits to external domain: ${form.targetDomain}`,
          targetElement: `form[${formIndex}]`,
          location: form.action,
          evidence: `Form action points to ${form.targetDomain} instead of ${analysis.domain}`,
          injectionRule: {
            id: `phishing-form-${formIndex}`,
            type: "block",
            selector: `form[${formIndex}]`,
            message: "This form submits to an external server. Blocked for your protection.",
            expiresAt: Date.now() + 86400000, // 24h
          },
        });
      }

      // Check 2: Credential harvesting
      const credentialFields = form.fields.filter((f) => f.fieldSuspicionScore > 25);
      if (credentialFields.length > 0) {
        threats.push({
          type: VaccineThreatType.CREDENTIAL_HARVESTER,
          severity: credentialFields.length > 3 ? "high" : "medium",
          description: `Form contains ${credentialFields.length} credential fields`,
          targetElement: `form[${formIndex}]`,
          location: form.action,
          evidence: `Fields: ${credentialFields.map((f) => f.name).join(", ")}`,
          injectionRule: {
            id: `credential-harvest-${formIndex}`,
            type: "warn",
            selector: `form[${formIndex}]`,
            message: "This form is requesting sensitive information. Be cautious.",
            expiresAt: Date.now() + 86400000,
          },
        });
      }

      // Check 3: Payment form without SSL
      const hasPaymentFields = form.fields.some(
        (f) =>
          /credit|card|payment|cvv|cvc/i.test(f.name) ||
          /credit|card|payment|cvv|cvc/i.test(f.type)
      );

      if (hasPaymentFields && !analysis.url.startsWith("https://")) {
        threats.push({
          type: VaccineThreatType.PAYMENT_FORM_FAKE,
          severity: "critical",
          description: "Payment form over unencrypted HTTP connection",
          targetElement: `form[${formIndex}]`,
          location: analysis.url,
          evidence: "Site lacks HTTPS but requests payment information",
          injectionRule: {
            id: `payment-no-ssl-${formIndex}`,
            type: "block",
            selector: `form[${formIndex}]`,
            message:
              "DANGER: This payment form is not encrypted. This is a critical security risk.",
            expiresAt: Date.now() + 86400000,
          },
        });
      }
    });

    return threats;
  }

  /**
   * Malware Signature Detection
   */
  private detectMalwareSignatures(analysis: ScrapedWebsiteAnalysis): VaccineThreat[] {
    const threats: VaccineThreat[] = [];

    // Check scripts
    analysis.scripts.forEach((script, scriptIndex) => {
      const content = script.content;

      this.malwareSignatures.forEach((sig) => {
        if (sig.pattern.test(content)) {
          threats.push({
            type: VaccineThreatType.MALWARE_SIGNATURE,
            severity: sig.severity,
            description: `Malware signature detected: ${sig.name}`,
            targetElement: `script[${scriptIndex}]`,
            location: script.src || "inline",
            evidence: `Known ${sig.category} pattern matched`,
            injectionRule: {
              id: `malware-${sig.name}-${scriptIndex}`,
              type: "disable",
              scriptContent: `// Malware signature blocked: ${sig.name}`,
              message: `Malware detected and blocked: ${sig.name}`,
              expiresAt: Date.now() + 86400000,
            },
          });
        }
      });
    });

    // Check external script URLs against known malicious domains
    analysis.scripts.forEach((script, scriptIndex) => {
      if (script.src && this.isKnownMaliciousDomain(script.src)) {
        threats.push({
          type: VaccineThreatType.MALWARE_SIGNATURE,
          severity: "high",
          description: `Script from known malware domain: ${script.src}`,
          targetElement: `script[${scriptIndex}]`,
          location: script.src,
          evidence: `Domain is known to host malware`,
          injectionRule: {
            id: `malicious-domain-${scriptIndex}`,
            type: "block",
            targetUrl: script.src,
            expiresAt: Date.now() + 86400000,
          },
        });
      }
    });

    return threats;
  }

  /**
   * Suspicious Script Detection
   */
  private detectSuspiciousScripts(analysis: ScrapedWebsiteAnalysis): VaccineThreat[] {
    const threats: VaccineThreat[] = [];

    analysis.scripts.forEach((script, scriptIndex) => {
      // Obfuscated code
      if (script.isObfuscated && script.suspicionScore > 50) {
        threats.push({
          type: VaccineThreatType.OBFUSCATED_CODE,
          severity: "medium",
          description: "Highly obfuscated script detected",
          targetElement: `script[${scriptIndex}]`,
          location: script.src || "inline",
          evidence: "Script uses excessive obfuscation techniques",
          injectionRule: {
            id: `obfuscated-${scriptIndex}`,
            type: "warn",
            message: "This script is heavily obfuscated and may be suspicious.",
            expiresAt: Date.now() + 86400000,
          },
        });
      }

      // Iframe injection
      if (/createElement.*iframe|<iframe/i.test(script.content)) {
        threats.push({
          type: VaccineThreatType.IFRAME_INJECTION,
          severity: "high",
          description: "Script creates iframes dynamically",
          targetElement: `script[${scriptIndex}]`,
          location: script.src || "inline",
          evidence: "Detected iframe creation in script",
          injectionRule: {
            id: `iframe-inject-${scriptIndex}`,
            type: "sandbox",
            message: "This script attempts to inject content. Sandboxed.",
            expiresAt: Date.now() + 86400000,
          },
        });
      }

      // Redirect chains
      if (/location\s*=|location\.href|window\.location/i.test(script.content)) {
        threats.push({
          type: VaccineThreatType.REDIRECT_CHAIN,
          severity: "high",
          description: "Script attempts page redirection",
          targetElement: `script[${scriptIndex}]`,
          location: script.src || "inline",
          evidence: "Script contains redirect code",
          injectionRule: {
            id: `redirect-${scriptIndex}`,
            type: "warn",
            message:
              "This script may redirect you. Click OK to proceed, or Cancel to block.",
            expiresAt: Date.now() + 86400000,
          },
        });
      }
    });

    return threats;
  }

  /**
   * Scam Pattern Detection
   */
  private detectScamPatterns(analysis: ScrapedWebsiteAnalysis): VaccineThreat[] {
    const threats: VaccineThreat[] = [];
    const text = analysis.textContent.toLowerCase();

    // Urgency language
    const urgencyKeywords = [
      "act now",
      "limited time",
      "urgent",
      "immediately",
      "before it's too late",
      "offer expires",
      "click here now",
    ];

    const urgencyMatches = urgencyKeywords.filter((keyword) => text.includes(keyword));

    if (urgencyMatches.length > 3) {
      threats.push({
        type: VaccineThreatType.URGENCY_LANGUAGE,
        severity: "medium",
        description: `Page uses excessive urgency language (${urgencyMatches.length} instances)`,
        evidence: `Found: ${urgencyMatches.join(", ")}`,
        injectionRule: {
          id: `urgency-${Date.now()}`,
          type: "warn",
          message: "This page uses high-pressure tactics. Take time to verify before acting.",
          expiresAt: Date.now() + 86400000,
        },
      });
    }

    // Fake trust badges
    if (this.detectFakeTrustBadges(analysis)) {
      threats.push({
        type: VaccineThreatType.FAKE_TRUST_BADGE,
        severity: "medium",
        description: "Fake trust badges or security seals detected",
        evidence: "Page displays uncertified trust indicators",
        injectionRule: {
          id: `fake-badge-${Date.now()}`,
          type: "warn",
          message: "This page displays fake security badges. Verify this site independently.",
          expiresAt: Date.now() + 86400000,
        },
      });
    }

    return threats;
  }

  /**
   * Social Engineering Detection
   */
  private detectSocialEngineering(analysis: ScrapedWebsiteAnalysis): VaccineThreat[] {
    const threats: VaccineThreat[] = [];
    const text = analysis.textContent.toLowerCase();
    const html = analysis.html.toLowerCase();

    // Fake support chat
    if (
      /live.?chat|chat.?now|support.?agent|customer.?service/i.test(html) &&
      /click.*chat|click.*now|contact.*support/i.test(html)
    ) {
      threats.push({
        type: VaccineThreatType.FAKE_SUPPORT_CHAT,
        severity: "medium",
        description: "Fake support chat interface detected",
        evidence: "Page includes chat widget elements",
        injectionRule: {
          id: `fake-chat-${Date.now()}`,
          type: "sandbox",
          message: "This support chat may not be authentic. Verify through official channels.",
          expiresAt: Date.now() + 86400000,
        },
      });
    }

    // Clipboard hijacking
    analysis.scripts.forEach((script, idx) => {
      if (
        /navigator\.clipboard|document\.execCommand\s*\(\s*['"]copy/i.test(
          script.content
        )
      ) {
        threats.push({
          type: VaccineThreatType.CLIPBOARD_HIJACK,
          severity: "high",
          description: "Script accesses clipboard",
          targetElement: `script[${idx}]`,
          evidence: "Script uses clipboard API",
          injectionRule: {
            id: `clipboard-${idx}`,
            type: "warn",
            message:
              "This site is accessing your clipboard. Do not copy sensitive information here.",
            expiresAt: Date.now() + 86400000,
          },
        });
      }
    });

    return threats;
  }

  /**
   * Domain Spoofing Detection
   */
  private detectDomainSpoofing(analysis: ScrapedWebsiteAnalysis): VaccineThreat[] {
    const threats: VaccineThreat[] = [];

    if (analysis.isDomainMatch) {
      threats.push({
        type: VaccineThreatType.SPOOFED_BRANDING,
        severity: "critical",
        description: "Page claims to be from a major company but domain doesn't match",
        evidence: `Domain ${analysis.domain} doesn't match claimed business`,
        injectionRule: {
          id: `spoofing-${Date.now()}`,
          type: "warn",
          message:
            "ALERT: This page claims to be from a major company but the domain doesn't match. This is likely a phishing attempt.",
          expiresAt: Date.now() + 86400000,
        },
      });
    }

    return threats;
  }

  /**
   * Shannon Entropy Analysis — obfuscated code has measurably higher entropy
   * than normal JS. Scripts above threshold are flagged.
   */
  private detectHighEntropyScripts(analysis: ScrapedWebsiteAnalysis): VaccineThreat[] {
    const threats: VaccineThreat[] = [];
    const ENTROPY_THRESHOLD = 5.5; // Normal JS: ~4.5, obfuscated: ~5.8+

    analysis.scripts.forEach((script, idx) => {
      if (!script.content || script.content.length < 200) return;

      const entropy = this.shannonEntropy(script.content);
      if (entropy > ENTROPY_THRESHOLD) {
        threats.push({
          type: VaccineThreatType.OBFUSCATED_CODE,
          severity: entropy > 6.0 ? "high" : "medium",
          description: `High-entropy script detected (entropy: ${entropy.toFixed(2)})`,
          targetElement: `script[${idx}]`,
          location: script.src || "inline",
          evidence: `Shannon entropy ${entropy.toFixed(2)} exceeds threshold ${ENTROPY_THRESHOLD} (normal JS ≈ 4.5)`,
          injectionRule: {
            id: `entropy-${idx}`,
            type: "warn",
            message: "This script has unusually high entropy, suggesting obfuscation.",
            expiresAt: Date.now() + 86400000,
          },
        });
      }
    });

    return threats;
  }

  private shannonEntropy(text: string): number {
    const freq = new Map<string, number>();
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      freq.set(c, (freq.get(c) || 0) + 1);
    }

    let entropy = 0;
    const len = text.length;
    for (const count of freq.values()) {
      const p = count / len;
      if (p > 0) entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  /**
   * Homoglyph Detection — catch аpple.com (Cyrillic 'а') vs apple.com.
   * Maps confusable Unicode characters to their ASCII equivalents.
   */
  private detectHomoglyphDomain(analysis: ScrapedWebsiteAnalysis): VaccineThreat[] {
    const threats: VaccineThreat[] = [];
    const domain = analysis.domain;

    if (!domain) return threats;

    // Check if domain contains non-ASCII characters (IDN/punycode)
    const hasNonAscii = /[^\x00-\x7F]/.test(domain);

    if (hasNonAscii) {
      threats.push({
        type: VaccineThreatType.SPOOFED_BRANDING,
        severity: "critical",
        description: `Domain contains non-ASCII characters (possible homoglyph attack): ${domain}`,
        evidence: `Domain "${domain}" contains Unicode characters that may visually mimic a legitimate domain`,
        injectionRule: {
          id: `homoglyph-${Date.now()}`,
          type: "warn",
          message: "WARNING: This domain contains special characters that may be impersonating a real website.",
          expiresAt: Date.now() + 86400000,
        },
      });
    }

    // Check links for homoglyph domains
    const knownBrands = ['google', 'apple', 'microsoft', 'amazon', 'facebook', 'paypal', 'netflix', 'bank'];

    // Confusable character map (Cyrillic → Latin)
    const confusables: Record<string, string> = {
      'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y',
      'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'ɡ': 'g', 'ɩ': 'l',
    };

    const deconfused = domain.split('').map(c => confusables[c] || c).join('');

    if (deconfused !== domain) {
      // Domain had confusable characters — check if it matches a known brand
      for (const brand of knownBrands) {
        if (deconfused.includes(brand)) {
          threats.push({
            type: VaccineThreatType.SPOOFED_BRANDING,
            severity: "critical",
            description: `Homoglyph attack detected: "${domain}" impersonates "${brand}"`,
            evidence: `After Unicode normalization, domain resolves to "${deconfused}" which matches known brand "${brand}"`,
            injectionRule: {
              id: `homoglyph-brand-${Date.now()}`,
              type: "block",
              selector: "body",
              message: `DANGER: This site is impersonating ${brand} using lookalike characters.`,
              expiresAt: Date.now() + 86400000,
            },
          });
          break;
        }
      }
    }

    return threats;
  }

  private detectFakeTrustBadges(analysis: ScrapedWebsiteAnalysis): boolean {
    const trustedBadges = [
      "norton",
      "mcafee",
      "avg",
      "kaspersky",
      "geotrust",
      "verisign",
      "comodo",
    ];

    const html = analysis.html.toLowerCase();
    const images = analysis.mediaElements
      .filter((m) => m.type === "image")
      .map((m) => (m.src || "").toLowerCase());

    // Check if page claims to have trust badges but doesn't
    const claimsSecure = /secure|trusted|verified|certified/i.test(
      analysis.textContent
    );

    // Check if badges are actually present (proper verification would check SSL, etc)
    const hasRealBadgeImages = images.some((img) =>
      trustedBadges.some((badge) => img.includes(badge))
    );

    // If claims security but has no real badges, likely fake
    return claimsSecure && !hasRealBadgeImages && html.includes("badge");
  }

  private isKnownMaliciousDomain(url: string): boolean {
    // In production, this would check against a threat intelligence feed
    const knownMalicious = [
      "malware-dist.com",
      "exploit-kit.net",
      "cryptominer-pool.io",
      "keylogger-service.ru",
    ];

    try {
      const domain = new URL(url).hostname;
      return knownMalicious.some(
        (mal) => domain?.includes(mal) || url.includes(mal)
      );
    } catch {
      return false;
    }
  }

  private initMalwareSignatures(): MalwareSignature[] {
    return [
      {
        name: "cryptominer_coinhive",
        pattern: /coinhive|monero\.io|webmining/i,
        severity: "high",
        category: "cryptominer",
      },
      {
        name: "cryptominer_jsecoin",
        pattern: /jsecoin|crypto\.mine/i,
        severity: "high",
        category: "cryptominer",
      },
      {
        name: "exploit_kit_angler",
        pattern: /angler|sweet_orange|rig.?ek/i,
        severity: "critical",
        category: "exploit",
      },
      {
        name: "keylogger_pattern",
        pattern: /onkeydown|onkeyup|onkeypress.*send|keyCode.*log/i,
        severity: "critical",
        category: "keylogger",
      },
      {
        name: "ransomware_crypto",
        pattern: /ransomware|crypto.?wall|locky|wannacry/i,
        severity: "critical",
        category: "ransomware",
      },
      {
        name: "xss_vector",
        pattern: /<script[^>]*>[\s\S]*?<\/script>|javascript:/i,
        severity: "high",
        category: "exploit",
      },
    ];
  }

  private initPhishingPatterns(): PhishingPattern[] {
    return [
      {
        name: "bank_login",
        fields: ["username", "password", "account", "pin"],
        suspicion: 30,
      },
      {
        name: "credit_card",
        fields: ["creditcard", "cardnumber", "cvv", "cvc", "expiry"],
        suspicion: 40,
      },
      {
        name: "social_security",
        fields: ["ssn", "socialsecurity", "taxpayerid"],
        suspicion: 50,
      },
      {
        name: "email_password",
        fields: ["email", "password"],
        suspicion: 20,
      },
    ];
  }
}

export const threatDetector = new ThreatDetector();
