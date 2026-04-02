/**
 * Vaccine Manager
 * Orchestrates threat detection, rule generation, storage, and vaccination
 *
 * SYNERGOS INTEGRATION: Now uses hybrid VERIDICT + SYNERGOS analysis
 * - VERIDICT: Fast signature-based detection (~5ms)
 * - SYNERGOS: Deep behavioral analysis (~155ms) on uncertain cases
 */

import { WebsiteScraperEdge } from "./website-scraper-edge";
import { ThreatDetector } from "./threat-detector";
import { InjectionEngine } from "./injection-engine";
import { synergosIntegration } from "./synergos-integration";
import { hashContent } from "./payload-signer";
import {
  ScrapedWebsiteAnalysis,
  VaccineReport,
  VaccineStore,
  InjectionRule,
  VaccineThreat,
  VaccineThreatType,
} from "./types";

const MAX_CACHE_SIZE = 1000; // Prevent unbounded memory growth

export class VaccineManager {
  private scraper: WebsiteScraperEdge;
  private threatDetector: ThreatDetector;
  private injectionEngine: InjectionEngine;
  private vaccineCache: Map<string, VaccineStore> = new Map();
  private cacheHits: Map<string, number> = new Map(); // Track hits for re-validation

  constructor() {
    this.scraper = new WebsiteScraperEdge();
    this.threatDetector = new ThreatDetector();
    this.injectionEngine = new InjectionEngine();
  }

  /**
   * Full vaccination pipeline: Scrape → Detect (VERIDICT) → Optional SYNERGOS → Rules → Store
   *
   * Decision Tree:
   * 1. Quick threat detection (VERIDICT) - ~5ms
   * 2. If confidence high → proceed with injection rules
   * 3. If confidence low OR unusual form → escalate to SYNERGOS - ~155ms
   * 4. Generate combined injection rules based on both signals
   * 5. Store vaccine with TTL for future hits
   */
  async vaccinate(url: string, vericticScore?: number): Promise<VaccineReport> {
    const startTime = Date.now();

    try {
      // Step 1: Scrape the website
      console.log(`[Vaccine] Scraping ${url}...`);
      const scrapedAnalysis = await this.scraper.scrapeWebsite(url);

      // Step 2: Hybrid threat detection (VERIDICT + optional SYNERGOS)
      console.log(`[Vaccine] Analyzing threats with SYNERGOS...`);
      const vaccineReport = await synergosIntegration.analyzeWithSynergos(
        scrapedAnalysis,
        vericticScore
      );

      // Step 3: Generate injection rules from threat analysis
      console.log(`[Vaccine] Generating injection rules...`);
      // threatsDetected can be string[] or VaccineThreat[] depending on source
      const threatObjects: VaccineThreat[] = vaccineReport.threatsDetected
        .map((t: any) => {
          if (typeof t === 'string') {
            return {
              type: VaccineThreatType.PHISHING_FORM,
              severity: 'high' as const,
              description: t,
              evidence: t,
              injectionRule: {
                id: `threat-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
                type: 'warn' as const,
                message: t,
                expiresAt: Date.now() + 86400000,
              },
            };
          }
          return t;
        });
      const injectionRules = this.injectionEngine.generateInjectionRules(threatObjects);

      // Add SYNERGOS-specific rules if available
      if (vaccineReport.synergosAnalysis) {
        const synergosRules = this._generateSynergosRules(vaccineReport.synergosAnalysis);
        injectionRules.push(...synergosRules);
      }

      // Step 4: Build final report
      const report: VaccineReport = {
        url,
        timestamp: Date.now(),
        threatLevel: vaccineReport.threatLevel,
        threatScore: vaccineReport.threatScore,
        threatsDetected: vaccineReport.threatsDetected,
        injectionRules,
        scrapedAnalysis,
        vericticScore,
        synergosAnalysis: vaccineReport.synergosAnalysis,
        latencyMs: vaccineReport.latencyMs,
      };

      // Step 5: Store vaccine (24h TTL)
      this.storeVaccine(url, report, injectionRules);

      console.log(
        `[Vaccine] Complete (${report.latencyMs}ms): ${report.threatLevel} threat level, ${report.threatsDetected.length} threats, SYNERGOS confidence: ${vaccineReport.synergosAnalysis?.confidence.toFixed(2) || 'N/A'}`
      );

      return report;
    } catch (error) {
      console.error(`[Vaccine] Error during vaccination:`, error);
      throw error;
    }
  }

  /**
   * Get a stored vaccine if not expired.
   * Forces re-validation after 10 cache hits to prevent serving stale/poisoned data.
   */
  getVaccine(url: string): VaccineStore | null {
    const vaccine = this.vaccineCache.get(url);

    if (!vaccine) {
      return null;
    }

    // Check expiration
    if (Date.now() > vaccine.expiresAt) {
      this.vaccineCache.delete(url);
      this.cacheHits.delete(url);
      return null;
    }

    // Force re-validation after 10 hits
    const hits = (this.cacheHits.get(url) || 0) + 1;
    this.cacheHits.set(url, hits);
    if (hits > 10) {
      this.vaccineCache.delete(url);
      this.cacheHits.delete(url);
      return null; // Caller will re-scan
    }

    return vaccine;
  }

  /**
   * Get or create vaccine for a URL
   */
  async getOrVaccinate(
    url: string,
    vericticScore?: number
  ): Promise<VaccineReport> {
    const existing = this.getVaccine(url);
    if (existing) {
      return existing.report;
    }

    return this.vaccinate(url, vericticScore);
  }

  /**
   * Invalidate a vaccine (e.g., when site is cleaned)
   */
  invalidateVaccine(url: string): void {
    this.vaccineCache.delete(url);
    console.log(`[Vaccine] Invalidated vaccine for ${url}`);
  }

  /**
   * Get injection script for content script
   */
  getInjectionScript(url: string): string | null {
    const vaccine = this.getVaccine(url);
    if (!vaccine) {
      return null;
    }

    return this.injectionEngine.generateContentScript(vaccine.injectionRules);
  }

  /**
   * Export vaccine as JSON (for API responses)
   */
  exportVaccine(url: string): VaccineReport | null {
    const vaccine = this.getVaccine(url);
    return vaccine ? vaccine.report : null;
  }

  private storeVaccine(
    url: string,
    report: VaccineReport,
    rules: InjectionRule[]
  ): void {
    // Enforce cache size limit (evict oldest entries if over limit)
    if (this.vaccineCache.size >= MAX_CACHE_SIZE) {
      let oldestKey: string | null = null;
      let oldestTime = Infinity;
      for (const [key, entry] of this.vaccineCache) {
        if (entry.createdAt < oldestTime) {
          oldestTime = entry.createdAt;
          oldestKey = key;
        }
      }
      if (oldestKey) this.vaccineCache.delete(oldestKey);
    }

    const expiresAt = Date.now() + 24 * 60 * 60 * 1000; // 24 hours

    const store: VaccineStore = {
      url,
      report,
      injectionRules: rules,
      expiresAt,
      createdAt: Date.now(),
      status: "active",
    };

    this.vaccineCache.set(url, store);
    this.cacheHits.set(url, 0);
  }

  private calculateThreatScore(
    threats: VaccineThreat[],
    vericticScore?: number
  ): number {
    if (threats.length === 0) {
      return vericticScore ? Math.max(0, vericticScore * 0.5) : 0;
    }

    // Weight threats by severity
    const severityWeights = {
      critical: 25,
      high: 15,
      medium: 8,
      low: 3,
    };

    let score = 0;
    threats.forEach((threat) => {
      score += severityWeights[threat.severity] || 0;
    });

    // Cap at 100
    score = Math.min(score, 100);

    // Factor in VERIDICT score (50% weight)
    if (vericticScore !== undefined) {
      score = score * 0.5 + vericticScore * 0.5;
    }

    return Math.round(score);
  }

  private getThreatLevel(
    score: number
  ): "safe" | "low" | "medium" | "high" | "critical" {
    // Randomized thresholds (±5%) to prevent attackers from crafting
    // pages that sit exactly below a known threshold
    const jitter = () => (Math.random() - 0.5) * 5; // ±2.5
    if (score < 15 + jitter()) return "safe";
    if (score < 35 + jitter()) return "low";
    if (score < 55 + jitter()) return "medium";
    if (score < 75 + jitter()) return "high";
    return "critical";
  }

  /**
   * Generate injection rules specific to SYNERGOS analysis results
   */
  private _generateSynergosRules(synergosAnalysis: any): InjectionRule[] {
    const rules: InjectionRule[] = [];

    // Block rules
    if (synergosAnalysis.verdict === 'BLOCK') {
      rules.push({
        id: `synergos-block-${Date.now()}`,
        type: 'block',
        selector: 'form',
        message: synergosAnalysis.verdict === 'BLOCK'
          ? 'SYNERGOS: Form blocked due to malicious intent pattern detection'
          : '',
        expiresAt: Date.now() + 3600000,
      } as any);
    }

    // Warn rules with defense recommendations
    if (synergosAnalysis.verdict === 'WARN' && synergosAnalysis.recommendedDefense) {
      rules.push({
        id: `synergos-warn-${Date.now()}`,
        type: 'warn',
        selector: 'form',
        message: 'SYNERGOS Warning: Unusual form structure detected. Verify before submitting.',
        expiresAt: Date.now() + 3600000,
      } as any);
    }

    // Prediction-based rules
    if (synergosAnalysis.nextAttackPrediction?.tactics) {
      const tactics = synergosAnalysis.nextAttackPrediction.tactics;

      if (tactics.includes('credential_harvesting')) {
        rules.push({
          id: `synergos-pred-cred-${Date.now()}`,
          type: 'monitor',
          selector: 'input[type="password"]',
          message: 'SYNERGOS: Monitoring password field activity',
          expiresAt: Date.now() + 3600000,
        } as any);
      }

      if (tactics.includes('payment_fraud')) {
        rules.push({
          id: `synergos-pred-pay-${Date.now()}`,
          type: 'warn',
          selector: 'input[name*="card"], input[name*="payment"]',
          message: 'SYNERGOS: Additional verification required for payment',
          expiresAt: Date.now() + 3600000,
        } as any);
      }
    }

    return rules;
  }

  private generateRecommendations(
    threats: VaccineThreat[],
    threatLevel: string
  ): string[] {
    const recommendations: string[] = [];

    // Count threat types
    const threatTypes = new Set(threats.map((t) => t.type));

    if (threats.some((t) => t.severity === "critical")) {
      recommendations.push("CRITICAL: Do not enter any personal information on this site.");
    }

    if (threatTypes.has(VaccineThreatType.PHISHING_FORM)) {
      recommendations.push(
        "This site contains suspicious forms. Avoid entering sensitive information."
      );
    }

    if (threatTypes.has(VaccineThreatType.CREDENTIAL_HARVESTER)) {
      recommendations.push(
        "This site is requesting credentials. Verify it's the official website before logging in."
      );
    }

    if (threatTypes.has(VaccineThreatType.MALWARE_SIGNATURE)) {
      recommendations.push(
        "This site contains known malware patterns. ScamShield has blocked malicious scripts."
      );
    }

    if (threatTypes.has(VaccineThreatType.SPOOFED_BRANDING)) {
      recommendations.push(
        "This site is impersonating a major company. Verify the real URL before providing information."
      );
    }

    if (threatTypes.has(VaccineThreatType.OBFUSCATED_CODE)) {
      recommendations.push(
        "This site contains obfuscated scripts. This is often used to hide malicious code."
      );
    }

    if (threatLevel === "safe") {
      recommendations.push("This site appears to be safe. You can proceed with normal browsing.");
    }

    if (recommendations.length === 0) {
      recommendations.push("Review the detected threats above before interacting with this site.");
    }

    return recommendations;
  }

  /**
   * Statistics for monitoring
   */
  getStats(): {
    cachedVaccines: number;
    totalThreats: number;
    threatsByType: Record<string, number>;
  } {
    let totalThreats = 0;
    const threatsByType: Record<string, number> = {};

    this.vaccineCache.forEach((vaccine) => {
      vaccine.report.threatsDetected.forEach((threat: any) => {
        totalThreats++;
        const type = typeof threat === 'string' ? 'unknown' : threat.type;
        threatsByType[type] = (threatsByType[type] || 0) + 1;
      });
    });

    return {
      cachedVaccines: this.vaccineCache.size,
      totalThreats,
      threatsByType,
    };
  }
}

export const vaccineManager = new VaccineManager();
