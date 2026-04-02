/**
 * SYNERGOS Integration Layer
 * Bridges SYNERGOS threat detection with existing ScamShield vaccine system
 *
 * Integration Strategy:
 * 1. Fast path: Quick VERIDICT check (signature-based)
 * 2. Fallback: SYNERGOS deep analysis if VERIDICT uncertain
 * 3. Escalation: SYNERGOS trajectory to inform defense updates
 */

import { ScrapedWebsiteAnalysis, ScrapedForm, VaccineReport } from "./types";
import { synergosEngine, SynergosDecision } from "./synergos-core";
import { threatDetector } from "./threat-detector";

export class SynergosIntegration {
  private readonly synergosThreshold = 0.80;  // Min confidence to trust SYNERGOS
  private readonly escalationThreshold = 0.65; // When to escalate to SYNERGOS

  /**
   * Main integration point: Analyze form and generate vaccine report
   * Uses hybrid VERIDICT + SYNERGOS approach
   */
  async analyzeWithSynergos(
    analysis: ScrapedWebsiteAnalysis,
    vericticScore?: number
  ): Promise<VaccineReport> {
    const startTime = performance.now();

    try {
      // STAGE 1: Quick threat detection (VERIDICT-style)
      const vericticThreats = threatDetector.detectThreats(analysis);
      const vericticSeverity = this._computeSeverity(vericticThreats);

      // STAGE 2: Decide if SYNERGOS escalation is needed
      const shouldEscalate =
        vericticScore === undefined ||
        vericticScore < this.escalationThreshold ||
        this._isUnusualForm(analysis);

      let synergosDecision: SynergosDecision | null = null;

      if (shouldEscalate && analysis.forms.length > 0) {
        // STAGE 3: Run SYNERGOS deep analysis
        synergosDecision = await synergosEngine.analyze(
          analysis.forms[0],
          analysis.html,
          { domain: analysis.domain }
        );
      }

      // STAGE 4: Unified threat assessment
      const finalDecision = this._unifyDecisions(
        vericticSeverity,
        vericticThreats,
        synergosDecision
      );

      // STAGE 5: Generate injection rules
      const injectionRules = this._generateInjectionRules(
        analysis,
        finalDecision,
        synergosDecision
      );

      const latencyMs = performance.now() - startTime;

      return {
        url: analysis.url,
        timestamp: Date.now(),
        threatLevel: finalDecision.threatLevel as VaccineReport['threatLevel'],
        threatScore: finalDecision.threatScore,
        threatsDetected: finalDecision.threats,
        injectionRules,
        synergosAnalysis: synergosDecision ? {
          verdict: synergosDecision.verdict,
          confidence: synergosDecision.confidence,
          nextAttackPrediction: synergosDecision.nextAttackPrediction,
          recommendedDefense: synergosDecision.recommendedDefense,
        } : undefined,
        latencyMs,
      };
    } catch (error) {
      console.error('[SYNERGOS-INTEGRATION] Error:', error);

      // Fallback: use only VERIDICT
      const vericticThreats = threatDetector.detectThreats(analysis);
      return {
        url: analysis.url,
        timestamp: Date.now(),
        threatLevel: this._computeThreatLevel(this._computeSeverity(vericticThreats)) as VaccineReport['threatLevel'],
        threatScore: this._computeSeverity(vericticThreats),
        threatsDetected: vericticThreats.map(t => t.description),
        injectionRules: [],
        latencyMs: performance.now() - startTime,
      };
    }
  }

  /**
   * Generate injection rules based on SYNERGOS + VERIDICT findings
   */
  private _generateInjectionRules(
    analysis: ScrapedWebsiteAnalysis,
    finalDecision: any,
    synergosDecision: SynergosDecision | null
  ): any[] {
    const rules: any[] = [];

    if (synergosDecision) {
      // Block rules from SYNERGOS
      if (synergosDecision.verdict === 'BLOCK') {
        rules.push({
          type: 'block',
          selector: 'form',
          message: synergosDecision.reasoning,
          expiresAt: Date.now() + 3600000,
        });
      }

      // Warn rules with recommendations
      if (synergosDecision.verdict === 'WARN') {
        const defenses = synergosDecision.recommendedDefense || [];
        rules.push({
          type: 'warn',
          selector: 'form',
          message: synergosDecision.reasoning,
          defenses,
          expiresAt: Date.now() + 3600000,
        });
      }

      // Prediction-based defense injection
      if (synergosDecision.nextAttackPrediction.likelihood > 0.7) {
        const tactics = synergosDecision.nextAttackPrediction.tactics || [];

        if (tactics.includes('credential_harvesting')) {
          rules.push({
            type: 'monitor',
            selector: 'input[type="password"]',
            message: 'Monitoring password field activity',
            action: 'log_form_submissions',
            expiresAt: Date.now() + 3600000,
          });
        }

        if (tactics.includes('payment_fraud')) {
          rules.push({
            type: 'require_verification',
            selector: 'input[name*="card"], input[name*="payment"]',
            message: 'Additional verification required for payment',
            expiresAt: Date.now() + 3600000,
          });
        }
      }
    }

    return rules;
  }

  /**
   * Unify VERIDICT and SYNERGOS decisions
   */
  private _unifyDecisions(
    vericticSeverity: number,
    vericticThreats: any[],
    synergosDecision: SynergosDecision | null
  ): { threatLevel: string; threatScore: number; threats: string[] } {
    let finalSeverity = vericticSeverity;
    let finalThreats = vericticThreats.map(t => t.description);

    if (synergosDecision && synergosDecision.confidence > this.synergosThreshold) {
      // SYNERGOS is confident: weight it heavily
      const synergosScore = synergosDecision.severity;
      finalSeverity = (vericticSeverity * 0.4 + synergosScore * 0.6);

      // Add SYNERGOS insights to threat list
      if (synergosDecision.verdict === 'BLOCK') {
        finalThreats.push(`[SYNERGOS] ${synergosDecision.reasoning}`);
      }

      // Add predicted attacks
      if (synergosDecision.nextAttackPrediction.tactics.length > 0) {
        finalThreats.push(
          `[PREDICTION] Expected next attack: ${synergosDecision.nextAttackPrediction.tactics.join(', ')}`
        );
      }
    }

    return {
      threatLevel: this._computeThreatLevel(finalSeverity),
      threatScore: finalSeverity,
      threats: finalThreats,
    };
  }

  /**
   * Heuristic: detect unusual/novel forms that benefit from SYNERGOS
   */
  private _isUnusualForm(analysis: ScrapedWebsiteAnalysis): boolean {
    if (analysis.forms.length === 0) return false;

    const form = analysis.forms[0];

    // Unusual if: many fields, external submission, unusual field names
    const manyFields = form.fields.length > 10;
    const externalSubmission = form.targetDomain !== undefined;
    const obfuscatedNames = form.fields.filter(f =>
      /[a-z]{20,}|_+[a-z]|x[0-9]{10}/.test(f.name)
    ).length > 2;

    return manyFields || externalSubmission || obfuscatedNames;
  }

  /**
   * Compute severity from threat list (VERIDICT-style)
   */
  private _computeSeverity(threats: any[]): number {
    if (threats.length === 0) return 0;

    const criticalThreats = threats.filter(t => t.severity === 'critical').length;
    const highThreats = threats.filter(t => t.severity === 'high').length;
    const mediumThreats = threats.filter(t => t.severity === 'medium').length;

    return Math.min(1.0,
      (criticalThreats * 1.0 + highThreats * 0.5 + mediumThreats * 0.2) / Math.max(threats.length, 1)
    );
  }

  /**
   * Map severity score to threat level
   */
  private _computeThreatLevel(severity: number): string {
    if (severity >= 0.8) return 'CRITICAL';
    if (severity >= 0.6) return 'HIGH';
    if (severity >= 0.4) return 'MEDIUM';
    if (severity >= 0.2) return 'LOW';
    return 'SAFE';
  }
}

export const synergosIntegration = new SynergosIntegration();
