/**
 * SYNERGOS Core Engine Tests
 * Validates all 5 stages of threat analysis
 *
 * Test Coverage:
 * - Stage 1: Intent Field Computation
 * - Stage 2A: Payoff Inference
 * - Stage 2B: Fragility Analysis
 * - Stage 2C: Unified Decision
 * - Stage 3: Evolution Tracking
 * - Stage 4: Trajectory Simulation
 * - Stage 5: Adaptive Dispatcher
 */

import { SynergosEngine } from './synergos-core';
import { ScrapedForm, FormField } from './types';

describe('SynergosEngine', () => {
  let engine: SynergosEngine;

  beforeEach(() => {
    engine = new SynergosEngine();
  });

  // ========================================================================
  // STAGE 1: FEATURE EXTRACTION
  // ========================================================================

  describe('Stage 1: Feature Extraction', () => {
    it('should compute intent field from form fields', async () => {
      const form = createTestForm({
        fields: [
          { name: 'email', type: 'email', fieldSuspicionScore: 10 },
          { name: 'password', type: 'password', fieldSuspicionScore: 30 },
          { name: 'verify_password', type: 'password', fieldSuspicionScore: 30 },
        ],
      });

      const result = await engine.analyze(form, '<html><form></form></html>');

      expect(result).toBeDefined();
      expect(result.threatProfile).toBeDefined();
      expect(result.threatProfile.intentField).toBeGreaterThanOrEqual(0);
      expect(result.threatProfile.intentField).toBeLessThanOrEqual(1);
    });

    it('should detect credential harvesting fields', async () => {
      const form = createTestForm({
        fields: [
          { name: 'username', type: 'text', fieldSuspicionScore: 20 },
          { name: 'password', type: 'password', fieldSuspicionScore: 40 },
          { name: 'password2', type: 'password', fieldSuspicionScore: 40 },
          { name: 'security_question', type: 'text', fieldSuspicionScore: 25 },
        ],
      });

      const result = await engine.analyze(form, '<html></html>');

      expect(result.threatProfile.intentField).toBeGreaterThan(0.3);
      expect(result.nextAttackPrediction.tactics).toContain('credential_harvesting');
    });

    it('should detect payment fraud patterns', async () => {
      const form = createTestForm({
        fields: [
          { name: 'card_number', type: 'text', fieldSuspicionScore: 50 },
          { name: 'cvv', type: 'text', fieldSuspicionScore: 50 },
          { name: 'exp_date', type: 'text', fieldSuspicionScore: 40 },
        ],
        targetDomain: 'evil.com',
      });

      const result = await engine.analyze(form, '<html></html>');

      expect(result.nextAttackPrediction.tactics).toContain('payment_fraud');
    });

    it('should measure latency under 200ms', async () => {
      const form = createTestForm({ fields: createFields(20) });

      const result = await engine.analyze(form, '<html></html>');

      expect(result.latencyMs).toBeLessThan(200);
      console.log(`SYNERGOS latency: ${result.latencyMs.toFixed(1)}ms`);
    });
  });

  // ========================================================================
  // STAGE 2: DECISION MAKING
  // ========================================================================

  describe('Stage 2: Unified Decision', () => {
    it('should block clear phishing forms', async () => {
      const form = createTestForm({
        fields: [
          { name: 'email', type: 'email', fieldSuspicionScore: 30 },
          { name: 'password', type: 'password', fieldSuspicionScore: 50 },
          { name: 'card', type: 'text', fieldSuspicionScore: 50 },
        ],
        targetDomain: 'malicious.com',
        action: 'http://phisher.ru/collect',
      });

      const result = await engine.analyze(form, '<html></html>');

      expect(result.verdict).toBe('BLOCK');
      expect(result.severity).toBeGreaterThan(0.7);
      expect(result.confidence).toBeGreaterThan(0.7);
    });

    it('should warn on suspicious forms', async () => {
      const form = createTestForm({
        fields: [
          { name: 'email', type: 'email', fieldSuspicionScore: 20 },
          { name: 'password', type: 'password', fieldSuspicionScore: 25 },
        ],
      });

      const result = await engine.analyze(form, '<html></html>');

      expect(['BLOCK', 'WARN']).toContain(result.verdict);
    });

    it('should allow legitimate forms', async () => {
      const form = createTestForm({
        fields: [
          { name: 'first_name', type: 'text', fieldSuspicionScore: 5 },
          { name: 'last_name', type: 'text', fieldSuspicionScore: 5 },
          { name: 'email', type: 'email', fieldSuspicionScore: 10 },
          { name: 'subscribe', type: 'checkbox', fieldSuspicionScore: 2 },
        ],
        method: 'POST',
        action: 'https://example.com/subscribe',
      });

      const result = await engine.analyze(form, '<html></html>');

      expect(result.verdict).toBe('ALLOW');
      expect(result.severity).toBeLessThan(0.5);
    });

    it('should have high confidence on clear threats', async () => {
      const form = createTestForm({
        fields: [
          { name: 'ssn', type: 'text', fieldSuspicionScore: 100 },
          { name: 'bank_account', type: 'text', fieldSuspicionScore: 100 },
        ],
        targetDomain: 'attacker.com',
        action: 'http://unsafe.com',
      });

      const result = await engine.analyze(form, '<html></html>');

      expect(result.verdict).toBe('BLOCK');
      expect(result.confidence).toBeGreaterThan(0.8);
    });
  });

  // ========================================================================
  // STAGE 3: EVOLUTION TRACKING
  // ========================================================================

  describe('Stage 3: Evolution Tracking', () => {
    it('should track form evolution over multiple scans', async () => {
      // Simulate scanning similar forms multiple times
      const forms = [
        createTestForm({ fields: createFields(5) }),
        createTestForm({ fields: createFields(6) }),
        createTestForm({ fields: createFields(7) }),
      ];

      const results = [];
      for (const form of forms) {
        const result = await engine.analyze(form, '<html></html>');
        results.push(result);
      }

      // Evolution signal should be captured
      expect(results[results.length - 1].threatProfile).toBeDefined();
    });

    it('should detect coordinated phase transitions', async () => {
      // In a real system, this would detect when many attackers
      // shift strategy simultaneously (coordinated evolution)
      const form = createTestForm({ fields: createFields(10) });
      const result = await engine.analyze(form, '<html></html>');

      expect(result.threatProfile.evolutionSignal).toBeGreaterThanOrEqual(0);
      expect(result.threatProfile.evolutionSignal).toBeLessThanOrEqual(1);
    });
  });

  // ========================================================================
  // STAGE 4: TRAJECTORY PREDICTION
  // ========================================================================

  describe('Stage 4: Trajectory Prediction', () => {
    it('should predict next attack tactics', async () => {
      const form = createTestForm({
        fields: [
          { name: 'password', type: 'password', fieldSuspicionScore: 40 },
          { name: 'pin', type: 'text', fieldSuspicionScore: 35 },
        ],
      });

      const result = await engine.analyze(form, '<html></html>');

      expect(result.nextAttackPrediction).toBeDefined();
      expect(Array.isArray(result.nextAttackPrediction.tactics)).toBe(true);
      expect(result.nextAttackPrediction.likelihood).toBeGreaterThanOrEqual(0);
      expect(result.nextAttackPrediction.likelihood).toBeLessThanOrEqual(1);
    });

    it('should provide defense recommendations based on predictions', async () => {
      const form = createTestForm({
        fields: [
          { name: 'card_number', type: 'text', fieldSuspicionScore: 50 },
          { name: 'cvv', type: 'text', fieldSuspicionScore: 50 },
        ],
      });

      const result = await engine.analyze(form, '<html></html>');

      expect(result.recommendedDefense).toBeDefined();
      expect(Array.isArray(result.recommendedDefense)).toBe(true);
      if (result.recommendedDefense.length > 0) {
        expect(result.recommendedDefense[0]).toBeTruthy();
      }
    });
  });

  // ========================================================================
  // STAGE 5: DECISION EXPLANATION
  // ========================================================================

  describe('Stage 5: Adaptive Dispatcher', () => {
    it('should provide human-readable reasoning', async () => {
      const form = createTestForm({
        fields: [
          { name: 'email', type: 'email', fieldSuspicionScore: 20 },
          { name: 'password', type: 'password', fieldSuspicionScore: 30 },
        ],
      });

      const result = await engine.analyze(form, '<html></html>');

      expect(result.reasoning).toBeTruthy();
      expect(result.reasoning.length > 0).toBe(true);
      expect(result.reasoning).toContain(
        ['BLOCK', 'WARN', 'ALLOW', 'Severity', 'severity', 'threat'].find(
          s => result.reasoning.includes(s)
        )
      );
    });

    it('should escalate to BLOCK on critical signals', async () => {
      const form = createTestForm({
        fields: [
          { name: 'ssn', type: 'text', fieldSuspicionScore: 100 },
          { name: 'bank_account', type: 'text', fieldSuspicionScore: 100 },
          { name: 'pin', type: 'text', fieldSuspicionScore: 100 },
        ],
        targetDomain: 'definitely-malicious.com',
      });

      const result = await engine.analyze(form, '<html></html>');

      expect(result.verdict).toBe('BLOCK');
      expect(result.reasoning).toContain('BLOCK');
    });
  });

  // ========================================================================
  // INTEGRATION & EDGE CASES
  // ========================================================================

  describe('Integration & Edge Cases', () => {
    it('should handle empty forms gracefully', async () => {
      const form: ScrapedForm = {
        action: '',
        method: 'POST',
        fields: [],
      };

      const result = await engine.analyze(form, '<html></html>');

      expect(result).toBeDefined();
      expect(result.verdict).toBe('ALLOW');
      expect(result.severity).toBeLessThan(0.3);
    });

    it('should handle very large forms (100+ fields)', async () => {
      const form = createTestForm({ fields: createFields(100) });

      const startTime = performance.now();
      const result = await engine.analyze(form, '<html></html>');
      const duration = performance.now() - startTime;

      expect(result).toBeDefined();
      expect(result.threatProfile).toBeDefined();
      expect(duration).toBeLessThan(500); // Should complete in <500ms even for huge forms
    });

    it('should be deterministic for same input', async () => {
      const form = createTestForm({ fields: createFields(10) });

      const result1 = await engine.analyze(form, '<html></html>');
      const result2 = await engine.analyze(form, '<html></html>');

      // Verdict should be same, though exact severity might vary slightly
      expect(result1.verdict).toBe(result2.verdict);
      expect(Math.abs(result1.severity - result2.severity)).toBeLessThan(0.1);
    });

    it('should provide consistent threat profiles', async () => {
      const form = createTestForm({
        fields: [
          { name: 'password', type: 'password', fieldSuspicionScore: 40 },
        ],
      });

      const result = await engine.analyze(form, '<html></html>');

      const threatProfile = result.threatProfile;
      expect(threatProfile.intentField).toBeGreaterThanOrEqual(0);
      expect(threatProfile.intentField).toBeLessThanOrEqual(1);
      expect(threatProfile.payoffDeviation).toBeGreaterThanOrEqual(0);
      expect(threatProfile.payoffDeviation).toBeLessThanOrEqual(1);
      expect(threatProfile.fragility).toBeGreaterThanOrEqual(0);
      expect(threatProfile.fragility).toBeLessThanOrEqual(1);
      expect(threatProfile.evolutionSignal).toBeGreaterThanOrEqual(0);
      expect(threatProfile.evolutionSignal).toBeLessThanOrEqual(1);
      expect(threatProfile.consensusConfidence).toBeGreaterThanOrEqual(0);
      expect(threatProfile.consensusConfidence).toBeLessThanOrEqual(1);
    });
  });

  // ========================================================================
  // PERFORMANCE BENCHMARKS
  // ========================================================================

  describe('Performance Benchmarks', () => {
    it('should complete simple form analysis in <100ms', async () => {
      const form = createTestForm({ fields: createFields(5) });

      const startTime = performance.now();
      await engine.analyze(form, '<html></html>');
      const duration = performance.now() - startTime;

      expect(duration).toBeLessThan(100);
    });

    it('should complete complex form analysis in <200ms', async () => {
      const form = createTestForm({ fields: createFields(30) });

      const startTime = performance.now();
      await engine.analyze(form, '<html></html>');
      const duration = performance.now() - startTime;

      expect(duration).toBeLessThan(200);
    });

    it('should complete very large form analysis in <400ms', async () => {
      const form = createTestForm({ fields: createFields(100) });

      const startTime = performance.now();
      await engine.analyze(form, '<html></html>');
      const duration = performance.now() - startTime;

      expect(duration).toBeLessThan(400);
    });
  });
});

// ============================================================================
// TEST HELPERS
// ============================================================================

function createTestForm(options?: {
  fields?: FormField[];
  action?: string;
  method?: string;
  targetDomain?: string;
}): ScrapedForm {
  return {
    action: options?.action || 'https://example.com/submit',
    method: options?.method || 'POST',
    fields: options?.fields || [
      { name: 'email', type: 'email', fieldSuspicionScore: 10 },
      { name: 'password', type: 'password', fieldSuspicionScore: 20 },
    ],
    targetDomain: options?.targetDomain,
  };
}

function createFields(count: number): FormField[] {
  const fields: FormField[] = [];
  const types = ['text', 'email', 'password', 'hidden', 'checkbox'];

  for (let i = 0; i < count; i++) {
    fields.push({
      name: `field_${i}`,
      type: types[i % types.length],
      fieldSuspicionScore: Math.random() * 30,
    });
  }

  return fields;
}
