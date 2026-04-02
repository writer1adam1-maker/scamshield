# Algorithm Factory - Behavioral Sandbox Perspectives

## Overview

This directory contains **proprietary algorithms** for behavioral threat detection in the ScamShield Website Vaccine system. These are original designs from multiple specialist perspectives, each combining unique mathematical and conceptual frameworks.

## Structure

```
perspectives/
├── agent_1_math_nature.md         [Mathematician + Naturalist]
│   └── Information-theoretic signatures + biological mimicry
├── agent_2_physics_game.md         [Physicist + Game Theorist]
│   └── Field theory + strategic equilibrium analysis
├── agent_3_info_engineer.md        [Information Theorist + Architect]
│   └── Entropy-based anomaly detection + systems engineering
└── README.md (this file)
```

## Quick Reference

### Agent 2 (Physics & Game Theory) - What's Here

**4 Original Algorithms:**

1. **Intent Field Analyzer** — Treat malicious intent as conserved energy flowing through forms. Legitimate forms diffuse energy; hostile forms concentrate it at exfiltration points.
   - Time: O(N log N) | Space: O(N)
   - Detects: Novel phishing variants without knowing obfuscation technique

2. **Adversarial Payoff Reconstruction** — Invert attacker optimization. Observed form = best response to our defense. Detect non-Nash forms as zero-day signals.
   - Time: O(N² · iterations) | Space: O(N²)
   - Detects: Strategic deviations revealing new attack strategies

3. **Behavioral Phase Transition Tracker** — Model attacker population as physical system. Detect when they undergo collective phase transition (sharp reorganization).
   - Time: O(M log M) | Space: O(M)
   - Detects: Coordinated evolution, shared threat intelligence

4. **Deception Cascade Fragility Index** — Measure redundancy and critical points in deception strategy. Identify which tricks matter most.
   - Time: O(N² + T·M) | Space: O(N²)
   - Detects: Structural weaknesses, optimal defense targets

### When to Use Each

| Algorithm | Best For | Speed | Confidence |
|-----------|----------|-------|-----------|
| Intent Field | Form structure anomalies | 45ms-1.2s | MEDIUM-HIGH |
| Adversarial Payoff | Novel variants, zero-days | 50-2s | HIGH |
| Phase Transition | Coordinated attacks | 50-100ms | HIGH (low FP) |
| Cascade Fragility | Defense optimization | 100ms-4s | MEDIUM (structural) |

### Integration with VERIDICT

These algorithms operate as **behavioral modules** complementing VERIDICT's signature-based approach:

```
VERIDICT Layer 1-3 (Signature-based):
  └─ Fast, high-confidence on known patterns

Behavioral Sandbox (These algorithms):
  └─ Slower, structural reasoning
  └─ Catches novel patterns
  └─ Feeds evidence to VERIDICT Layer 4 (Immune System)
```

## Implementation Roadmap

**Phase 1 (MVP):** Intent Field Analyzer
- ~200 lines TypeScript
- 100-150ms latency
- Integrate into existing vaccine injection

**Phase 2:** Adversarial Payoff Reconstruction
- ~300 lines + math library (numeric.js)
- 150-250ms latency
- Requires training data on attack strategies

**Phase 3:** Phase Transition Tracker
- ~400 lines + time-series analysis
- 50ms per window (1hr aggregation)
- Requires historical form variants database

**Phase 4:** Advanced variants
- Critical exponent estimation, cognitive load analysis
- Research/optimization use only

## Key Design Principles

1. **Structural Reasoning** — Detect what attacks *must* do to function, not what they happen to look like
2. **Multi-Perspective** — Each agent brings orthogonal detection capability; no single evasion defeats all
3. **Physics-Based** — Use field theory, thermodynamics, phase transitions as computational primitives
4. **Game-Theoretic** — Model attacker as rational agent optimizing against our defense
5. **Adaptive** — Algorithms evolve with attacker ecosystem without retraining monolithic models

## Complexity & Performance

### Real-Time Budget
Target: <4 seconds (Vercel Edge Runtime)

**Recommended allocation:**
- Intent Field: 500-1000ms
- Adversarial Payoff: 1000-2000ms (conditional)
- Phase Transition: 50-100ms (background batch)
- Cascade Fragility: 100-500ms (optional, for complex forms)

### Scaling
- Intent Field: Handles 50-200 field forms in real-time; 1000+ fields requires approximation
- Adversarial Payoff: Performance degrades with feature count (5-10 features optimal, 20+ features ~2s)
- Phase Transition: Batch operation; minimal real-time overhead
- Cascade Fragility: Full ablation expensive; use fast approximation for real-time

## Blind Spots & Mitigations

| Blind Spot | Mitigation |
|-----------|-----------|
| Distributed intent across endpoints | Combine with threat intelligence + domain reputation |
| Non-rational attackers | Add quantal response noise term to payoff model |
| Latency on complex forms | Warm-start relaxation + caching from previous sessions |
| Novel trick types | Intent field still detects energy concentration |
| False positives on legitimate apps | Behavioral baseline per domain |

## Testing & Validation

For each algorithm:
1. **Unit tests** — Verify core mechanics on synthetic forms
2. **Integration tests** — Test with real phishing dataset
3. **Ablation tests** — Remove components, measure impact
4. **Baseline comparison** — Compare against signature-based and ML approaches
5. **False positive analysis** — Evaluate on legitimate banking/SaaS forms

## References

**Physics Foundations:**
- Goldstein, *Classical Mechanics* (2002)
- Landau & Lifshitz, *Statistical Physics* (1980)
- Phase transition theory, critical phenomena

**Game Theory Foundations:**
- Von Neumann & Morgenstern, *Theory of Games* (1944)
- Myerson, *Game Theory: Analysis of Conflict* (1991)
- Maynard Smith, *Evolution and Theory of Games* (1982)

**Cybersecurity:**
- VERIDICT Algorithm (ScamShield, 2026)
- Website Vaccine System (ScamShield, 2026)

## Classification

**Proprietary & Confidential**
- Not for external distribution
- Trade-secret level IP
- Use within ScamShield only

## Contact & Support

For implementation questions or improvements:
- Review full algorithm docs in agent_2_physics_game.md
- Check ALGORITHMS_SUMMARY.txt for quick reference
- See comments in algorithm implementations for detailed mechanics

---

**Status:** Design Document (Ready for implementation)
**Last Updated:** 2026-04-02
**Version:** 1.0.0
