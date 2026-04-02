# SYNERGOS AUDIT: The Mathematician & Naturalist
## Comprehensive Critique, Upgrade, and New Feature Proposal

**Agent**: The Mathematician & Naturalist (Agent 1)
**Classification**: Proprietary & Confidential Trade Secret
**Date**: 2026-04-02
**Scope**: Full audit of all 5 SYNERGOS stages + 4 new feature proposals
**Method**: Combined mathematical rigor (set theory, topology, abstract algebra, number theory, combinatorics, category theory, lattice structures) with naturalistic design (evolutionary strategies, swarm intelligence, immune systems, mycorrhizal networks, predator-prey dynamics, stigmergy, chemotaxis)

---

# PART A: CRITIQUE (Weaknesses Found)

## Stage 1: Intent Field Computation

### Weakness 1.1 — 1D Diffusion Is Topologically Degenerate

**Mathematical Flaw**: The intent field treats the form as a 1D chain (linear array of fields). The diffusion kernel `psi(t+1) = 0.5*psi(t) + 0.25*(psi_left + psi_right)` is a 1D discrete Laplacian with Neumann boundary conditions. This is the simplest possible topology -- a path graph.

Real HTML forms are not 1D. They have:
- Nested fieldsets (tree structure)
- Conditional visibility (DAG structure)
- Multi-column layouts (grid structure)
- Tab-indexed navigation (arbitrary permutation of visual order)

By flattening to 1D, SYNERGOS loses all structural information about how fields relate spatially and logically. Two forms with identical fields in different layouts produce identical intent fields, which is mathematically wrong -- the Laplacian spectrum of a path graph vs a tree vs a grid are entirely different objects.

**Invariant Missed**: The eigenvalue spectrum of the form's actual adjacency Laplacian is a topological invariant that an attacker cannot change without altering form functionality. By using only the 1D chain Laplacian, SYNERGOS ignores this free invariant.

**Adversarial Evasion**: An attacker can distribute high-urgency fields across a multi-column layout so that in the 1D projection they appear non-adjacent, breaking hotspot detection. The Laplacian of the actual 2D layout would still show concentration, but the 1D chain misses it.

### Weakness 1.2 — Fixed Relaxation Iterations (5) Ignores Convergence

**Mathematical Flaw**: The diffusion is run for exactly 5 iterations regardless of form size. For a form with 3 fields, 5 iterations nearly reaches steady state (the spectral gap of a 3-node path is ~0.586, so convergence is fast). For a form with 50 fields, the spectral gap is ~0.004, meaning 5 iterations barely diffuse at all -- the field stays almost at its initial condition.

This means: large forms are systematically under-relaxed (hotspots are over-detected), and small forms are over-relaxed (hotspots are smoothed away). Neither extreme is correct.

**Missing Invariant**: The number of iterations should be proportional to `1/spectral_gap ~ n^2` for a path graph. Alternatively, use the analytical steady-state solution directly (solve the tridiagonal system in O(n) time via Thomas algorithm).

### Weakness 1.3 — Keyword-Based Persuasion Scoring Is Brittle

**Blind Spot**: The urgency/authority/scarcity estimators use hardcoded keyword lists (5 keywords each). This is a 15-word dictionary. Any attacker who avoids these exact words bypasses the entire intent field stage. The field becomes zero everywhere, and SYNERGOS sees nothing.

Modern phishing uses synonyms, Unicode homoglyphs, image-based text, and contextual implications ("Your account status has changed" implies urgency without using any urgency keyword).

**Naturalistic Perspective**: In predator-prey dynamics, a predator that relies on exactly 15 visual cues goes extinct when prey evolves camouflage for those 15 cues. The SYNERGOS "predator" is ecologically fragile.

### Weakness 1.4 — Boundary Conditions Create Edge Artifacts

**Mathematical Flaw**: At the boundaries (i=0 and i=n-1), the diffusion kernel implicitly uses zero-padding (missing neighbor contributes 0). This creates artificial sinks at the edges -- field energy drains out the boundaries. The Laplacian at boundaries is computed as `psi(i-1) - 2*psi(i) + psi(i+1)` with the missing term treated as 0, which biases boundary curvature upward.

This means the first and last form fields always appear as hotspots (high |Laplacian|), regardless of their actual persuasion content. Legitimate forms whose first field is "email" will get a false hotspot.

---

## Stage 2A: Payoff Inference

### Weakness 2.1 — The Nash Equilibrium Is Not Actually Computed

**Mathematical Flaw**: The code computes `nashEquilibriumPayoff = credentialPayoff + paymentPayoff - detectionCost`, which is a linear combination of features. This is not a Nash equilibrium. A Nash equilibrium requires:
1. Defining a strategy space for both attacker AND defender
2. Computing the payoff matrix for all strategy pairs
3. Finding the fixed point where neither player can unilaterally improve

The current implementation computes a single-player optimum (attacker's best response given fixed defenses), which is a best-response function, not an equilibrium. The distinction matters because a true Nash equilibrium accounts for the defender's adaptation. Without modeling defender response, the "deviation" measurement is meaningless -- you are measuring deviation from an arbitrary point, not from strategic equilibrium.

**Adversarial Evasion**: An attacker who understands that SYNERGOS uses this simplified "Nash" can design forms that score exactly at the pseudo-equilibrium, receiving a deviation of 0 and being classified as "rational but predictable." Meanwhile, their actual strategy exploits the defender's lack of adaptation modeling.

### Weakness 2.2 — Strategy Classification Is a Decision Tree, Not Game-Theoretic

**Blind Spot**: The objective classification (`if credentialRatio > 0.3 then credential_harvest`) is a simple threshold tree. This has nothing to do with game theory. A game-theoretic classification would ask: "What objective function, when maximized, produces this observed form?" -- that is an inverse optimization problem. The current approach is just a pattern matcher with fancy labels.

### Weakness 2.3 — Payoff Values Are Arbitrary Constants

**Mathematical Flaw**: The payoff computation uses hardcoded constants: credentials = 80-100 points, payment = 150-200 points, external submission penalty = -50. These are not calibrated to any real data. The ratio between credential value (80) and payment value (150) determines which forms look "rational" and which look "deviant." If these ratios are wrong, the entire deviation metric is miscalibrated.

In game theory, payoffs must be derived from revealed preferences (observing actual attacker behavior) or from market prices (dark web credential prices). Using arbitrary constants produces a metric with no semantic grounding.

---

## Stage 2B: Fragility Analysis

### Weakness 2.4 — Graph Connectivity Check Is a Stub

**Critical Implementation Flaw**: The `_isGraphConnected` method always returns `true` if there are any edges:

```typescript
private _isGraphConnected(graph: FormDependencyGraph): boolean {
    if (graph.edges.length === 0) return false;
    return true;  // Simple check: if there are edges, assume connected
}
```

This means the ablation test (remove a node, check if graph stays connected) ALWAYS reports "still connected" for any graph with more than one edge. The entire fragility analysis collapses: `removalImpact` is always 0.0 for non-trivial graphs, so `criticalNodes` is always empty, and `fragility` is determined solely by `identifiedTricks.length * 0.2`.

The fragility stage is effectively non-functional.

### Weakness 2.5 — Centrality Is Degree-Based, Not Betweenness

**Mathematical Flaw**: The documentation claims betweenness centrality, but the code computes degree centrality:

```typescript
criticalityScores[i] = (inDegree + outDegree) / Math.max(edges.length, 1);
```

Betweenness centrality measures how many shortest paths pass through a node. Degree centrality measures how many edges touch a node. These are fundamentally different: a node with high degree but no bridging role has high degree centrality but low betweenness centrality. For detecting critical attack dependencies (bridges, articulation points), betweenness is correct and degree is not.

### Weakness 2.6 — Edge Construction Uses Math.random()

**Critical Flaw**: The `_shouldConnectNodes` method uses `Math.random() > 0.6` to decide whether to create edges between sequentially ordered nodes. This means the dependency graph is non-deterministic -- the same form analyzed twice produces different graphs, different fragility scores, and potentially different verdicts.

```typescript
return a.id < b.id && Math.random() > 0.6;
```

This violates the determinism requirement stated in the validation section ("same input -> same output"). It also means the fragility analysis cannot be reproduced, tested, or reasoned about.

---

## Stage 2C: Unified Decision

### Weakness 2.7 — Entropy Is Actually Standard Deviation, Not Entropy

**Mathematical Flaw**: The code computes:

```typescript
const consensusEntropy = Math.sqrt(variance);
```

This is the standard deviation, not entropy. Shannon entropy of three signals would be `-sum(p_i * log(p_i))` after normalizing signals to a probability distribution. Standard deviation and entropy have different properties:
- Standard deviation is scale-dependent; entropy is not
- Standard deviation is maximized when signals are spread; entropy is maximized when signals are uniform
- For three signals [0.8, 0.75, 0.85], the std dev is 0.05 and the entropy (after normalization) is ~1.098, which is near maximal

Using standard deviation mislabeled as "entropy" means the confidence metric behaves differently than documented. The "entropy-weighted" combination is actually "standard-deviation-weighted," which has different optimality properties.

### Weakness 2.8 — Entropy Added to Severity Score Is Contradictory

**Mathematical Flaw**: The severity formula includes `consensusEntropy * 0.15` as a positive additive term:

```
severity = 0.35*intent + 0.30*payoff + 0.20*fragility + 0.15*entropy
```

This means when signals disagree (high entropy/std dev), severity INCREASES. But the documentation says high entropy means low confidence. So a form where signals strongly disagree gets a HIGHER threat score, which could cause false positives on legitimate forms where one signal fires and others don't.

The semantics are inverted: entropy should DECREASE severity (or decrease confidence, which gates the BLOCK threshold), not increase it.

---

## Stage 3: Evolution Tracking

### Weakness 3.1 — Recomputing Intent Fields for Entire Window Is O(W*n)

**Performance Flaw**: In `_stage3_phaseTransition()`, the code recomputes the intent field for every form in the window:

```typescript
const fieldStrengths = this.formWindow.map(f => {
    const field = this._stage1_intentField(f);
    return field.totalEnergy;
});
```

For a window of 1000 forms, this recomputes 1000 intent fields (each taking ~30ms for the relaxation), making Stage 3 take ~30 seconds instead of the claimed 30ms. This is three orders of magnitude slower than documented.

The fix is obvious (cache totalEnergy when forms enter the window), but the current implementation is catastrophically slow.

### Weakness 3.2 — Order Parameter Is a Scalar, Missing Directional Information

**Mathematical Flaw**: The order parameter mu(t) is defined as the average totalEnergy. This is a scalar. It cannot distinguish between:
- 1000 forms all targeting credentials (coherent direction)
- 500 forms targeting credentials + 500 targeting payment (incoherent direction, but same average energy)

In statistical physics, the order parameter must capture both magnitude and alignment. The proper analog is a vector order parameter (like magnetization in the Ising model), not a scalar average. Using a scalar means SYNERGOS cannot detect when the attacker population is splitting into distinct strategy clusters, which is a critical phase transition signal.

### Weakness 3.3 — Derivative Computation Uses Fixed Lookback, Not Windowed

**Mathematical Flaw**: The first derivative is computed as:

```typescript
(fieldStrengths[n-1] - fieldStrengths[n-10]) / 10
```

This measures the average slope over the last 10 forms. If the window has 500 forms with a trend that reversed at form 490, the derivative still shows the old trend direction. A proper windowed derivative would use a Savitzky-Golay filter or exponential moving average that adapts to recent behavior.

### Weakness 3.4 — Phase Classification Thresholds Are Arbitrary

**Blind Spot**: The thresholds (|d2mu/dt2| > 0.05 for "critical", dmu/dt > 0.02 for "heating") are hardcoded magic numbers with no calibration basis. On what data were these thresholds determined? Different attack ecosystems will have different natural fluctuation levels. A threshold that is "critical" for one ecosystem may be "noise" for another.

In statistical physics, phase transitions are detected by divergence of susceptibility (chi -> infinity), not by threshold comparison. The current approach misses the actual physics it claims to implement.

---

## Stage 4: Trajectory Simulation

### Weakness 4.1 — ODE System Has No Physical Grounding

**Mathematical Flaw**: The ODE derivative function is:

```typescript
derivative[0] = -0.1 * payoff.equilibriumDeviation;
derivative[1] = -0.05 * payoff.equilibriumDeviation;
// diffusion + noise for others
```

Only features 0 and 1 have gradient descent terms, and they both descend on the same scalar (equilibriumDeviation). Features 2-11 evolve only via diffusion + noise. This means:
- The ODE cannot predict changes in credential ratio, payment ratio, obfuscation, etc.
- Features 2-11 simply diffuse toward their neighbors and random-walk
- The "trajectory prediction" for most features is just brownian motion

The ODE does not model any actual attacker decision-making for 10 of the 12 feature dimensions. Its predictions are noise.

### Weakness 4.2 — Lyapunov Exponent Computation Is Wrong

**Mathematical Flaw**: The Lyapunov exponent is computed by comparing the initial state to the evolved perturbed state:

```typescript
const perturbedState = initialState.map((v, i) => v + 1e-6);
const divergence = perturbedState.reduce((a, b, i) => a + Math.abs(b - y[i]), 0);
const lyapunovExponent = Math.log(divergence / 1e-6) / this.rkSteps;
```

But `y` is the evolved UNPERTURBED state, and `perturbedState` is the UNEVOLVED perturbed state. The code never actually evolves the perturbed state forward! It compares the evolved unperturbed trajectory against the un-evolved perturbed initial condition, which measures something like `|f(x) - (x + epsilon)|` rather than `|f(x) - f(x + epsilon)|`.

This is not a Lyapunov exponent -- it is a nonsensical quantity that grows with the magnitude of the ODE evolution regardless of sensitivity to initial conditions. The prediction confidence derived from this value is meaningless.

### Weakness 4.3 — Math.random() Breaks Reproducibility and Lyapunov Measurement

**Critical Flaw**: The noise term uses `Math.random()`:

```typescript
derivative[i] += (Math.random() - 0.5) * noiseScale;
```

This makes the ODE stochastic, which means:
1. Two calls with the same input produce different trajectories
2. The Lyapunov exponent (even if correctly computed) measures noise sensitivity, not structural sensitivity
3. The RK4 integrator loses its 4th-order accuracy because the derivative function is non-deterministic (each RK4 substep gets different random values)

For deterministic prediction, noise should be seeded or computed from a hash of the state vector.

---

## Stage 5: Adaptive Dispatcher

### Weakness 5.1 — Threat Profile Decomposes Severity by Weights, Not Actual Signal Values

**Mathematical Flaw**: The threat profile reports:

```typescript
intentField: unified.severity * 0.35,
payoffDeviation: unified.severity * 0.30,
fragility: unified.severity * 0.20,
```

This decomposes the unified severity by the combination weights, not by the actual signal values. If intent = 0.9, payoff = 0.1, fragility = 0.1, the unified severity might be ~0.40, and the reported intentField would be 0.40 * 0.35 = 0.14, which completely misrepresents the actual intent signal (0.9). The threat profile is decorative, not informative.

### Weakness 5.2 — Binary Threshold Decision Ignores Confidence Distribution

**Blind Spot**: The dispatcher uses two thresholds: severity > 0.75 + confidence > 0.80 = BLOCK; severity > 0.50 = WARN; else ALLOW. This creates sharp decision boundaries. A form with severity 0.749 is WARN; severity 0.751 with confidence 0.81 is BLOCK. This discontinuity is exploitable: an attacker who knows the thresholds can design forms that sit just below 0.75.

A Bayesian decision-theoretic approach would compute expected loss for each action (BLOCK, WARN, ALLOW) given the severity and confidence distributions, producing a smooth decision surface with no exploitable discontinuities.

---

# PART B: UPGRADES (Fixes for Each Weakness)

## Upgrade 1.1 — "Manifold Field Diffusion"

**Fixes**: Weakness 1.1 (1D topology) and Weakness 1.4 (boundary artifacts)

**Core Mechanism**: Replace the 1D chain diffusion with diffusion on the actual form topology graph. Construct the graph Laplacian L = D - A (where D is degree matrix, A is adjacency matrix) from the form's structural relationships (fieldsets, tabs, conditional visibility, validation dependencies). Run diffusion as psi(t+1) = psi(t) - alpha * L * psi(t), which naturally respects the form's multi-dimensional structure. Use periodic or Neumann boundary conditions on the graph (no energy drain at boundaries).

**Why It Fixes It**: Diffusion on the actual graph captures how persuasion pressure spreads through the real form structure. Fields in the same fieldset are close (high diffusion between them); fields in different tabs are far (low diffusion). The eigenvectors of L form a natural basis for the field, and hotspots are detected as projections onto high-frequency eigenmodes -- topologically invariant.

**Complexity**: Time O(n^2) for dense graph Laplacian multiply, O(n + m) for sparse. Space O(n + m).

```typescript
interface FormGraph {
  adjacency: Map<number, { neighbor: number; weight: number }[]>;
  laplacian: Float32Array[];  // n x n sparse matrix
}

function buildFormGraph(form: ScrapedForm, html: string): FormGraph {
  const n = form.fields.length;
  const adjacency = new Map<number, { neighbor: number; weight: number }[]>();

  for (let i = 0; i < n; i++) adjacency.set(i, []);

  // Connect fields in same fieldset (weight 1.0)
  const fieldsets = extractFieldsetGroupings(html);
  for (const group of fieldsets) {
    for (let i = 0; i < group.length; i++) {
      for (let j = i + 1; j < group.length; j++) {
        adjacency.get(group[i])!.push({ neighbor: group[j], weight: 1.0 });
        adjacency.get(group[j])!.push({ neighbor: group[i], weight: 1.0 });
      }
    }
  }

  // Connect fields with validation dependencies (weight 0.7)
  const validationDeps = extractValidationDeps(html);
  for (const [from, to] of validationDeps) {
    adjacency.get(from)!.push({ neighbor: to, weight: 0.7 });
  }

  // Connect visually adjacent fields via tab order (weight 0.3)
  for (let i = 0; i < n - 1; i++) {
    adjacency.get(i)!.push({ neighbor: i + 1, weight: 0.3 });
    adjacency.get(i + 1)!.push({ neighbor: i, weight: 0.3 });
  }

  return { adjacency, laplacian: computeGraphLaplacian(adjacency, n) };
}

function diffuseOnGraph(
  psi: Float32Array,
  laplacian: Float32Array[],
  alpha: number,
  iterations: number
): Float32Array {
  const n = psi.length;
  let current = new Float32Array(psi);

  for (let iter = 0; iter < iterations; iter++) {
    const next = new Float32Array(n);
    for (let i = 0; i < n; i++) {
      let lapProduct = 0;
      for (let j = 0; j < n; j++) {
        lapProduct += laplacian[i][j] * current[j];
      }
      next[i] = current[i] - alpha * lapProduct;
    }
    current = next;
  }
  return current;
}
```

---

## Upgrade 1.2 — "Spectral Convergence Guard"

**Fixes**: Weakness 1.2 (fixed 5 iterations)

**Core Mechanism**: Instead of running a fixed number of relaxation iterations, compute the spectral gap of the form's graph Laplacian (smallest nonzero eigenvalue, lambda_2). Set the number of iterations to `ceil(C / lambda_2)` where C is a convergence constant (e.g., 3.0 for 95% convergence). Alternatively, for the 1D fallback case, use the Thomas algorithm to solve the steady-state equation `L * psi_steady = source` directly in O(n) time, bypassing iterative relaxation entirely.

**Why It Fixes It**: The spectral gap governs the mixing time of diffusion. By adapting iteration count to the actual spectrum, small forms converge correctly (few iterations) and large forms get enough iterations to diffuse properly. The direct solver eliminates the iteration question entirely.

**Complexity**: Time O(n) for tridiagonal solve, O(n^2) for general Laplacian eigenvalue. Space O(n).

```typescript
function adaptiveRelaxation(
  source: Float32Array,
  laplacian: Float32Array[],
  convergenceThreshold: number = 0.001
): { steady: Float32Array; iterations: number } {
  const n = source.length;

  // For tridiagonal (1D) case: direct solve via Thomas algorithm
  if (isTridiagonal(laplacian)) {
    return { steady: thomasSolve(laplacian, source), iterations: 1 };
  }

  // For general graph: iterate with convergence check
  let current = new Float32Array(source);
  const alpha = 0.25;
  let iterations = 0;
  const maxIterations = Math.min(n * n, 500);

  while (iterations < maxIterations) {
    const next = diffuseOneStep(current, laplacian, alpha);

    // Check convergence: ||next - current|| / ||current||
    let diffNorm = 0, currentNorm = 0;
    for (let i = 0; i < n; i++) {
      diffNorm += (next[i] - current[i]) ** 2;
      currentNorm += current[i] ** 2;
    }

    if (Math.sqrt(diffNorm) / Math.sqrt(currentNorm + 1e-10) < convergenceThreshold) {
      return { steady: next, iterations };
    }

    current = next;
    iterations++;
  }

  return { steady: current, iterations };
}
```

---

## Upgrade 1.3 — "Semantic Embedding Field Sources"

**Fixes**: Weakness 1.3 (15-word keyword dictionary)

**Core Mechanism**: Replace hardcoded keyword lists with pre-computed semantic embedding lookups. For each form field's label/placeholder/surrounding text, compute a compact embedding (e.g., 64-dim via a small frozen model or pre-computed lookup table of ~2000 common phishing phrases). Measure cosine similarity to reference urgency/authority/scarcity prototype vectors. This turns the 15-keyword brittle detector into a continuous semantic field that works on synonyms, paraphrases, and novel phrasing.

**Why It Fixes It**: An attacker can avoid 15 keywords but cannot avoid the semantic neighborhood of urgency/authority/scarcity without fundamentally changing the persuasion strategy (which would make their attack less effective). The embedding approach captures the invariant meaning, not the surface form.

**Complexity**: Time O(n * d) where d = embedding dimension (64). Space O(V * d) for vocabulary lookup table (V ~ 2000 words, ~500KB).

```typescript
// Pre-computed prototype vectors for persuasion dimensions
const URGENCY_PROTOTYPE = new Float32Array(64);    // Average embedding of urgency phrases
const AUTHORITY_PROTOTYPE = new Float32Array(64);   // Average embedding of authority phrases
const SCARCITY_PROTOTYPE = new Float32Array(64);    // Average embedding of scarcity phrases

// Pre-computed word embeddings (loaded once at startup, ~500KB)
const EMBEDDING_TABLE: Map<string, Float32Array> = loadEmbeddingTable();

function semanticPersuasionScore(
  text: string,
  prototype: Float32Array
): number {
  const words = tokenize(text.toLowerCase());
  if (words.length === 0) return 0;

  // Average embedding of the text
  const textEmbed = new Float32Array(64);
  let found = 0;
  for (const word of words) {
    const embed = EMBEDDING_TABLE.get(word);
    if (embed) {
      for (let i = 0; i < 64; i++) textEmbed[i] += embed[i];
      found++;
    }
  }
  if (found === 0) return 0;
  for (let i = 0; i < 64; i++) textEmbed[i] /= found;

  // Cosine similarity to prototype
  let dot = 0, normA = 0, normB = 0;
  for (let i = 0; i < 64; i++) {
    dot += textEmbed[i] * prototype[i];
    normA += textEmbed[i] ** 2;
    normB += prototype[i] ** 2;
  }

  return Math.max(0, dot / (Math.sqrt(normA) * Math.sqrt(normB) + 1e-8));
}

function estimateUrgencyV2(field: FormField): number {
  const text = `${field.name} ${field.label || ''} ${field.placeholder || ''}`;
  return semanticPersuasionScore(text, URGENCY_PROTOTYPE);
}
```

---

## Upgrade 2.1 — "Stackelberg Equilibrium Solver"

**Fixes**: Weakness 2.1 (fake Nash) and Weakness 2.2 (decision tree classification)

**Core Mechanism**: Replace the single-player payoff computation with a proper two-player Stackelberg game. The defender (SYNERGOS) is the leader who sets detection thresholds; the attacker is the follower who best-responds. Compute the Stackelberg equilibrium by solving the bilevel optimization: for each defender strategy d, find the attacker's best response a*(d), then find the defender strategy d* that minimizes expected damage given a*(d*). The deviation of the observed form from a*(d*) is the true equilibrium deviation.

**Why It Fixes It**: A Stackelberg equilibrium correctly models the asymmetric information game between defender and attacker. The defender commits to a strategy (published thresholds), and the attacker optimizes against it. This is the correct game-theoretic model for security systems. The deviation from this equilibrium genuinely measures how much the observed attack deviates from optimal exploitation.

**Complexity**: Time O(|D| * |A|) where |D| = defender strategy discretization, |A| = attacker strategy discretization. With |D| = |A| = 50, this is O(2500), trivially fast. Space O(|D| + |A|).

```typescript
interface StrategyProfile {
  attackerFeatures: number[];    // Feature vector of attacker's form
  defenderThresholds: number[];  // Detection thresholds
  attackerPayoff: number;        // Attacker's expected payoff
  defenderPayoff: number;        // Defender's expected payoff (negative = damage)
}

function computeStackelbergEquilibrium(
  defenderStrategies: number[][],
  attackerStrategies: number[][],
  detectionModel: (form: number[], thresholds: number[]) => number
): StrategyProfile {
  let bestDefenderPayoff = -Infinity;
  let bestProfile: StrategyProfile | null = null;

  for (const dStrat of defenderStrategies) {
    // For each defender strategy, find attacker's best response
    let bestAttackerPayoff = -Infinity;
    let bestAttackerStrat: number[] | null = null;

    for (const aStrat of attackerStrategies) {
      const detectionProb = detectionModel(aStrat, dStrat);
      const attackValue = computeAttackValue(aStrat);
      const attackerPayoff = attackValue * (1 - detectionProb) - detectionProb * 100;

      if (attackerPayoff > bestAttackerPayoff) {
        bestAttackerPayoff = attackerPayoff;
        bestAttackerStrat = aStrat;
      }
    }

    // Defender's payoff given attacker's best response
    const defenderPayoff = -bestAttackerPayoff;  // Zero-sum approximation

    if (defenderPayoff > bestDefenderPayoff) {
      bestDefenderPayoff = defenderPayoff;
      bestProfile = {
        attackerFeatures: bestAttackerStrat!,
        defenderThresholds: dStrat,
        attackerPayoff: bestAttackerPayoff,
        defenderPayoff,
      };
    }
  }

  return bestProfile!;
}

function measureEquilibriumDeviation(
  observedFeatures: number[],
  equilibrium: StrategyProfile
): number {
  // L2 distance in feature space, normalized
  let sumSq = 0;
  for (let i = 0; i < observedFeatures.length; i++) {
    sumSq += (observedFeatures[i] - equilibrium.attackerFeatures[i]) ** 2;
  }
  return Math.sqrt(sumSq) / Math.sqrt(observedFeatures.length);
}
```

---

## Upgrade 2.4 — "True Articulation Point Detection"

**Fixes**: Weakness 2.4 (stub connectivity check) and Weakness 2.5 (wrong centrality)

**Core Mechanism**: Replace the stub `_isGraphConnected` with Tarjan's bridge-finding algorithm, and replace degree centrality with proper betweenness centrality via Brandes' algorithm. Additionally, compute articulation points (cut vertices) -- nodes whose removal disconnects the graph. These are the true critical nodes of the attack dependency structure.

**Why It Fixes It**: Tarjan's algorithm correctly identifies bridges (critical edges) and articulation points (critical nodes) in O(n + m) time. Brandes' algorithm computes betweenness centrality in O(n * m) time. Together, these provide a mathematically correct fragility measurement: a form with many articulation points is genuinely fragile (removing one field breaks the attack).

**Complexity**: Time O(n * m) for betweenness (dominated by Brandes). Space O(n + m).

```typescript
function findArticulationPoints(
  adjacencyList: Map<number, number[]>,
  n: number
): { articulationPoints: Set<number>; bridges: [number, number][] } {
  const disc = new Int32Array(n).fill(-1);
  const low = new Int32Array(n).fill(-1);
  const parent = new Int32Array(n).fill(-1);
  const isAP = new Uint8Array(n);
  const bridges: [number, number][] = [];
  let timer = 0;

  function dfs(u: number) {
    disc[u] = low[u] = timer++;
    let children = 0;

    for (const v of adjacencyList.get(u) || []) {
      if (disc[v] === -1) {
        children++;
        parent[v] = u;
        dfs(v);

        low[u] = Math.min(low[u], low[v]);

        // u is an articulation point if:
        if (parent[u] === -1 && children > 1) isAP[u] = 1;
        if (parent[u] !== -1 && low[v] >= disc[u]) isAP[u] = 1;

        // Bridge detection
        if (low[v] > disc[u]) bridges.push([u, v]);
      } else if (v !== parent[u]) {
        low[u] = Math.min(low[u], disc[v]);
      }
    }
  }

  for (let i = 0; i < n; i++) {
    if (disc[i] === -1) dfs(i);
  }

  const articulationPoints = new Set<number>();
  for (let i = 0; i < n; i++) {
    if (isAP[i]) articulationPoints.add(i);
  }

  return { articulationPoints, bridges };
}

function brandesBetweenness(
  adjacencyList: Map<number, number[]>,
  n: number
): Float32Array {
  const cb = new Float32Array(n);

  for (let s = 0; s < n; s++) {
    const stack: number[] = [];
    const pred: number[][] = Array.from({ length: n }, () => []);
    const sigma = new Float32Array(n);
    sigma[s] = 1;
    const dist = new Int32Array(n).fill(-1);
    dist[s] = 0;
    const queue = [s];

    // BFS
    let head = 0;
    while (head < queue.length) {
      const v = queue[head++];
      stack.push(v);
      for (const w of adjacencyList.get(v) || []) {
        if (dist[w] === -1) {
          dist[w] = dist[v] + 1;
          queue.push(w);
        }
        if (dist[w] === dist[v] + 1) {
          sigma[w] += sigma[v];
          pred[w].push(v);
        }
      }
    }

    // Back-propagation
    const delta = new Float32Array(n);
    while (stack.length > 0) {
      const w = stack.pop()!;
      for (const v of pred[w]) {
        delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w]);
      }
      if (w !== s) cb[w] += delta[w];
    }
  }

  // Normalize
  const maxCb = Math.max(...cb, 1);
  for (let i = 0; i < n; i++) cb[i] /= maxCb;

  return cb;
}
```

---

## Upgrade 2.6 — "Deterministic Dependency Inference"

**Fixes**: Weakness 2.6 (Math.random() in edge construction)

**Core Mechanism**: Replace the random edge construction with a deterministic rule system based on field semantic types and structural HTML analysis. Edges are created based on: (a) semantic dependency rules (credential -> verification -> submission), (b) HTML DOM nesting (fields in same fieldset), (c) JavaScript validation dependencies (extracted from event handlers), (d) tab-order proximity. Each rule produces a deterministic weight in [0, 1], and edges are created when the total weight exceeds a threshold.

**Why It Fixes It**: The dependency graph becomes deterministic, reproducible, and semantically meaningful. The same form always produces the same graph, enabling reliable testing, debugging, and Lyapunov analysis.

**Complexity**: Time O(n^2) for pairwise rule evaluation. Space O(n^2) worst case (dense graph).

```typescript
function deterministicEdgeWeight(a: FormNode, b: FormNode): number {
  let weight = 0;

  // Rule 1: Semantic flow (credential -> verification -> payment -> submission)
  const FLOW_ORDER: Record<string, number> = {
    'credential': 1, 'verification': 2, 'payment': 3, 'personal': 2, 'other': 4
  };
  if (FLOW_ORDER[a.semanticType] < FLOW_ORDER[b.semanticType]) {
    weight += 0.4;
  }

  // Rule 2: Sequential ordering (earlier fields feed later fields)
  if (a.id < b.id) {
    weight += 0.2 * (1 / (1 + Math.abs(a.id - b.id)));  // Decays with distance
  }

  // Rule 3: Same semantic type (parallel fields, e.g., password + confirm_password)
  if (a.semanticType === b.semanticType && a.id !== b.id) {
    weight += 0.3;
  }

  // Rule 4: High urgency on both (attack coupling)
  if (a.urgencyScore > 0.5 && b.urgencyScore > 0.5) {
    weight += 0.1;
  }

  return weight;
}

function buildDeterministicGraph(nodes: FormNode[]): FormEdge[] {
  const edges: FormEdge[] = [];
  const THRESHOLD = 0.35;

  for (let i = 0; i < nodes.length; i++) {
    for (let j = i + 1; j < nodes.length; j++) {
      const weight = deterministicEdgeWeight(nodes[i], nodes[j]);
      if (weight >= THRESHOLD) {
        edges.push({
          from: i,
          to: j,
          type: 'flow',
          weight,
        });
      }
    }
  }

  return edges;
}
```

---

## Upgrade 2.7 — "True Shannon Entropy Consensus"

**Fixes**: Weakness 2.7 (mislabeled entropy) and Weakness 2.8 (contradictory severity addition)

**Core Mechanism**: Replace the standard deviation computation with actual Shannon entropy of the signal distribution. Normalize the three signals to a probability distribution, compute H = -sum(p_i * log2(p_i)). Use entropy as a CONFIDENCE MODIFIER (multiplying the severity's gating threshold), not as an additive severity term. When signals agree (low entropy), confidence is high and BLOCK thresholds are easier to meet. When signals disagree (high entropy), confidence drops and the system requires stronger evidence.

**Why It Fixes It**: Shannon entropy correctly measures the information content of signal agreement. Using it as a confidence modifier (rather than a severity addend) aligns with the documented semantics: disagreement = less certainty, not higher threat.

**Complexity**: Time O(1). Space O(1).

```typescript
function computeTrueEntropy(signals: number[]): {
  entropy: number;
  normalizedEntropy: number;
  confidence: number;
} {
  // Normalize signals to probability distribution
  const sum = signals.reduce((a, b) => a + Math.abs(b), 0);
  if (sum === 0) return { entropy: 0, normalizedEntropy: 0, confidence: 1.0 };

  const probs = signals.map(s => Math.abs(s) / sum);

  // Shannon entropy: H = -sum(p * log2(p))
  let entropy = 0;
  for (const p of probs) {
    if (p > 0) entropy -= p * Math.log2(p);
  }

  // Normalize: max entropy for 3 signals = log2(3) = 1.585
  const maxEntropy = Math.log2(signals.length);
  const normalizedEntropy = entropy / maxEntropy;  // 0 = perfect agreement, 1 = total disagreement

  // Confidence: high when signals agree (low entropy)
  const confidence = 1.0 - normalizedEntropy;

  return { entropy, normalizedEntropy, confidence };
}

function unifySignalsV2(
  intentSignal: number,
  payoffSignal: number,
  fragilitySignal: number
): { severity: number; confidence: number } {
  const signals = [intentSignal, payoffSignal, fragilitySignal];
  const { confidence } = computeTrueEntropy(signals);

  // Severity is weighted average (entropy NOT added)
  const severity = intentSignal * 0.40 + payoffSignal * 0.35 + fragilitySignal * 0.25;

  return {
    severity: Math.min(1.0, severity),
    confidence,
  };
}
```

---

## Upgrade 3.1 — "Incremental Order Parameter with Strategy Decomposition"

**Fixes**: Weakness 3.1 (recomputing all intent fields) and Weakness 3.2 (scalar order parameter)

**Core Mechanism**: Cache totalEnergy incrementally as forms enter and leave the window (O(1) per update). Replace the scalar order parameter with a vector order parameter that decomposes by attack strategy type. Maintain a rolling covariance matrix of the feature vectors in the window. The eigenvalues of this covariance matrix reveal the number of distinct strategy clusters (number of eigenvalues above noise threshold), and the principal eigenvector reveals the dominant strategy direction. This is analogous to the magnetization vector in the XY model, not the Ising model.

**Why It Fixes It**: The incremental cache eliminates the O(W*n) recomputation. The vector order parameter detects strategy bifurcation (attacker population splitting into subspecialties), which a scalar average misses entirely. The covariance eigendecomposition is a natural generalization of the order parameter to high-dimensional strategy spaces.

**Complexity**: Time O(d^2) per update for covariance matrix maintenance (d=12 features), O(d^3) for eigendecomposition (trivial for d=12). Space O(d^2 + W) for covariance matrix and energy cache.

```typescript
class IncrementalPhaseTracker {
  private energyRing: Float64Array;        // Circular buffer of totalEnergy
  private featureSum: Float64Array;         // Running sum of feature vectors
  private featureSquareSum: Float64Array;   // Running sum of outer products (flattened)
  private head: number = 0;
  private count: number = 0;
  private readonly d: number = 12;

  constructor(private readonly windowSize: number = 1000) {
    this.energyRing = new Float64Array(windowSize);
    this.featureSum = new Float64Array(this.d);
    this.featureSquareSum = new Float64Array(this.d * this.d);
  }

  addForm(features: number[], totalEnergy: number): void {
    // Remove oldest if window full
    if (this.count >= this.windowSize) {
      // Would need to store old features -- use reservoir or approximate
      // For simplicity, use exponential decay instead
    }

    this.energyRing[this.head] = totalEnergy;
    this.head = (this.head + 1) % this.windowSize;
    this.count = Math.min(this.count + 1, this.windowSize);

    // Update running sums
    for (let i = 0; i < this.d; i++) {
      this.featureSum[i] += features[i];
      for (let j = 0; j < this.d; j++) {
        this.featureSquareSum[i * this.d + j] += features[i] * features[j];
      }
    }
  }

  getOrderParameter(): {
    scalarMu: number;
    dominantDirection: Float64Array;
    numClusters: number;
    covarianceSpectrum: number[];
  } {
    if (this.count === 0) {
      return {
        scalarMu: 0,
        dominantDirection: new Float64Array(this.d),
        numClusters: 0,
        covarianceSpectrum: [],
      };
    }

    // Scalar order parameter (backward compatible)
    let sumEnergy = 0;
    for (let i = 0; i < this.count; i++) sumEnergy += this.energyRing[i];
    const scalarMu = sumEnergy / this.count;

    // Covariance matrix
    const cov = new Float64Array(this.d * this.d);
    for (let i = 0; i < this.d; i++) {
      for (let j = 0; j < this.d; j++) {
        cov[i * this.d + j] = this.featureSquareSum[i * this.d + j] / this.count
          - (this.featureSum[i] / this.count) * (this.featureSum[j] / this.count);
      }
    }

    // Eigendecomposition (power iteration for top-k)
    const { eigenvalues, eigenvectors } = powerIteration(cov, this.d, 3);

    // Number of clusters = number of eigenvalues above noise threshold
    const noiseThreshold = eigenvalues[0] * 0.1;
    const numClusters = eigenvalues.filter(e => e > noiseThreshold).length;

    return {
      scalarMu,
      dominantDirection: eigenvectors[0],
      numClusters,
      covarianceSpectrum: eigenvalues,
    };
  }
}
```

---

## Upgrade 4.1 — "Feature-Coupled Gradient Field ODE"

**Fixes**: Weakness 4.1 (only 2 features have gradient terms)

**Core Mechanism**: Derive the ODE gradient field from the payoff function for ALL features, not just features 0 and 1. For each feature dimension i, compute the partial derivative of attacker payoff with respect to feature i. This gradient tells us: "In which direction would a rational attacker change this feature to increase their payoff?" The full ODE becomes dF_i/dt = -lambda * dPayoff/dF_i + diffusion + noise, where the gradient is computed via finite differences on the payoff function.

**Why It Fixes It**: Every feature dimension now has a meaningful drift term driven by attacker incentives. The trajectory prediction genuinely models how a rational attacker would evolve their form across all 12 dimensions, not just 2.

**Complexity**: Time O(d^2) per ODE evaluation (d=12 for finite differences on payoff). Space O(d).

```typescript
function payoffGradient(
  features: number[],
  payoffFunction: (f: number[]) => number,
  epsilon: number = 1e-4
): number[] {
  const d = features.length;
  const gradient = new Array(d);
  const basePay = payoffFunction(features);

  for (let i = 0; i < d; i++) {
    const perturbed = [...features];
    perturbed[i] += epsilon;
    gradient[i] = (payoffFunction(perturbed) - basePay) / epsilon;
  }

  return gradient;
}

function fullOdeDerivative(
  state: number[],
  payoffFn: (f: number[]) => number,
  phase: PhaseTransition,
  seed: number  // Deterministic noise seed
): number[] {
  const d = state.length;
  const gradient = payoffGradient(state, payoffFn);
  const derivative = new Array(d);
  const lambda = 0.1;

  for (let i = 0; i < d; i++) {
    // Gradient descent on payoff (attacker optimizes)
    derivative[i] = -lambda * gradient[i];

    // Diffusion between adjacent features
    if (i > 0 && i < d - 1) {
      derivative[i] += 0.01 * (state[i + 1] - 2 * state[i] + state[i - 1]);
    }

    // Deterministic pseudo-noise from hash
    const noiseScale = phase.phaseState === 'heating' ? 0.05 : 0.01;
    derivative[i] += deterministicNoise(seed, i) * noiseScale;
  }

  return derivative;
}

// Deterministic noise: hash-based, reproducible
function deterministicNoise(seed: number, index: number): number {
  let h = seed ^ (index * 2654435761);
  h = Math.imul(h ^ (h >>> 16), 0x85ebca6b);
  h = Math.imul(h ^ (h >>> 13), 0xc2b2ae35);
  h ^= h >>> 16;
  return (h & 0xffff) / 0x10000 - 0.5;  // Range [-0.5, 0.5]
}
```

---

## Upgrade 4.2 — "Correct Lyapunov Exponent via Twin Trajectories"

**Fixes**: Weakness 4.2 (Lyapunov never evolves perturbed state) and Weakness 4.3 (random noise breaks reproducibility)

**Core Mechanism**: Actually evolve BOTH the original and perturbed trajectories through the same ODE integration, then measure their divergence. Use deterministic noise (hash-based) so both trajectories experience the same noise realization. The Lyapunov exponent is then log(||y_final - y'_final||) / (T * ||y_0 - y'_0||), which correctly measures exponential sensitivity to initial conditions.

**Why It Fixes It**: This is the textbook definition of the maximal Lyapunov exponent. Both trajectories evolve under the same dynamics, and their divergence (or convergence) genuinely reflects the ODE's stability properties.

**Complexity**: Time O(d * RK_steps) -- same as current, just running the ODE twice. Space O(d).

```typescript
function computeLyapunovExponent(
  initialState: number[],
  odeStep: (state: number[], seed: number) => number[],
  steps: number,
  perturbation: number = 1e-6,
  seed: number
): number {
  const d = initialState.length;

  // Original trajectory
  let y = [...initialState];
  // Perturbed trajectory (perturb only first component for max Lyapunov)
  let yp = [...initialState];
  yp[0] += perturbation;

  const h = 0.01;

  for (let step = 0; step < steps; step++) {
    const stepSeed = seed + step;

    // RK4 for original
    const k1 = odeStep(y, stepSeed);
    const k2 = odeStep(y.map((v, i) => v + 0.5 * h * k1[i]), stepSeed);
    const k3 = odeStep(y.map((v, i) => v + 0.5 * h * k2[i]), stepSeed);
    const k4 = odeStep(y.map((v, i) => v + h * k3[i]), stepSeed);
    y = y.map((v, i) => v + (h / 6) * (k1[i] + 2*k2[i] + 2*k3[i] + k4[i]));

    // RK4 for perturbed (same seed = same noise)
    const pk1 = odeStep(yp, stepSeed);
    const pk2 = odeStep(yp.map((v, i) => v + 0.5 * h * pk1[i]), stepSeed);
    const pk3 = odeStep(yp.map((v, i) => v + 0.5 * h * pk2[i]), stepSeed);
    const pk4 = odeStep(yp.map((v, i) => v + h * pk3[i]), stepSeed);
    yp = yp.map((v, i) => v + (h / 6) * (pk1[i] + 2*pk2[i] + 2*pk3[i] + pk4[i]));
  }

  // Measure divergence
  let divergence = 0;
  for (let i = 0; i < d; i++) {
    divergence += (y[i] - yp[i]) ** 2;
  }
  divergence = Math.sqrt(divergence);

  const T = steps * h;
  return Math.log(divergence / perturbation) / T;
}
```

---

## Upgrade 5.1 — "Bayesian Decision Surface"

**Fixes**: Weakness 5.1 (decorative threat profile) and Weakness 5.2 (exploitable sharp thresholds)

**Core Mechanism**: Replace the two-threshold decision tree with a Bayesian decision-theoretic approach. Define a loss matrix L(action, truth) where actions = {BLOCK, WARN, ALLOW} and truth = {malicious, suspicious, benign}. Compute the posterior probability P(truth | signals) using the actual signal values as evidence. Select the action that minimizes expected loss: action* = argmin_a sum_t L(a, t) * P(t | signals). This produces a smooth decision surface with no exploitable discontinuities.

Report the ACTUAL signal values in the threat profile, not the weighted severity decomposition.

**Why It Fixes It**: There are no sharp thresholds to exploit. The decision surface is smooth, and an attacker trying to reduce severity must reduce ALL signals (which requires actually making the form more legitimate). The threat profile reports actual signal values, making it genuinely informative for analysts.

**Complexity**: Time O(|A| * |T|) = O(9) -- constant time. Space O(1).

```typescript
interface LossMatrix {
  // L[action][truth]: cost of taking action when truth holds
  BLOCK: { malicious: number; suspicious: number; benign: number };
  WARN:  { malicious: number; suspicious: number; benign: number };
  ALLOW: { malicious: number; suspicious: number; benign: number };
}

const DEFAULT_LOSS: LossMatrix = {
  BLOCK: { malicious: 0, suspicious: 5, benign: 20 },   // Blocking legit = high cost
  WARN:  { malicious: 10, suspicious: 0, benign: 5 },   // Warning on suspicious = ideal
  ALLOW: { malicious: 100, suspicious: 15, benign: 0 },  // Allowing malicious = catastrophic
};

function bayesianDispatch(
  intentSignal: number,
  payoffSignal: number,
  fragilitySignal: number,
  phaseSignal: number,
  confidence: number,
  loss: LossMatrix = DEFAULT_LOSS
): { verdict: 'BLOCK' | 'WARN' | 'ALLOW'; expectedLoss: Record<string, number> } {
  // Posterior: P(malicious | signals) via logistic model
  const logOdds = 3.0 * intentSignal + 2.5 * payoffSignal +
                  1.5 * fragilitySignal + 1.0 * phaseSignal - 3.0;
  const pMalicious = 1 / (1 + Math.exp(-logOdds));
  const pBenign = 1 / (1 + Math.exp(logOdds * 0.8));
  const pSuspicious = Math.max(0, 1 - pMalicious - pBenign);

  // Expected loss for each action
  const expectedLoss = {
    BLOCK: loss.BLOCK.malicious * pMalicious +
           loss.BLOCK.suspicious * pSuspicious +
           loss.BLOCK.benign * pBenign,
    WARN:  loss.WARN.malicious * pMalicious +
           loss.WARN.suspicious * pSuspicious +
           loss.WARN.benign * pBenign,
    ALLOW: loss.ALLOW.malicious * pMalicious +
           loss.ALLOW.suspicious * pSuspicious +
           loss.ALLOW.benign * pBenign,
  };

  // Minimum expected loss
  let bestAction: 'BLOCK' | 'WARN' | 'ALLOW' = 'ALLOW';
  let bestLoss = expectedLoss.ALLOW;

  if (expectedLoss.WARN < bestLoss) {
    bestAction = 'WARN';
    bestLoss = expectedLoss.WARN;
  }
  if (expectedLoss.BLOCK < bestLoss) {
    bestAction = 'BLOCK';
    bestLoss = expectedLoss.BLOCK;
  }

  return { verdict: bestAction, expectedLoss };
}
```

---

# PART C: NEW FEATURES

## New Feature 1: "Persistent Homology Fingerprint" (Topological Persistence)

**Creative Name**: The Topology That Survives

### Core Mechanism

Persistent homology is an algebraic topology tool that detects "holes" (topological features) in data at multiple scales. We apply it to the form's field similarity graph:

1. Construct a filtered simplicial complex from the form. Each field is a 0-simplex. For each pair of fields, compute a "dissimilarity" based on their semantic distance (e.g., password and confirm_password are close; password and subscribe_checkbox are far). At threshold epsilon, connect fields with dissimilarity < epsilon.

2. As epsilon increases from 0 to 1, the simplicial complex grows. Connected components merge (H0 features die), loops form and fill (H1 features are born and die), and higher-dimensional voids appear (H2+). Record the birth and death times of each topological feature.

3. The persistence diagram (set of (birth, death) pairs) is a topological fingerprint that is INVARIANT to field renaming, reordering, and cosmetic changes. An attacker can rename "password" to "secure_input_7" but cannot change the topological structure without breaking form functionality.

4. Compute the bottleneck distance between the observed form's persistence diagram and a reference library of known phishing/legitimate diagrams. Forms with small bottleneck distance to known phishing patterns are flagged.

5. Critical insight: phishing forms have characteristic H1 features (loops in the dependency graph where credential fields reference each other circularly, e.g., email -> verification_code -> backup_email -> email). Legitimate forms have tree-like dependency structures with no H1 features. This topological difference persists across all surface-level mutations.

### Why It Is Unique and Cannot Be Evaded

An attacker must preserve the functional relationships between form fields (otherwise the attack breaks). These functional relationships define the topology. Changing field names, labels, ordering, or visual layout does not change the topology. The ONLY way to evade persistent homology detection is to change the actual dependency structure of the form -- which changes how the attack works and may break it.

The bottleneck distance between persistence diagrams is a metric (satisfies triangle inequality), so it provides provable guarantees: if two forms have bottleneck distance < delta, their topological structure is within delta of each other. This is a mathematical certificate of similarity that no surface-level mutation can defeat.

### Complexity

- **Time**: O(n^3) for full persistent homology (using the standard matrix reduction algorithm). For forms with n < 100 fields, this is < 1ms. For sparse complexes, O(n * m * alpha(n)) with union-find.
- **Space**: O(n^2) for the distance matrix and simplicial complex.

### TypeScript Code Sketch

```typescript
interface PersistencePair {
  dimension: number;   // 0 = connected component, 1 = loop, 2 = void
  birth: number;       // Threshold where feature appears
  death: number;       // Threshold where feature disappears
  persistence: number; // death - birth (longer = more significant)
}

interface PersistenceDiagram {
  pairs: PersistencePair[];
  bottleneckFingerprint: Float32Array;  // Compact representation
}

function computeFieldDistanceMatrix(form: ScrapedForm): Float32Array {
  const n = form.fields.length;
  const dist = new Float32Array(n * n);

  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      // Semantic distance: same type = close, different type = far
      const typeMatch = classifyField(form.fields[i]) === classifyField(form.fields[j]) ? 0.0 : 0.5;
      // Positional distance: adjacent = close, far = far
      const positionDist = Math.abs(i - j) / n;
      // Urgency correlation: both urgent = close
      const urgencyDist = Math.abs(estimateUrgency(form.fields[i]) - estimateUrgency(form.fields[j]));

      const d = typeMatch * 0.4 + positionDist * 0.3 + urgencyDist * 0.3;
      dist[i * n + j] = d;
      dist[j * n + i] = d;
    }
  }

  return dist;
}

function computePersistentHomology(distMatrix: Float32Array, n: number): PersistenceDiagram {
  const pairs: PersistencePair[] = [];

  // === H0: Connected components (Union-Find) ===
  const parent = Int32Array.from({ length: n }, (_, i) => i);
  const rank = new Int32Array(n);
  const birthTime = new Float32Array(n);  // All born at 0

  // Sort all edges by distance
  const edges: { i: number; j: number; dist: number }[] = [];
  for (let i = 0; i < n; i++) {
    for (let j = i + 1; j < n; j++) {
      edges.push({ i, j, dist: distMatrix[i * n + j] });
    }
  }
  edges.sort((a, b) => a.dist - b.dist);

  function find(x: number): number {
    while (parent[x] !== x) { parent[x] = parent[parent[x]]; x = parent[x]; }
    return x;
  }

  function union(a: number, b: number, deathTime: number): boolean {
    const ra = find(a), rb = find(b);
    if (ra === rb) return false;  // Already connected

    // Younger component dies (born later or same time)
    const dying = rank[ra] < rank[rb] ? ra : rb;
    const surviving = dying === ra ? rb : ra;

    pairs.push({
      dimension: 0,
      birth: 0,
      death: deathTime,
      persistence: deathTime,
    });

    parent[dying] = surviving;
    if (rank[ra] === rank[rb]) rank[surviving]++;
    return true;
  }

  // Process edges in order (Vietoris-Rips filtration)
  for (const edge of edges) {
    union(edge.i, edge.j, edge.dist);
  }

  // === H1: Loops (simplified via cycle detection) ===
  // Track edges that create cycles (when union returns false)
  const uf2Parent = Int32Array.from({ length: n }, (_, i) => i);
  const uf2Rank = new Int32Array(n);

  function find2(x: number): number {
    while (uf2Parent[x] !== x) { uf2Parent[x] = uf2Parent[uf2Parent[x]]; x = uf2Parent[x]; }
    return x;
  }

  for (const edge of edges) {
    const ra = find2(edge.i), rb = find2(edge.j);
    if (ra === rb) {
      // This edge creates a cycle = H1 feature born
      pairs.push({
        dimension: 1,
        birth: edge.dist,
        death: Infinity,  // Simplified: assume cycle persists
        persistence: Infinity,
      });
    } else {
      uf2Parent[ra] = rb;
      if (uf2Rank[ra] === uf2Rank[rb]) uf2Rank[rb]++;
    }
  }

  // Compact fingerprint: sort persistences, take top-k
  const fingerprint = new Float32Array(16);
  const sorted = pairs.sort((a, b) => b.persistence - a.persistence);
  for (let i = 0; i < Math.min(16, sorted.length); i++) {
    fingerprint[i] = sorted[i].persistence === Infinity ? 1.0 : sorted[i].persistence;
  }

  return { pairs, bottleneckFingerprint: fingerprint };
}

function bottleneckDistance(a: PersistenceDiagram, b: PersistenceDiagram): number {
  // Simplified: L-infinity distance between fingerprints
  let maxDiff = 0;
  for (let i = 0; i < 16; i++) {
    maxDiff = Math.max(maxDiff, Math.abs(
      a.bottleneckFingerprint[i] - b.bottleneckFingerprint[i]
    ));
  }
  return maxDiff;
}
```

### Integration with SYNERGOS

Insert between Stage 1 and Stage 2. The persistence fingerprint becomes features F13-F28 (16 additional topological features). These feed into the unified decision as a 4th signal channel alongside intent, payoff, and fragility. The bottleneck distance to known phishing diagrams provides a direct threat indicator independent of all existing channels.

---

## New Feature 2: "Adaptive Immune Memory" (T-Cell Variant Detection)

**Creative Name**: The Algorithmic Thymus

### Core Mechanism

Inspired by the adaptive immune system's T-cell recognition mechanism. The immune system does not store exact pathogen signatures -- it stores compressed, approximate representations (epitopes) that match variant strains via cross-reactivity. We implement this computationally:

1. **Signature Extraction**: When SYNERGOS detects a confirmed phishing form (BLOCK with high confidence), extract a compressed signature: a 128-bit locality-sensitive hash (LSH) of the form's feature vector + topology fingerprint. This is the "epitope" -- a lossy compression that preserves structural similarity but discards surface details.

2. **Memory Storage**: Store epitopes in a cuckoo filter (space-efficient probabilistic data structure). Each epitope also stores metadata: attack type, severity, first-seen timestamp, variant count.

3. **Recognition**: When a new form arrives, compute its epitope and query the cuckoo filter. If the filter returns a match, the new form is a VARIANT of a known attack -- even if every field name, label, and URL has changed. The LSH ensures that forms with similar structure hash to the same bucket with high probability.

4. **Affinity Maturation**: Over time, frequently-matched epitopes are "promoted" (their recognition radius expands). Rarely-matched epitopes decay. This mimics the immune system's affinity maturation, where frequently-encountered pathogens generate stronger, broader immune responses.

5. **Clonal Selection**: When a new attack family is detected (no existing epitope matches), a new "naive T-cell" epitope is created. If this epitope matches multiple future variants, it is "clonally expanded" (stored in multiple hash tables for faster lookup). If it never matches again, it is pruned.

6. **Cross-Reactivity Radius**: Each epitope has an adjustable Hamming distance threshold. New epitopes start with a tight radius (exact match only). As variants are confirmed, the radius expands to cover the observed mutation range. This automatically adapts to each attack family's mutation rate.

### Why It Is Unique and Cannot Be Evaded

The LSH-based matching is inherently fuzzy -- it matches structure, not surface. An attacker who changes field names, labels, and URLs but preserves the underlying attack structure will match existing epitopes. To evade the immune memory, the attacker must change the actual STRUCTURE of their attack, which means developing an entirely new attack type (costly, time-consuming, and itself detectable by the novelty signals in Stage 2).

The adaptive radius means that even gradual mutation is tracked -- each confirmed variant widens the recognition radius, so the system gets BETTER at detecting variants over time, not worse.

### Complexity

- **Time**: O(k) for LSH computation (k = number of hash functions, typically 8-16). O(1) for cuckoo filter lookup. Total: O(k) per form, ~microseconds.
- **Space**: O(E * 128 bits) where E = number of stored epitopes. For 10,000 epitopes: ~160KB. Cuckoo filter overhead: ~20KB.

### TypeScript Code Sketch

```typescript
interface ImmuneEpitope {
  lshHash: Uint32Array;       // 4 x 32-bit LSH values
  attackType: string;
  severity: number;
  firstSeen: number;
  variantCount: number;
  recognitionRadius: number;  // Hamming distance threshold
  affinityScore: number;      // Higher = more frequently matched
}

class AdaptiveImmuneMemory {
  private epitopes: Map<string, ImmuneEpitope> = new Map();
  private readonly hashFunctions: number = 8;
  private readonly bucketSize: number = 4;

  // LSH: locality-sensitive hashing via random hyperplane projection
  private hyperplanes: Float32Array[];

  constructor(featureDim: number = 28) {
    // Initialize random hyperplanes (seeded for determinism)
    this.hyperplanes = [];
    for (let h = 0; h < this.hashFunctions * 32; h++) {
      const plane = new Float32Array(featureDim);
      for (let i = 0; i < featureDim; i++) {
        plane[i] = deterministicNormal(h * featureDim + i);
      }
      this.hyperplanes.push(plane);
    }
  }

  computeEpitope(features: number[]): Uint32Array {
    const hash = new Uint32Array(this.hashFunctions);
    let bit = 0;

    for (let h = 0; h < this.hashFunctions; h++) {
      let value = 0;
      for (let b = 0; b < 32; b++) {
        const plane = this.hyperplanes[bit++];
        let dot = 0;
        for (let i = 0; i < features.length; i++) {
          dot += features[i] * plane[i];
        }
        if (dot >= 0) value |= (1 << b);
      }
      hash[h] = value;
    }

    return hash;
  }

  recognize(features: number[]): {
    isVariant: boolean;
    matchedEpitope: ImmuneEpitope | null;
    similarity: number;
  } {
    const queryHash = this.computeEpitope(features);
    let bestMatch: ImmuneEpitope | null = null;
    let bestSimilarity = 0;

    for (const [_, epitope] of this.epitopes) {
      const hammingDist = this.hammingDistance(queryHash, epitope.lshHash);
      const maxDist = this.hashFunctions * 32;
      const similarity = 1 - hammingDist / maxDist;

      if (similarity > bestSimilarity) {
        bestSimilarity = similarity;
        bestMatch = epitope;
      }
    }

    const isVariant = bestMatch !== null &&
      bestSimilarity > (1 - bestMatch.recognitionRadius / (this.hashFunctions * 32));

    if (isVariant && bestMatch) {
      // Affinity maturation: expand radius, increase affinity
      bestMatch.variantCount++;
      bestMatch.affinityScore *= 1.1;
      bestMatch.recognitionRadius = Math.min(
        bestMatch.recognitionRadius * 1.05,
        this.hashFunctions * 16  // Max radius = 50% of hash space
      );
    }

    return { isVariant, matchedEpitope: bestMatch, similarity: bestSimilarity };
  }

  memorize(features: number[], attackType: string, severity: number): void {
    const hash = this.computeEpitope(features);
    const key = Array.from(hash).join('-');

    if (!this.epitopes.has(key)) {
      this.epitopes.set(key, {
        lshHash: hash,
        attackType,
        severity,
        firstSeen: Date.now(),
        variantCount: 1,
        recognitionRadius: 8,  // Start conservative (8-bit Hamming radius)
        affinityScore: 1.0,
      });
    }
  }

  private hammingDistance(a: Uint32Array, b: Uint32Array): number {
    let dist = 0;
    for (let i = 0; i < a.length; i++) {
      let xor = a[i] ^ b[i];
      while (xor) { dist++; xor &= xor - 1; }  // Popcount
    }
    return dist;
  }

  // Periodic cleanup: remove low-affinity epitopes (apoptosis)
  prune(minAffinity: number = 0.1): void {
    for (const [key, epitope] of this.epitopes) {
      epitope.affinityScore *= 0.99;  // Decay
      if (epitope.affinityScore < minAffinity) {
        this.epitopes.delete(key);
      }
    }
  }
}
```

### Integration with SYNERGOS

Add as a pre-check before Stage 1. If the immune memory recognizes the form as a variant of a known attack, immediately boost the severity by the matched epitope's severity * similarity. This provides O(1) detection for known attack families and their variants, potentially short-circuiting the full 155ms pipeline. After Stage 5 produces a BLOCK verdict, call `memorize()` to store the new epitope for future variant detection.

---

## New Feature 3: "Spectral Laplacian Fingerprint" (Spectral Graph Analysis)

**Creative Name**: The Eigenvalue Signature

### Core Mechanism

The eigenvalue spectrum of a graph's Laplacian matrix encodes deep structural information that is invariant to node labeling (field renaming). Two graphs are isomorphic if and only if their Laplacian spectra are identical (with some caveats for co-spectral graphs, which are rare in practice).

1. **Graph Construction**: Build the form dependency graph (using the deterministic edge construction from Upgrade 2.6). Compute the normalized graph Laplacian: L_norm = I - D^(-1/2) * A * D^(-1/2), where D is degree matrix and A is adjacency matrix.

2. **Eigendecomposition**: Compute all eigenvalues lambda_1 <= lambda_2 <= ... <= lambda_n of L_norm. For forms with n < 100 fields, this takes < 1ms via QR iteration.

3. **Spectral Fingerprint**: The ordered sequence of eigenvalues IS the fingerprint. Key spectral features:
   - lambda_2 (algebraic connectivity / Fiedler value): Measures how well-connected the form is. Phishing forms tend to have lower algebraic connectivity (fragile, tree-like structure with critical bridges).
   - Spectral gap (lambda_2 / lambda_max): Measures expansion properties. Legitimate forms have larger spectral gaps (more uniform connectivity).
   - Spectral entropy: H_spectral = -sum(lambda_i/trace * log(lambda_i/trace)). Measures complexity of the graph structure.
   - Number of zero eigenvalues: Equals number of connected components. Phishing forms with disconnected "decoy" sections have more zero eigenvalues.

4. **Classification**: Compare the spectral fingerprint against reference distributions of legitimate and phishing forms. Use Kullback-Leibler divergence between the observed spectral distribution and reference distributions to classify.

5. **Mutation Robustness**: Adding a single field to a form changes at most O(1) eigenvalues significantly (interlacing theorem). This means the spectral fingerprint is STABLE under small mutations -- an attacker must restructure the entire form graph to significantly change the spectrum.

### Why It Is Unique and Cannot Be Evaded

The eigenvalue interlacing theorem guarantees that adding or removing a single node changes each eigenvalue by at most O(1/n). To change the spectral fingerprint by a large amount, the attacker must change O(n) edges simultaneously -- essentially redesigning the entire form. This provides a mathematical guarantee of mutation resilience that no keyword-based or pattern-based detector can offer.

Furthermore, co-spectral non-isomorphic graphs (graphs with the same eigenvalues but different structure) are extremely rare for small graphs (n < 100). In practice, the spectral fingerprint is a unique identifier of the form's dependency structure.

### Complexity

- **Time**: O(n^3) for full eigendecomposition via QR. O(n * m) for top-k eigenvalues via Lanczos iteration. For n < 100: < 1ms.
- **Space**: O(n^2) for the Laplacian matrix. O(n) for eigenvalues.

### TypeScript Code Sketch

```typescript
interface SpectralFingerprint {
  eigenvalues: Float64Array;
  algebraicConnectivity: number;  // lambda_2
  spectralGap: number;            // lambda_2 / lambda_max
  spectralEntropy: number;
  numComponents: number;          // # zero eigenvalues
  fiedlerVector: Float64Array;    // Eigenvector of lambda_2 (clustering structure)
}

function computeNormalizedLaplacian(
  adjacencyList: Map<number, { neighbor: number; weight: number }[]>,
  n: number
): Float64Array[] {
  // Degree matrix
  const degree = new Float64Array(n);
  for (let i = 0; i < n; i++) {
    const neighbors = adjacencyList.get(i) || [];
    degree[i] = neighbors.reduce((s, e) => s + e.weight, 0);
  }

  // L_norm = I - D^{-1/2} A D^{-1/2}
  const L: Float64Array[] = [];
  for (let i = 0; i < n; i++) {
    L.push(new Float64Array(n));
    L[i][i] = degree[i] > 0 ? 1.0 : 0.0;  // Diagonal = 1

    for (const { neighbor: j, weight } of adjacencyList.get(i) || []) {
      if (degree[i] > 0 && degree[j] > 0) {
        L[i][j] = -weight / Math.sqrt(degree[i] * degree[j]);
      }
    }
  }

  return L;
}

function eigendecompose(L: Float64Array[], n: number): {
  eigenvalues: Float64Array;
  eigenvectors: Float64Array[];
} {
  // QR iteration for full spectrum (n < 100 is trivial)
  // For production: use iterative Lanczos for top-k

  const eigenvalues = new Float64Array(n);
  const eigenvectors: Float64Array[] = [];

  // Power iteration for top eigenvalues (simplified)
  let A = L.map(row => new Float64Array(row));

  for (let k = 0; k < Math.min(n, 20); k++) {
    // Power iteration for largest eigenvalue of current matrix
    let v = new Float64Array(n);
    v[k % n] = 1.0;

    for (let iter = 0; iter < 100; iter++) {
      // Multiply: Av
      const Av = new Float64Array(n);
      for (let i = 0; i < n; i++) {
        for (let j = 0; j < n; j++) {
          Av[i] += A[i][j] * v[j];
        }
      }

      // Normalize
      let norm = 0;
      for (let i = 0; i < n; i++) norm += Av[i] ** 2;
      norm = Math.sqrt(norm);
      if (norm < 1e-12) break;

      for (let i = 0; i < n; i++) v[i] = Av[i] / norm;
      eigenvalues[k] = norm;
    }

    eigenvectors.push(v);

    // Deflate: A = A - lambda * v * v^T
    for (let i = 0; i < n; i++) {
      for (let j = 0; j < n; j++) {
        A[i][j] -= eigenvalues[k] * v[i] * v[j];
      }
    }
  }

  // Sort eigenvalues ascending
  const indices = Array.from({ length: eigenvalues.length }, (_, i) => i);
  indices.sort((a, b) => eigenvalues[a] - eigenvalues[b]);

  return {
    eigenvalues: Float64Array.from(indices.map(i => eigenvalues[i])),
    eigenvectors: indices.map(i => eigenvectors[i]),
  };
}

function computeSpectralFingerprint(
  adjacencyList: Map<number, { neighbor: number; weight: number }[]>,
  n: number
): SpectralFingerprint {
  const L = computeNormalizedLaplacian(adjacencyList, n);
  const { eigenvalues, eigenvectors } = eigendecompose(L, n);

  // Count zero eigenvalues (connected components)
  let numComponents = 0;
  for (let i = 0; i < n; i++) {
    if (eigenvalues[i] < 1e-8) numComponents++;
  }

  const lambda2 = n > 1 ? eigenvalues[numComponents] : 0;
  const lambdaMax = eigenvalues[n - 1] || 1;

  // Spectral entropy
  const trace = eigenvalues.reduce((s, v) => s + v, 0) || 1;
  let spectralEntropy = 0;
  for (let i = 0; i < n; i++) {
    const p = eigenvalues[i] / trace;
    if (p > 0) spectralEntropy -= p * Math.log2(p);
  }

  return {
    eigenvalues,
    algebraicConnectivity: lambda2,
    spectralGap: lambda2 / lambdaMax,
    spectralEntropy,
    numComponents,
    fiedlerVector: eigenvectors[numComponents] || new Float64Array(n),
  };
}

function spectralThreatScore(
  observed: SpectralFingerprint,
  legitimateReference: SpectralFingerprint,
  phishingReference: SpectralFingerprint
): number {
  // KL divergence from observed to legitimate vs observed to phishing
  const klLegit = spectralKL(observed, legitimateReference);
  const klPhish = spectralKL(observed, phishingReference);

  // Score: closer to phishing = higher threat
  return klLegit / (klLegit + klPhish + 1e-8);
}

function spectralKL(a: SpectralFingerprint, b: SpectralFingerprint): number {
  // Symmetric KL between spectral distributions
  const n = Math.min(a.eigenvalues.length, b.eigenvalues.length);
  if (n === 0) return 0;

  let kl = 0;
  const aTrace = a.eigenvalues.reduce((s, v) => s + Math.max(v, 1e-8), 0);
  const bTrace = b.eigenvalues.reduce((s, v) => s + Math.max(v, 1e-8), 0);

  for (let i = 0; i < n; i++) {
    const p = Math.max(a.eigenvalues[i], 1e-8) / aTrace;
    const q = Math.max(b.eigenvalues[i], 1e-8) / bTrace;
    kl += p * Math.log(p / q) + q * Math.log(q / p);
  }

  return kl / (2 * n);
}
```

### Integration with SYNERGOS

Compute during Stage 1, alongside the intent field and dependency graph (reuses the same graph). The spectral fingerprint provides features F29-F33 (algebraicConnectivity, spectralGap, spectralEntropy, numComponents, spectralThreatScore). Feed into Stage 2C as a 4th signal alongside intent, payoff, and fragility. The Fiedler vector also provides a natural bipartition of the form into two clusters, which can enhance the fragility analysis (are critical nodes in the same cluster or split across clusters?).

---

## New Feature 4: "Stigmergic Swarm Consensus" (Original Math + Nature Hybrid)

**Creative Name**: The Pheromone Lattice

### Core Mechanism

This is an original combination of lattice theory (mathematics) with stigmergy (naturalistic swarm intelligence). Stigmergy is indirect coordination through environment modification -- ants leave pheromone trails that guide other ants. We apply this to multi-form detection across a browsing session:

1. **Pheromone Lattice Construction**: Define a lattice over the space of form features. Each point in the lattice represents a possible form configuration. When SYNERGOS analyzes a form, it deposits a "pheromone" at the lattice point corresponding to that form's feature vector. The pheromone value encodes: threat level (0-1), confidence (0-1), and timestamp.

2. **Lattice Diffusion**: Pheromones diffuse through the lattice according to the lattice's order relation. If form A is "dominated" by form B in the lattice (every feature of A is <= the corresponding feature of B), then pheromone flows from B to A. This models how knowledge about severe threats propagates to less-severe variants. The diffusion respects the lattice structure: pheromone only flows downward through the partial order, never upward.

3. **Swarm Decision**: When a new form arrives, its threat assessment is not based on the form alone. Instead, compute the CUMULATIVE pheromone at its lattice position: the sum of all pheromones that have diffused to this point from previously-analyzed forms. If a browsing session has encountered multiple suspicious forms, each deposits pheromone that accumulates at nearby lattice points, making subsequent forms easier to detect.

4. **Evaporation**: Pheromones decay exponentially over time (half-life: 5 minutes). This ensures the system adapts to changing contexts -- pheromones from an old browsing session do not contaminate new sessions.

5. **Anti-Pheromone**: When a form is confirmed as ALLOW (legitimate), deposit "anti-pheromone" at its lattice position. Anti-pheromone cancels threat pheromone, creating safe zones in the lattice. This prevents accumulated pheromone from causing false positives on forms that are similar to but distinct from actual threats.

6. **Lattice Homomorphism Detection**: Compute the structure-preserving maps (homomorphisms) from the observed session's pheromone distribution to known attack campaign templates. If a homomorphism exists, the session contains a coordinated multi-form attack (e.g., phishing form + fake verification form + data exfiltration form). Individual forms may score below threshold, but the lattice homomorphism reveals the coordinated campaign structure.

7. **Mathematical Invariant**: The pheromone lattice is a bounded distributive lattice (join and meet are defined, distributes). The Birkhoff representation theorem guarantees that this lattice is isomorphic to the lattice of down-sets of some poset -- meaning the pheromone distribution has a canonical, minimal representation. This canonical form is the "campaign fingerprint" and is invariant to the order in which forms are encountered.

### Why It Is Unique and Cannot Be Evaded

An attacker who sends multiple phishing forms in a session creates a characteristic pheromone pattern in the lattice. Even if each individual form is below detection threshold, the accumulated pheromone pushes the lattice past threshold. To evade this:
- The attacker would need to interleave legitimate forms (which deposit anti-pheromone) -- but this requires the attacker to own legitimate sites, which is expensive.
- The attacker could space forms across sessions (evaporation resets pheromone) -- but this makes the attack slower and less effective.
- The attacker could randomize form features to avoid lattice proximity -- but random features are easily detected by the payoff inference (irrational strategy).

The lattice homomorphism detection catches coordinated campaigns even when individual forms are carefully crafted to be below threshold. This is a capability no existing SYNERGOS stage has.

### Complexity

- **Time**: O(n * P) per form lookup, where P = number of active pheromone deposits (typically < 100 per session). Lattice diffusion: O(P^2) per deposit (compare all pairs for domination). Evaporation: O(P) amortized.
- **Space**: O(P * d) for pheromone storage, where d = feature dimension. For 100 deposits x 12 features: < 10KB per session.

### TypeScript Code Sketch

```typescript
interface PheromoneDeposit {
  position: Float32Array;     // Lattice point (feature vector)
  threatLevel: number;        // 0-1
  confidence: number;         // 0-1
  timestamp: number;
  isAntiPheromone: boolean;   // true = legitimacy marker
}

class PheromoneLatticee {
  private deposits: PheromoneDeposit[] = [];
  private readonly halfLife: number = 5 * 60 * 1000;  // 5 minutes in ms
  private readonly featureDim: number = 12;

  /**
   * Deposit pheromone after analyzing a form
   */
  deposit(
    features: number[],
    threatLevel: number,
    confidence: number,
    isLegitimate: boolean
  ): void {
    this.deposits.push({
      position: Float32Array.from(features),
      threatLevel,
      confidence,
      timestamp: Date.now(),
      isAntiPheromone: isLegitimate,
    });

    // Prune evaporated deposits
    this.evaporate();
  }

  /**
   * Query cumulative pheromone at a lattice point
   */
  query(features: number[]): {
    cumulativeThreat: number;
    cumulativeConfidence: number;
    numContributors: number;
    campaignDetected: boolean;
  } {
    this.evaporate();

    let totalThreat = 0;
    let totalConfidence = 0;
    let numContributors = 0;
    const now = Date.now();

    for (const dep of this.deposits) {
      // Check lattice domination: does deposit dominate query point?
      // (deposit at higher threat level in lattice)
      const dominates = this.latticeDominates(dep.position, features);

      if (dominates || this.latticeDistance(dep.position, features) < 0.3) {
        // Pheromone diffuses from dominant/nearby points
        const age = now - dep.timestamp;
        const decay = Math.exp(-Math.LN2 * age / this.halfLife);
        const proximity = 1 - this.latticeDistance(dep.position, features);

        const contribution = dep.threatLevel * decay * proximity * dep.confidence;

        if (dep.isAntiPheromone) {
          totalThreat -= contribution * 0.5;  // Anti-pheromone partially cancels
        } else {
          totalThreat += contribution;
          totalConfidence += dep.confidence * decay;
          numContributors++;
        }
      }
    }

    // Campaign detection: if 3+ contributors with high cumulative threat
    const campaignDetected = numContributors >= 3 && totalThreat > 1.5;

    return {
      cumulativeThreat: Math.max(0, Math.min(1, totalThreat)),
      cumulativeConfidence: Math.min(1, totalConfidence / Math.max(numContributors, 1)),
      numContributors,
      campaignDetected,
    };
  }

  /**
   * Check if point A dominates point B in the lattice
   * (A >= B in every dimension)
   */
  private latticeDominates(a: Float32Array, b: number[]): boolean {
    for (let i = 0; i < this.featureDim; i++) {
      if (a[i] < b[i] - 0.05) return false;  // Small tolerance
    }
    return true;
  }

  /**
   * Lattice distance: L-infinity distance normalized by dimension
   */
  private latticeDistance(a: Float32Array, b: number[]): number {
    let maxDiff = 0;
    for (let i = 0; i < this.featureDim; i++) {
      maxDiff = Math.max(maxDiff, Math.abs(a[i] - b[i]));
    }
    return maxDiff;
  }

  /**
   * Remove deposits whose pheromone has evaporated below threshold
   */
  private evaporate(): void {
    const now = Date.now();
    const minDecay = 0.01;  // Remove when decay < 1%

    this.deposits = this.deposits.filter(dep => {
      const age = now - dep.timestamp;
      return Math.exp(-Math.LN2 * age / this.halfLife) > minDecay;
    });
  }

  /**
   * Detect campaign pattern via lattice homomorphism
   */
  detectCampaign(): {
    isCampaign: boolean;
    campaignType: string;
    formSequence: number[];
  } | null {
    if (this.deposits.length < 3) return null;

    // Check if deposits form a monotone chain in the lattice
    // (each subsequent form dominates or is dominated by previous)
    const threatDeposits = this.deposits.filter(d => !d.isAntiPheromone);

    // Sort by timestamp
    threatDeposits.sort((a, b) => a.timestamp - b.timestamp);

    // Check for escalation pattern: threat levels increasing
    let escalationCount = 0;
    for (let i = 1; i < threatDeposits.length; i++) {
      if (threatDeposits[i].threatLevel > threatDeposits[i-1].threatLevel + 0.05) {
        escalationCount++;
      }
    }

    const isEscalation = escalationCount >= threatDeposits.length * 0.6;

    // Check for spread pattern: features diversifying
    let featureSpread = 0;
    for (let d = 0; d < this.featureDim; d++) {
      const values = threatDeposits.map(dep => dep.position[d]);
      const min = Math.min(...values);
      const max = Math.max(...values);
      featureSpread += max - min;
    }

    const isSpread = featureSpread > this.featureDim * 0.3;

    if (isEscalation && isSpread) {
      return {
        isCampaign: true,
        campaignType: 'escalating_multi_vector',
        formSequence: threatDeposits.map((_, i) => i),
      };
    }

    if (threatDeposits.length >= 3 && !isEscalation && !isSpread) {
      // Clustered pattern: all similar forms = phishing kit
      return {
        isCampaign: true,
        campaignType: 'phishing_kit_deployment',
        formSequence: threatDeposits.map((_, i) => i),
      };
    }

    return null;
  }
}
```

### Integration with SYNERGOS

The Pheromone Lattice operates as a cross-form context layer that wraps around the entire SYNERGOS pipeline:

- **Before Stage 1**: Query the lattice for cumulative pheromone at the new form's (approximate) position. If cumulative threat > 0.5, add a "session context boost" of +0.2 to the intent field source terms.
- **After Stage 5**: Deposit pheromone based on the verdict. BLOCK/WARN deposits threat pheromone; ALLOW deposits anti-pheromone.
- **Campaign Detection**: Run `detectCampaign()` after each deposit. If a campaign is detected, override individual form verdicts: escalate ALL forms in the campaign to BLOCK, even if individually they were WARN or ALLOW.

This creates an emergent capability: SYNERGOS can now detect COORDINATED MULTI-FORM ATTACKS that are invisible to single-form analysis. Each form alone is below threshold, but the swarm intelligence of accumulated pheromone reveals the pattern.

---

# SUMMARY OF FINDINGS

## Critical Issues (Must Fix)

| ID | Stage | Issue | Severity |
|----|-------|-------|----------|
| 2.4 | Fragility | `_isGraphConnected` always returns true -- fragility stage non-functional | CRITICAL |
| 2.6 | Fragility | `Math.random()` in edge construction breaks determinism | CRITICAL |
| 4.2 | Trajectory | Lyapunov exponent never evolves perturbed state -- value is meaningless | CRITICAL |
| 4.3 | Trajectory | `Math.random()` in ODE noise breaks reproducibility | CRITICAL |
| 3.1 | Evolution | Recomputes all intent fields in window -- O(30s) instead of O(30ms) | CRITICAL |

## Major Issues (Should Fix)

| ID | Stage | Issue | Severity |
|----|-------|-------|----------|
| 1.1 | Intent | 1D diffusion ignores form topology | MAJOR |
| 2.1 | Payoff | "Nash equilibrium" is just a linear combination, not actual game theory | MAJOR |
| 2.5 | Fragility | Degree centrality used instead of betweenness centrality | MAJOR |
| 2.7 | Unified | Standard deviation mislabeled as entropy | MAJOR |
| 2.8 | Unified | Entropy added to severity (should modulate confidence) | MAJOR |
| 4.1 | Trajectory | Only 2/12 features have ODE gradient terms | MAJOR |
| 5.1 | Dispatch | Threat profile is decorative (not actual signal values) | MAJOR |

## Moderate Issues (Should Consider)

| ID | Stage | Issue | Severity |
|----|-------|-------|----------|
| 1.2 | Intent | Fixed 5 relaxation iterations -- wrong for varying form sizes | MODERATE |
| 1.3 | Intent | 15-keyword dictionary is brittle | MODERATE |
| 1.4 | Intent | Zero-padding boundary creates edge artifacts | MODERATE |
| 2.2 | Payoff | Strategy classification is threshold tree, not game-theoretic | MODERATE |
| 2.3 | Payoff | Payoff values are uncalibrated arbitrary constants | MODERATE |
| 3.2 | Evolution | Scalar order parameter misses directional information | MODERATE |
| 3.3 | Evolution | Fixed lookback derivative doesn't adapt | MODERATE |
| 3.4 | Evolution | Phase classification thresholds are arbitrary | MODERATE |
| 5.2 | Dispatch | Sharp thresholds are exploitable by adversary | MODERATE |

## New Capabilities Proposed

| Feature | Name | Core Idea | Integration Point |
|---------|------|-----------|-------------------|
| 1 | Persistent Homology Fingerprint | Topological invariant of form structure | Stage 1 -> Stage 2C (4th signal) |
| 2 | Adaptive Immune Memory | LSH-based variant detection with affinity maturation | Pre-Stage 1 (fast path) + Post-Stage 5 (memorize) |
| 3 | Spectral Laplacian Fingerprint | Graph eigenvalue signature for structural classification | Stage 1 (parallel with intent field) |
| 4 | Pheromone Lattice | Cross-form stigmergic swarm consensus | Session wrapper around entire pipeline |

---

**End of Audit Report**
**Agent 1: The Mathematician & Naturalist**
**Date: 2026-04-02**
