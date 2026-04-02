# ScamShield — Complete Algorithm & Architecture Reference

> **Generated:** 2026-03-30
> **Codebase:** `scamshield/` — Next.js 14 App Router + TypeScript
> **Total algorithms:** 17 modules, ~13,000 lines
> **Live API:** `https://scamshield-green.vercel.app`

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Core Types & Interfaces](#2-core-types--interfaces)
3. [VERIDICT Engine — Main Orchestrator](#3-veridict-engine--main-orchestrator)
4. [Layer 1: Fisher Information Cascade](#4-layer-1-fisher-information-cascade)
5. [Layer 2: Conservation Laws](#5-layer-2-conservation-laws)
6. [Layer 3: Cascade Breaker](#6-layer-3-cascade-breaker)
7. [Layer 4: Adaptive Immune Repertoire](#7-layer-4-adaptive-immune-repertoire)
8. [Extended Module: URL Deep Analyzer](#8-extended-module-url-deep-analyzer)
9. [Extended Module: Similarity Engine](#9-extended-module-similarity-engine)
10. [Extended Module: Financial Risk Scorer](#10-extended-module-financial-risk-scorer)
11. [Extended Module: Multilingual Detector](#11-extended-module-multilingual-detector)
12. [Extended Module: Phone Analyzer](#12-extended-module-phone-analyzer)
13. [Extended Module: Linguistic Deception Detector](#13-extended-module-linguistic-deception-detector)
14. [Signal Extractors](#14-signal-extractors)
15. [Conversation Arc Analyzer](#15-conversation-arc-analyzer)
16. [IP Intelligence](#16-ip-intelligence)
17. [WHOIS / SSL Enrichment](#17-whois--ssl-enrichment)
18. [Threat Intelligence](#18-threat-intelligence)
19. [Community Scoring](#19-community-scoring)
20. [API Routes](#20-api-routes)
21. [Infrastructure](#21-infrastructure)
22. [Browser Extension](#22-browser-extension)
23. [B2B API Endpoints](#23-b2b-api-endpoints)
24. [Scoring Quick-Reference](#24-scoring-quick-reference)

---

## 1. Architecture Overview

```
User Input (URL / Text / Screenshot)
        │
        ▼
  POST /api/scan
        │
  ┌─────┴──────────────────────────────────────────┐
  │ Parallel execution (Promise.all)               │
  │  ├─ runVERIDICT(analysisInput)                 │
  │  ├─ enrichUrlWithWhoisSsl(url)  [URLs only]    │
  │  └─ analyzeUrlIp(url)           [URLs only]    │
  └─────┬──────────────────────────────────────────┘
        │
  VERIDICT Engine
  ├── Layer 1: Fisher Information Cascade
  ├── Layer 2: Conservation Laws
  ├── Layer 3: Cascade Breaker
  ├── Layer 4: Adaptive Immune Repertoire
  │
  Extended Modules (run in parallel inside engine):
  ├── URL Deep Analyzer
  ├── Similarity Engine
  ├── Financial Risk Scorer
  ├── Multilingual Detector
  ├── Phone Analyzer
  └── Linguistic Deception Detector
        │
  Score Fusion → Threat Level → Evidence List → VERIDICTResult
        │
  Merge WHOIS/SSL + IP Intelligence (score boosts, evidence prepend)
        │
  Persist to Supabase (fire-and-forget)
        │
  Return JSON response
```

### Threat Level Thresholds (global)

| Score | Threat Level |
|-------|-------------|
| 0–14  | SAFE        |
| 15–34 | LOW         |
| 35–54 | MEDIUM      |
| 55–74 | HIGH        |
| 75–100| CRITICAL    |

---

## 2. Core Types & Interfaces

**File:** `src/lib/algorithms/types.ts`

### Enums

```typescript
enum ThreatLevel { SAFE, LOW, MEDIUM, HIGH, CRITICAL }

enum ThreatCategory {
  PHISHING, ADVANCE_FEE, TECH_SUPPORT, ROMANCE, CRYPTO, IRS_GOV,
  PACKAGE_DELIVERY, SOCIAL_MEDIA, SUBSCRIPTION_TRAP, FAKE_CHARITY,
  RENTAL_HOUSING, STUDENT_LOAN, GENERIC, MARKETPLACE_FRAUD,
  ELDER_SCAM, TICKET_SCAM, INVESTMENT_FRAUD, EMPLOYMENT_SCAM, BANK_OTP
}

enum SignalType {
  URGENCY, AUTHORITY, FINANCIAL_REQUEST, PERSONAL_INFO_REQUEST,
  THREAT, REWARD, SUSPICIOUS_LINK, GRAMMAR_ERROR, EMOTIONAL_MANIPULATION,
  DOMAIN_MISMATCH, UNKNOWN_SENDER, CRYPTO_MENTION, GIFT_CARD_REQUEST,
  WIRE_TRANSFER, OTP_BYPASS, PHONE_NUMBER, CALLBACK_NUMBER
}
```

### Key Interfaces

```typescript
interface AnalysisInput {
  url?: string;
  text?: string;
  smsBody?: string;
  emailBody?: string;
  emailHeaders?: Record<string, string>;
  screenshotOcrText?: string;
}

interface VERIDICTResult {
  score: number;                    // 0–100
  threatLevel: ThreatLevel;
  category: ThreatCategory;
  evidence: EvidenceItem[];
  layerScores: LayerScores;         // fisher, conservation, cascadeBreaker, immune
  layerDetails: LayerDetails;       // per-layer detail arrays
  confidenceInterval: ConfidenceInterval;  // { lower, upper }
  similarKnownScam?: string;
  financialRisk?: FinancialRiskResult;
  urlDeepAnalysis?: UrlDeepAnalysisResult;
  multilingualDetection?: MultilingualResult;
  phoneAnalysis?: PhoneAnalysisResult;
  linguisticDeception?: LinguisticDeceptionResult;
  processingTimeMs?: number;        // added by API route
  // Dynamically added by API route:
  whoisSsl?: { domainAge, sslValid, registrar }
  ipIntelligence?: IpIntelligenceData
}

interface EvidenceItem {
  layer: string;
  finding: string;
  detail: string;
  severity: ThreatSeverity;   // "low" | "medium" | "high" | "critical"
  confidence: number;          // 0–1
}

interface LayerScores {
  fisher: number;
  conservation: number;
  cascadeBreaker: number;
  immune: number;
}

interface ConfidenceInterval {
  lower: number;
  upper: number;
}

interface FinancialRiskResult {
  riskScore: number;
  riskType: string;
  estimatedLoss: string;
  urgencyScore: number;
  sophisticationScore: number;
  recommendedActions: string[];
}

interface UrlDeepAnalysisResult {
  overallRiskScore: number;
  detectedBrands: string[];
  homoglyphsDetected: boolean;
  flags: string[];
  breakdown: Record<string, number>;
}

interface MultilingualResult {
  detected: boolean;
  dominantLanguage: string;
  matches: Array<{ language, pattern, confidence }>;
  riskScore: number;
  flags: string[];
}

interface PhoneAnalysisResult {
  detected: boolean;
  phones: Array<{ number, type, riskScore, flags }>;
  highestRisk: number;
  flags: string[];
}

interface LinguisticDeceptionResult {
  score: number;
  deceptionTactics: string[];
  manipulationScore: number;
  flags: string[];
  details: string[];
}
```

---

## 3. VERIDICT Engine — Main Orchestrator

**File:** `src/lib/algorithms/veridict-engine.ts` (886 lines)

### Function: `runVERIDICT(input: AnalysisInput): Promise<VERIDICTResult>`

The top-level entry point. Steps:

1. **Preprocess** input — URL normalization, encoding detection
2. **Extract signals** via `extractSignals(input)` from signal-extractors.ts
3. **Run 4 layers in sequence** (each informed by previous)
4. **Run 7 extended modules in parallel** (URL analyzer, similarity, risk, multilingual, phone, linguistic deception)
5. **Fuse scores** using weighted combination
6. **Build evidence list** (deduplicated, severity-sorted)
7. **Classify threat category** from layer findings
8. **Compute confidence interval** (bootstrap sampling)
9. **Return `VERIDICTResult`**

### Score Fusion Formula

```
fusedScore = (
  fisherScore    × 0.30 +
  conservScore   × 0.25 +
  cascadeScore   × 0.25 +
  immuneScore    × 0.20
)
```

Additional boosts applied (additive, capped at 100):
- `urlDeepAnalysis.overallRiskScore > 60` → +8
- `multilingualDetection.riskScore > 50` → +5
- `linguisticDeception.score > 60` → +6
- `phoneAnalysis.highestRisk > 70` → +4

### Input Preprocessing

- Adds `https://` prefix if URL has no protocol
- Decodes unnecessary percent-encoding
- Strips `\r` from text, normalizes Unicode whitespace
- Detects Base64-encoded content and decodes it

### Confidence Interval Calculation

Bootstrap sampling over 500 iterations:
- Each sample perturbs individual layer scores by ±gaussian(0, σ=8)
- 95th percentile of fused distribution used for upper/lower CI bounds
- Returns `{ lower: p2.5, upper: p97.5 }`

### Category Classification

Priority order checked:
1. Immune layer — checks highest-affinity antibody category
2. Similarity engine — uses nearest template's category
3. Signal-based fallback — checks dominant SignalType patterns

---

## 4. Layer 1: Fisher Information Cascade

**File:** `src/lib/algorithms/fisher-cascade.ts`

### Function: `runFisherCascade(signals: Signal[], input: AnalysisInput): LayerResult`

**Theory:** Uses Fisher Information from statistics — signals with higher discriminative power (low noise, high variance relative to baseline) carry more weight. Early stopping when cumulative information exceeds threshold.

### Algorithm Steps

```
1. Compute Fisher Information for each signal:
   I(θ) = E[(d/dθ log f(x;θ))²]
   Approximated as: variance(signal_values) / noise_estimate²

2. Sort signals by Fisher Information (descending)

3. Accumulate signals until:
   - Cumulative I(θ) exceeds THRESHOLD (adaptive, scales with input length)
   OR
   - All signals exhausted

4. Apply correlation discounting:
   If two signals share semantic category → reduce weight of second by 0.7×

5. Apply surprise bonus:
   Cross-context signal (e.g., URL anomaly + urgency text together) → ×1.15

6. Compute calibrated sigmoid score:
   score = 100 / (1 + exp(-k × (cumI - midpoint)))
   where k=0.08, midpoint=adaptive based on baseline
```

### Signal Weight Lookup Table

| SignalType | Base Weight |
|-----------|-------------|
| URGENCY | 1.2 |
| FINANCIAL_REQUEST | 1.8 |
| CRYPTO_MENTION | 1.6 |
| OTP_BYPASS | 2.0 |
| GIFT_CARD_REQUEST | 1.9 |
| WIRE_TRANSFER | 1.9 |
| SUSPICIOUS_LINK | 1.5 |
| THREAT | 1.7 |
| AUTHORITY | 1.1 |
| PERSONAL_INFO_REQUEST | 1.6 |
| GRAMMAR_ERROR | 0.8 |
| REWARD | 1.0 |
| EMOTIONAL_MANIPULATION | 1.3 |

### Early Stopping Rules

- Minimum 3 signals evaluated before stopping
- Maximum 25 signals evaluated (performance cap)
- Stop early if single signal I(θ) > 80 (slam-dunk case)

---

## 5. Layer 2: Conservation Laws

**File:** `src/lib/algorithms/conservation-laws.ts`

### Function: `runConservationLaws(signals: Signal[], input: AnalysisInput): LayerResult`

**Theory:** Legitimate communication follows "conservation laws" — e.g., a real bank never asks for your password. Violations create measurable asymmetries in the 6×6 violation tensor.

### The 6 Conservation Laws

| # | Law | What It Checks | Severity Weight |
|---|-----|---------------|-----------------|
| 1 | Identity-Provenance | Claimed sender identity matches actual origin | 1.5× |
| 2 | Value-Exchange | Promised value proportional to requested action | 1.3× |
| 3 | Urgency-Legitimacy | Urgency level justified by actual stakes | 1.2× |
| 4 | Authority-Channel | Authority claim matches expected official channel | 1.4× |
| 5 | Information-Asymmetry | Sender requesting info they should already have | 1.1× |
| 6 | Context-Coherence | Internal consistency of the message narrative | 1.0× |

### Violation Tensor

6×6 matrix `V[i][j]` where `V[i][j]` = degree to which law `i` violation predicts law `j` violation.

**Score formula:**
```
frobenius_norm = sqrt(sum(V[i][j]²))
weighted_norm  = frobenius_norm × severity_weights
score          = min(100, weighted_norm × calibration_factor)
```

### Individual Law Detection

**Law 1 — Identity-Provenance:**
- Email header `From:` vs `Reply-To:` mismatch
- Domain in link ≠ domain claimed in text
- Sender claims to be from `paypal.com` but link goes to `pay-pal-secure.com`

**Law 2 — Value-Exchange:**
- Promise of large reward (lottery, inheritance) for small upfront payment
- Guaranteed investment returns
- "You won $1M — just pay $200 processing fee"

**Law 3 — Urgency-Legitimacy:**
- "Account suspended in 24 hours" with no prior warning
- "IMMEDIATE ACTION REQUIRED" for non-emergency situations
- Deadline pressure without legal/regulatory basis

**Law 4 — Authority-Channel:**
- IRS communicating via SMS (IRS only uses postal mail)
- Bank asking for OTP via phone call
- "Microsoft Security Team" via WhatsApp

**Law 5 — Information-Asymmetry:**
- Bank asking for full account number when they have it
- OTP request: "Please tell us the code we just sent you"
- SSN request from entity claiming to already have your file

**Law 6 — Context-Coherence:**
- Message switches language mid-way
- Contradictory statements (e.g., "your account is safe" then "immediate action required")
- Formatting inconsistencies (US English + UK phone number + Nigerian bank)

---

## 6. Layer 3: Cascade Breaker

**File:** `src/lib/algorithms/cascade-breaker.ts` (535 lines)

### Function: `runCascadeBreaker(signals: Signal[], input: AnalysisInput, fisherScore: number, conservScore: number): LayerResult`

**Theory:** Detects psychological manipulation "cascade triggers" — sequences of escalating pressure designed to override rational decision-making. Inspired by CIA influence operation detection.

### Cascade Trigger Categories

| Category | Examples | Risk Weight |
|----------|----------|-------------|
| FEAR_INDUCTION | Arrest threat, account seizure, lawsuit | 1.8 |
| SCARCITY_PRESSURE | "Only 3 slots left", "Offer expires tonight" | 1.4 |
| SOCIAL_PROOF | "Thousands already enrolled", "Join 50,000 investors" | 1.2 |
| AUTHORITY_APPEAL | "FBI Agent", "IRS Notice", "Your bank has detected" | 1.5 |
| RECIPROCITY_EXPLOIT | Free gift before asking for something | 1.3 |
| COMMITMENT_TRAP | Small initial yes → escalating requests | 1.6 |
| ISOLATION_TACTIC | "Don't tell anyone", "This is private" | 1.7 |
| IDENTITY_LEVERAGING | Uses your name, employer, family details | 1.4 |

### Cascade Detection

1. Each trigger type has 8–15 regex patterns
2. Detected triggers assigned weights based on category
3. **Sequence bonus:** If 3+ different trigger types detected in a single message → ×1.35
4. **Amplification:** Fear + Scarcity together → additional ×1.2
5. Uses `fisherScore` and `conservScore` as priors — if both are high, cascade detection is less aggressive (evidence already strong)

### Manipulation Flow Scoring

Checks for classic manipulation arc within a single message:
```
Rapport → Authority → Problem → Urgency → Solution → Action Required
```
Each step present adds to flow score. Complete 6-step arc = high manipulation confidence.

---

## 7. Layer 4: Adaptive Immune Repertoire

**File:** `src/lib/algorithms/immune-repertoire.ts` (1,910 lines)

### Function: `runImmuneRepertoire(signals: Signal[], input: AnalysisInput): LayerResult`

**Theory:** Inspired by adaptive immune system — a repertoire of 120+ "antibodies" each recognizing a specific scam pattern. Successful detections boost antibody affinity (clonal selection). Unknown threats trigger zero-day detection.

### Antibody Structure

```typescript
interface Antibody {
  id: string;               // e.g., "PKG-001"
  name: string;             // "USPS Package Delivery Scam"
  pattern: RegExp;          // primary detection regex
  affinity: number;         // detection confidence 0.6–0.95
  generation: number;       // evolution counter
  falsePositiveRate: number; // expected FP rate 0.01–0.20
  category: ThreatCategory;
  description: string;
}
```

### Antibody Repertoire (120+ patterns, 28 categories)

| Category | IDs | Count | Description |
|----------|-----|-------|-------------|
| Package Delivery | PKG-001–007 | 7 | USPS, FedEx, UPS, DHL, Amazon |
| Bank/Financial | BNK-001–010 | 10 | Account suspension, wire transfer, PayPal, gift cards |
| E-commerce | ECM-001–006 | 6 | Amazon, Netflix, Apple, Microsoft phishing |
| Cryptocurrency | CRY-001–008 | 8 | Guaranteed returns, doubling, wallet verification, airdrops |
| IRS/Government | GOV-001–007 | 7 | Tax debt, SSA suspension, immigration threats |
| Romance | ROM-001–005 | 5 | Military deployment, stranded abroad, inheritance |
| Tech Support | TEC-001–008 | 8 | Microsoft, virus alerts, remote access |
| Lottery/Prize | LOT-001–004 | 4 | Lottery winners, prize fees, sweepstakes |
| Extortion | EXT-001–003 | 3 | Sextortion, password reveal, DDoS threats |
| Employment | JOB-001–003 + EMP-001–005 | 8 | Work-from-home, reshipping mules, mystery shopper |
| Social Media | SOC-001–010 | 10 | Instagram verification, giveaways, dating scams |
| Subscription | SUB-001–007 | 7 | Free trials, hidden auto-charges |
| Fake Charity | CHR-001–007 | 7 | Disaster relief, donation pressure |
| Rental/Housing | RNT-001–007 | 7 | Deposit before viewing, landlord abroad |
| Student Loans | STU-001–007 | 7 | Forgiveness scams, consolidation fees |
| High-Value | ADD-001–008 | 8 | Deepfakes, QR codes, BEC, SIM swap |
| Toll Road | TOL-001–002 | 2 | E-ZPass, unpaid balance |
| Pig Butchering | PIG-001–003 | 3 | Wrong number openers, investment guarantees |
| Boss/BEC | BEC-001–002 | 2 | Gift card demands, urgent wire transfers |
| Digital Arrest | ARR-001–002 | 2 | FBI threats, money laundering |
| Recovery Scams | REC-001–002 | 2 | Fund recovery fees, victim compensation |
| Payment Red Flags | PAY-001–002 | 2 | Gift cards, P2P/wire transfer requests |
| Marketplace | MKT-001–006 | 6 | Overpayment checks, ticket fraud |
| Elder Scams | ELD-001–006 | 6 | Grandparent emergency, Medicare |
| Ticket Scams | TKT-001–004 | 4 | Last-minute VIP access |
| Investment Fraud | INV-001–006 | 6 | Ponzi, Forex, pump-and-dump, AI bots |
| Bank OTP Bypass | OTP-001–006 | 6 | Verification codes, APP fraud |

### Key Functions

```typescript
// Generate looser pattern variants for partial matching
function fuzzyMatch(antibody: Antibody, text: string): number

// Find all matching antibodies, sorted by affinity
function findMatches(text: string): AntibodyMatch[]

// Group matched antibodies by category prefix, amplify cluster hits
function computeClusterActivation(matches: AntibodyMatch[]): ClusterScore[]

// Identify potential new threat patterns from weak multi-antibody matches
function detectZeroDay(text: string, matches: AntibodyMatch[]): ZeroDaySignal | null

// Boost affinity of successful antibodies (learning mechanism)
function clonalSelection(matches: AntibodyMatch[]): void
```

### Danger Signal Gating

If `fisherScore < 15 AND conservScore < 15 AND cascadeScore < 15`:
- Skip cluster activation and zero-day detection
- Only return raw antibody matches (performance optimization)

### Scoring Formula

```
immuneScore = clusterActivation × 0.6 + rawAffinity × 0.4
bonus if zero-day detected: +10 (capped at 100)
```

---

## 8. Extended Module: URL Deep Analyzer

**File:** `src/lib/algorithms/url-deep-analyzer.ts`

### Function: `deepAnalyzeUrl(url: string): UrlDeepAnalysisResult`

Performs structural decomposition of URLs to detect brand impersonation and obfuscation.

### Checks Performed

| Check | Description | Weight |
|-------|-------------|--------|
| Homoglyph detection | ℝ→R, а→a (Cyrillic), ε→e | +25 |
| Brand in subdomain | `paypal.secure-login.com` | +20 |
| Brand in path | `login.evil.com/paypal/verify` | +15 |
| Excessive subdomains | ≥4 subdomain levels | +12 |
| Port number | Non-standard port in URL | +10 |
| URL length | >100 chars | +8 |
| Encoded characters | `%2F%3D` in domain | +15 |
| Known shortener | goo.su, tinyurl.com, etc. | +8–20 |
| IP address URL | `http://192.168.1.1/bank` | +25 |
| Dash-in-domain | `pay-pal-secure-login.com` | +12 |

**Brand database:** 80+ monitored brands (PayPal, Amazon, Apple, Microsoft, Google, Chase, Bank of America, Wells Fargo, Citibank, Netflix, IRS, USPS, FedEx, UPS, DHL, etc.)

### Homoglyph Table (selected)

```
а/а (Cyrillic a), е (Cyrillic e), о (Cyrillic o), р (Cyrillic p),
ℝ, ℤ, ℂ, ℕ, ℚ — mathematical symbols
ο (Greek omicron), α (Greek alpha), μ (Greek mu)
0/O, 1/l/I, rn/m confusion
```

---

## 9. Extended Module: Similarity Engine

**File:** `src/lib/algorithms/similarity-engine.ts` (676 lines)

### Function: `findClosestTemplates(text: string): SimilarityResult[]`

Returns top-3 matching scam templates with similarity scores.

### Three Similarity Metrics

#### 1. Trigram Jaccard Similarity (35% weight)
```
trigrams(s) = all 3-char sequences from s
J(A,B) = |trigrams(A) ∩ trigrams(B)| / |trigrams(A) ∪ trigrams(B)|
```

#### 2. TF-IDF Cosine Similarity (40% weight)
```
TF(t,d)  = count(t in d) / total_tokens(d)
IDF(t)   = log(N / df(t))   where N = total docs in corpus
TF-IDF   = TF × IDF
cosine   = dot(a,b) / (|a| × |b|)
```

#### 3. Structural Pattern Similarity (25% weight)
Checks for presence of 10 structural elements:
- Greeting, Authority claim, Problem statement, Urgency signal
- Action required, Deadline, Threat, Reward promise, Link, Personal info request

Bonus ×1.2 if `urgency → action → deadline` sequence present.

### Template Corpus (50+ templates, 28 categories)

| Category | Count | Examples |
|----------|-------|---------|
| Package Delivery | 6 | USPS, FedEx, UPS, Amazon, DHL, Generic |
| Bank/Financial | 8 | Fraud alert, wire transfer, PayPal, Venmo, Zelle, CashApp |
| IRS/Government | 5 | Tax refund, audit threat, SSA, stimulus, DMV |
| Tech Support | 5 | Microsoft, Apple, Antivirus, Google, browser popup |
| Cryptocurrency | 5 | Investment, giveaway, wallet verification, airdrop |
| Romance | 4 | Military, investment pitch, emergency, inheritance |
| Prize/Lottery | 5 | Lottery, survey, sweepstakes, iPhone, car |
| Job Scams | 4 | WFH, fake recruiter, mystery shopper, data entry |
| Rental/Housing | 3 | Too-good deals, security deposit, application fees |
| Social Media | 3 | Instagram verification, copyright, TikTok |
| Toll Road | 3 | SunPass, E-ZPass, generic |
| Pig Butchering | 6 | Wrong number openers (various) |
| Boss/BEC | 2 | Gift card, wire transfer |
| Digital Arrest | 2 | FBI, money laundering |
| Recovery Scams | 1 | Fund recovery |
| Marketplace | 4 | Advance payment, overpayment check, tickets, vehicles |
| Elder/Grandparent | 3 | Emergency bail, lawyer, Medicare |
| Investment Fraud | 4 | Crypto, Forex, Ponzi, pump-and-dump |
| Bank OTP Bypass | 3 | Fake bank security, safe account, SIM swap |
| Employment Scams | 3 | Reshipping, fake payroll, identity harvest |
| ... | ... | ... |

---

## 10. Extended Module: Financial Risk Scorer

**File:** `src/lib/algorithms/risk-scorer.ts` (513 lines)

### Function: `assessFinancialRisk(input: AnalysisInput, signals: Signal[]): FinancialRiskResult`

Estimates financial exposure if victim complies.

### Risk Scoring Components

| Component | Weight | Description |
|-----------|--------|-------------|
| Urgency Score | 0.25 | Time pressure indicators |
| Sophistication Score | 0.25 | Professionalism, personalization |
| Financial Request Size | 0.30 | Dollar amount mentioned |
| Payment Method Risk | 0.20 | Gift card > wire > crypto > bank |

### Financial Loss Estimation

Calculates `estimatedLoss` string based on:
- Dollar amounts extracted from text (regex)
- Scam type baseline losses from FBI IC3 data
- Multiplied by sophistication coefficient

### Payment Method Risk Table

| Method | Risk Multiplier | Recovery Chance |
|--------|----------------|-----------------|
| Gift cards | 2.0× | Near zero |
| Wire transfer | 1.8× | Very low |
| Cryptocurrency | 1.9× | Near zero |
| Zelle/P2P | 1.5× | Low |
| Bank transfer | 1.3× | Moderate |
| Credit card | 0.8× | High (chargeback) |

### Recommended Actions (generated per risk level)

- Score > 80: "Do NOT respond", "Contact authorities", "Block sender"
- Score 60–80: "Verify independently", "Do not click links", "Report to FTC"
- Score 40–60: "Treat with caution", "Verify sender identity"
- Score < 40: "Low risk — proceed with normal caution"

---

## 11. Extended Module: Multilingual Detector

**File:** `src/lib/algorithms/multilingual-detector.ts` (405 lines)

### Function: `detectMultilingualScam(text: string): MultilingualResult`

Detects scam patterns in non-English text to identify international campaigns targeting diaspora communities.

### Supported Languages & Pattern Counts

| Language | Patterns | Focus Areas |
|----------|----------|-------------|
| Spanish | 10 | Banking urgency, advance payment, lottery, crypto |
| French | 7 | Blocked accounts, advanced fees, OTP |
| Portuguese | 5 | Suspended accounts, advance payments |
| Arabic | 3 | Account suspension, prize/lottery |
| German | 4 | Account locked, TAN/OTP, package delivery |
| Chinese | 4 | Investment scams, impersonation |

### Language Detection

```typescript
function detectLanguage(text: string): string
// Uses marker word frequency analysis
// Returns ISO 639-1 code or "en"
```

### Risk Scoring

```
riskScore = highestMatchConfidence + (matchCount - 1) × 8
capped at 100
```

---

## 12. Extended Module: Phone Analyzer

**File:** `src/lib/algorithms/phone-analyzer.ts` (205 lines)

### Function: `analyzePhoneNumbers(text: string): PhoneAnalysisResult`

Extracts and classifies phone numbers by risk level.

### Phone Number Patterns Detected

- US toll-free numbers (800, 888, 877, 866, 855, 844, 833)
- International numbers with country code prefix
- Premium rate numbers (+1-900, +44-0900)
- Known scam area codes (809, 284, 876 — Caribbean charge-back)

### Risk Classification

| Type | Risk Score | Description |
|------|-----------|-------------|
| Caribbean callback | 85 | 809/284/876 — per-minute charges |
| Premium rate | 80 | 900-number scams |
| Spoofed government | 75 | Fake IRS/SSA numbers |
| Multiple numbers | 60 | Callback redundancy = professional operation |
| Toll-free | 30 | Lower risk but still flagged |

### Flags Generated

- `PREMIUM_RATE_NUMBER` — premium rate detected
- `CARIBBEAN_CALLBACK` — Caribbean area code
- `MULTIPLE_CALLBACK_NUMBERS` — 3+ phone numbers in message
- `SUSPICIOUS_AREA_CODE` — known scam-associated area code

---

## 13. Extended Module: Linguistic Deception Detector

**File:** `src/lib/algorithms/linguistic-deception.ts` (344 lines)

### Function: `detectLinguisticDeception(text: string): LinguisticDeceptionResult`

Identifies manipulation techniques from psychology/persuasion research.

### Deception Tactic Detection

| Tactic | Pattern Examples | Weight |
|--------|-----------------|--------|
| False urgency | "must act now", "expires in", "only X hours left" | 1.4 |
| False authority | "official notice", "law enforcement", "federal agent" | 1.5 |
| Fear amplification | "criminal charges", "arrest warrant", "account frozen" | 1.6 |
| Social proof | "thousands of customers", "most people choose" | 1.1 |
| Scarcity | "limited availability", "final notice" | 1.3 |
| Reciprocity setup | "we've already reserved", "your free gift awaits" | 1.2 |
| Identity confirmation | Uses name/employer as trust signal | 1.4 |
| Commitment escalation | "as we discussed", "following your request" | 1.5 |
| Isolation instruction | "do not tell", "keep this confidential" | 1.8 |
| Guilt induction | "you owe", "your obligation", "you agreed" | 1.3 |

### Manipulation Score

```
manipulationScore = sum(detected_tactic_weights) × diversity_bonus
diversity_bonus   = 1.0 + (unique_categories / 10) × 0.5
```

---

## 14. Signal Extractors

**File:** `src/lib/algorithms/signal-extractors.ts` (1,540 lines)

### Function: `extractSignals(input: AnalysisInput): Signal[]`

Converts raw input into typed, weighted signals for algorithm consumption.

### URL Shortener Database (tiered by abuse rate)

| Tier | Examples | Abuse Rate | Signal Boost |
|------|----------|------------|-------------|
| HIGH | goo.su, is.gd | ≥49% | +25 |
| MEDIUM | tinyurl.com, t.ly, rebrand.ly | 10–17% | +15 |
| LOW | bit.ly, ow.ly, buff.ly, cutt.ly, etc. | <10% | +8 |

Full LOW_ABUSE set: `qrco.de, bit.ly, t.co, ow.ly, buff.ly, shorturl.at, cutt.ly, tiny.cc, lnkd.in, rb.gy, s.id, v.gd, clck.ru, u.to, shorte.st, adf.ly, bc.vc, j.mp, goo.gl, dlvr.it, db.tt, qr.ae, trib.al, soo.gd, budurl.com, linktr.ee, han.gl, surl.li`

### Extraction Categories

| Extractor | Signals Produced |
|-----------|-----------------|
| URL extractor | SUSPICIOUS_LINK, DOMAIN_MISMATCH |
| Text urgency extractor | URGENCY, THREAT |
| Authority extractor | AUTHORITY |
| Financial keyword extractor | FINANCIAL_REQUEST, GIFT_CARD_REQUEST, WIRE_TRANSFER, CRYPTO_MENTION |
| Personal info extractor | PERSONAL_INFO_REQUEST |
| Phone extractor | PHONE_NUMBER, CALLBACK_NUMBER |
| OTP bypass extractor | OTP_BYPASS |
| Grammar error detector | GRAMMAR_ERROR |
| Emotional language extractor | EMOTIONAL_MANIPULATION, REWARD |

### Signal Interface

```typescript
interface Signal {
  type: SignalType;
  value: string;         // extracted raw value
  confidence: number;   // 0–1
  context: string;      // surrounding text snippet
  source: "url" | "text" | "email_header" | "sms";
}
```

---

## 15. Conversation Arc Analyzer

**File:** `src/lib/algorithms/conversation-arc.ts` (576 lines)

**API Endpoint:** `POST /api/analyze-conversation`

### Purpose

Detects pig-butchering (sha zhu pan) and romance scam grooming arcs in multi-message conversation exports. Primary B2B product for dating apps, social platforms, and banks.

### Function: `analyzeConversationArc(conversationText: string): ConversationArcResult`

### 6 Grooming Phases (GroomingPhase enum)

| Phase | Key Signals | Risk Weight |
|-------|------------|-------------|
| RAPPORT_BUILDING | Flattery, shared interests, "we have so much in common" | — |
| TRUST_DEVELOPMENT | Daily contact, future planning, personal disclosure | 5% |
| ISOLATION | "Don't tell others", moving to WhatsApp/Telegram | 10% |
| INVESTMENT_HOOK | Crypto trading, "I made $50k last month" | 20% |
| PRESSURE_ESCALATION | Urgency to invest, FOMO, "limited time" | 25% |
| COLLECTION | Requesting money/crypto transfer, wire, gift cards | 40% |

### Overall Risk Weight Formula

```
overallRisk = COLLECTION×0.40 + PRESSURE×0.25 + INVESTMENT×0.20 +
              ISOLATION×0.10 + TRUST×0.05
```

### Phase Pattern Count

Each phase has 10–20 regex patterns with weights 0.5–1.0:
- Rapport: 15 patterns (flattery, shared-interest language)
- Trust: 12 patterns (daily contact, future planning)
- Isolation: 14 patterns (platform migration, secrecy)
- Investment: 18 patterns (crypto mentions, returns claims)
- Pressure: 16 patterns (urgency, FOMO, deadlines)
- Collection: 20 patterns (payment requests, crypto addresses)

### Phase Score Formula

```
rawWeight   = sum(pattern.weight for each match)
totalMessages = count of messages in conversation
phaseScore  = min(100, (rawWeight / (log2(totalMessages + 2) / 2)) × 10)
```

### Arc Type Classification

```
PIG_BUTCHERING:   rapport≥20 AND investment≥20 AND (collection≥15 OR pressure≥25)
ROMANCE_SCAM:     rapport≥20 AND (collection≥20 OR isolation≥25) AND investment<20
INVESTMENT_FRAUD: investment≥25 AND (pressure≥20 OR collection≥20) AND rapport<15
ADVANCE_FEE:      collection≥25 AND trust≥15 AND rapport<15
GENERIC_GROOMING: ≥3 phases present but no specific arc match
BENIGN:           overallRisk < 15
```

### Arc Completion Multiplier

```
phases_present ≥ 5 → ×1.5
phases_present ≥ 4 → ×1.3
phases_present ≥ 3 → ×1.15
otherwise          → ×1.0
```

### Conversation Parser

```typescript
function parseConversation(text: string): ConversationMessage[]
```

Supports 10 conversation export formats:
- WhatsApp (`[DD/MM/YYYY, HH:MM] Name: text`)
- iMessage / Apple Messages
- Telegram export
- Signal desktop
- Facebook Messenger export
- Generic `Name: text` format
- Line-by-line (alternating speakers inferred)
- JSON array `[{sender, text, timestamp}]`
- CSV (first column = sender, second = text)
- Plain text with speaker labels

### Timeline Generation

Divides conversation into 5–10 temporal segments. Each segment colored by dominant phase:
```typescript
const PHASE_COLORS = {
  RAPPORT_BUILDING:    "#22c55e",  // green
  TRUST_DEVELOPMENT:   "#84cc16",  // lime
  ISOLATION:           "#eab308",  // yellow
  INVESTMENT_HOOK:     "#f97316",  // orange
  PRESSURE_ESCALATION: "#ef4444",  // red
  COLLECTION:          "#7f1d1d",  // dark red
}
```

### ConversationArcResult

```typescript
interface ConversationArcResult {
  overallRisk: number;             // 0–100
  threatLevel: ThreatLevel;
  arcType: ArcType;
  arcLabel: string;                // human-readable arc name
  phases: PhaseResult[];           // 6 items, one per phase
  timeline: TimelineSegment[];     // 5–10 segments
  criticalFindings: string[];      // most important evidence strings
  recommendedActions: string[];    // per-risk-level actions
  messageCount: number;
  processingTimeMs: number;
}
```

---

## 16. IP Intelligence

**File:** `src/lib/ip-intelligence.ts` (308 lines)

### Functions

```typescript
// Analyze an IP address directly
function analyzeIp(ipAddress: string): Promise<IpIntelligenceResult>

// Resolve a URL's domain to IP, then analyze
function analyzeUrlIp(url: string): Promise<IpIntelligenceResult | null>

// Classify hosting type from org/ISP/ASN strings
function classifyHosting(isp: string, org: string, asn: string): HostingCategory
```

### HostingCategory Union Type

```typescript
type HostingCategory = "residential" | "cloud" | "vps" | "vpn_proxy" | "tor" | "unknown"
```

### IpIntelligenceResult Interface

```typescript
interface IpIntelligenceResult {
  ip: string;
  country: string;
  countryCode: string;             // ISO 3166-1 alpha-2
  city: string;
  isp: string;
  org: string;
  asn: string;
  hostingCategory: HostingCategory;
  isDatacenter: boolean;
  isVpnOrProxy: boolean;
  countryRiskLevel: "low" | "medium" | "high" | "critical";
  scoreBoost: number;              // 0–40
  evidence: EvidenceItem[];
  flags: string[];
}
```

### DNS Resolution

```typescript
// Primary: dns.promises.resolve4(hostname)
// Fallback: dns.promises.lookup(hostname)
// Private IP check: skips RFC-1918 ranges
```

### High-Risk Country Registry (20+ entries)

| Code | Country | Risk Level | Score Boost | Reason |
|------|---------|-----------|-------------|--------|
| KH | Cambodia | CRITICAL | +30 | Pig-butchering scam compounds |
| MM | Myanmar | CRITICAL | +30 | Cyber-scam compounds (UN documented) |
| LA | Laos | CRITICAL | +28 | Known scam operations |
| NG | Nigeria | HIGH | +20 | Advance-fee & romance scam origin |
| RU | Russia | HIGH | +20 | Major cybercrime infrastructure |
| CN | China | HIGH | +18 | Extensive fraud network operations |
| GH | Ghana | HIGH | +18 | Romance and advance-fee scams |
| UA | Ukraine | MEDIUM | +12 | Cybercrime activity |
| IN | India | MEDIUM | +10 | Tech support scam origin |
| PK | Pakistan | MEDIUM | +10 | Various fraud operations |
| PH | Philippines | MEDIUM | +8 | AMLC-listed high-risk |
| ... | ... | ... | ... | ... |

### Hosting Classification Logic

Checks `org`, `isp`, and `asn` strings against keyword lists:

**VPN/Proxy keywords:** `nordvpn, expressvpn, cyberghost, protonvpn, mullvad, privateinternetaccess, ipvanish, windscribe, surfshark, hidemyass, torguard, vypr, tunnelbear` + 20 more

**TOR detection:** `tor exit, tor relay, tor node` in org string

**Cloud/Datacenter keywords:** `amazon, aws, google cloud, microsoft azure, digitalocean, linode, vultr, hetzner, ovh, cloudflare` + 15 more

**VPS/Bulletproof keywords:** `frantech, buyvm, psychz, sharktech, host4fun, hostkey, serverius` + 10 more — these get highest boost

**Known Scam ASNs:**
- Integen Inc: +15
- Frantech Solutions (BuyVM): +18 (bulletproof hosting)

### Score Boost Table

| Category | Boost |
|---------|-------|
| TOR node | +35 |
| VPN/Proxy | +22 |
| Scam ASN | +15–18 |
| High-risk country (critical) | +28–30 |
| High-risk country (high) | +18–20 |
| VPS hosting | +12 |
| Cloud hosting | +3 |
| **Total cap** | **40** |

### API Used

`http://ip-api.com/json/{ip}?fields=status,message,query,country,countryCode,region,regionName,city,isp,org,as`
- Free tier: 45 req/min, no API key needed
- Note: `proxy`, `hosting`, `mobile` fields require paid plan → hosting classified via heuristics

---

## 17. WHOIS / SSL Enrichment

**File:** `src/lib/whois-ssl.ts`

### Function: `enrichUrlWithWhoisSsl(url: string): Promise<WhoisSslResult>`

Runs RDAP lookup and SSL check in parallel, both with 4-second AbortSignal timeouts.

### RDAP Lookup

```typescript
async function rdapLookup(domain: string): Promise<RdapResult>
```

- API: `https://rdap.org/domain/{domain}`
- Extracts: registration date, expiry date, registrar name
- Computes `domainAge` in days from registration date to now

### SSL Check

```typescript
async function checkSSL(url: string): Promise<boolean | null>
```

- Method: `fetch(https://domain)` with HEAD request
- Returns `true` if HTTPS connection succeeds, `false` if error, `null` on timeout

### WhoisSslResult

```typescript
interface WhoisSslResult {
  domainAge: number | null;   // days since registration
  sslValid: boolean | null;
  registrar: string | null;
  scoreBoost: number;
  evidence: EvidenceItem[];
}
```

### Score Boost Rules

| Condition | Boost |
|-----------|-------|
| Domain < 7 days old | +25 |
| Domain 7–30 days old | +15 |
| Domain 30–90 days old | +8 |
| SSL invalid | +15 |
| SSL unknown | +5 |
| Suspicious registrar | +8 |

---

## 18. Threat Intelligence

**File:** `src/lib/algorithms/threat-intelligence.ts` (428 lines)

### Functions

```typescript
function analyzeTrends(incidents: ThreatIncident[]): TrendAnalysis
function detectOutbreak(incidents: ThreatIncident[]): OutbreakAlert[]
function predictNextWave(trendAnalysis: TrendAnalysis): WavePrediction[]
function generateThreatIntelligence(incidents: ThreatIncident[]): ThreatIntelligenceReport
```

### Time-Series Processing

1. **Bucketing:** Groups incidents into 1-hour buckets with gap filling (0-count hours kept)
2. **Adaptive EMA:** `α = min(0.3, density_factor × 0.1)` — sparse data gets smoother smoothing
3. **Multi-window EMA:** hour, day (24h), week (168h), month (720h)
4. **Derivatives:**
   - Velocity: `v[t] = ema[t] - ema[t-1]`
   - Acceleration: `a[t] = v[t] - v[t-1]`

### Outbreak Detection

```
z-score = (current_value - mean) / std_dev
outbreak triggered if z_score ≥ 2.0
severity:
  z ≥ 3.0 → "critical"
  z ≥ 2.5 → "warning"
  z ≥ 2.0 → "watch"
```

### Kinematic Wave Prediction

```
peak_time_estimate = -v / a  (frames)
confidence = (data_points_factor × recency_factor × consistency_factor)
```

---

## 19. Community Scoring

**File:** `src/lib/algorithms/community-scoring.ts` (394 lines)

### Functions

```typescript
function computeReporterReliability(reporter: ReporterProfile): ReliabilityScore
function detectGaming(reports: CommunityReport[]): GamingDetectionResult
function aggregateCommunityReports(reports: CommunityReport[]): CommunityTrustScore
```

### Temporal Decay

```
weight = exp(-λ × age_days)   where λ = ln(2) / 30  (30-day half-life)
```

### Wilson Score Interval

```
// 95% confidence interval for binary proportion
z = 1.96
p̂ = positive_reports / total_reports
lower = (p̂ + z²/2n - z√(p̂(1-p̂)/n + z²/4n²)) / (1 + z²/n)
upper = (p̂ + z²/2n + z√(p̂(1-p̂)/n + z²/4n²)) / (1 + z²/n)
```

### Bayesian Reporter Reliability

Beta-Binomial model: `Beta(α + correct, β + incorrect)` with prior `Beta(2, 1)` (mildly skeptical, assumes ~67% chance reporter is reliable).

### Account Quality Factors

```
age_factor    = 0.3 + 0.7 × sigmoid(account_age_days / 30)
volume_factor = log10(total_reports + 1) / 3   (diminishing returns)
```

### Anti-Gaming Detection (5 signals)

| Signal | Condition | Severity |
|--------|-----------|----------|
| Temporal burst | 3+ reporters within 10 minutes | High |
| New account swarm | Multiple <30-day accounts on same target | High |
| Unanimous anomaly | >95% agreement with 8+ reports | Medium |
| Low-accuracy cluster | 3+ reporters with <40% accuracy | Medium |
| Single-target swarm | Multiple reporters, all single-report only | Medium |

Anti-gaming dampening: reduces final score by up to 50% based on gaming severity.

---

## 20. API Routes

### `POST /api/scan`

**File:** `src/app/api/scan/route.ts`

**Request:**
```json
{
  "type": "url" | "text" | "screenshot",
  "content": "string (max 10,000 chars)"
}
```

**Execution Flow:**
1. Rate limit check (IP-based, 10 req/15min free, 100 req/15min Pro)
2. Input validation (type, content length)
3. `buildAnalysisInput()` — maps type to AnalysisInput fields
4. `Promise.all([runVERIDICT, enrichUrlWithWhoisSsl, analyzeUrlIp])` — parallel
5. Merge WHOIS evidence (prepended, scoreBoost applied)
6. Merge IP intelligence (prepended, scoreBoost applied)
7. Fire-and-forget Supabase insert to `scans` table
8. Return `{ ...result, processingTimeMs }` with rate limit headers

**Response headers:**
- `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-Processing-Time`

**Rate limit response (429):**
```json
{
  "error": "Rate limit exceeded. Upgrade to Pro for unlimited scans.",
  "remaining": 0,
  "resetAt": "2026-03-30T12:00:00.000Z"
}
```

---

### `POST /api/scan/screenshot`

**File:** `src/app/api/scan/screenshot/route.ts`

**Request:** `multipart/form-data` with `image` field (PNG/JPEG/WEBP, max 5MB)

**Execution Flow:**
1. Parse form data, validate MIME type and size
2. Extract text via OCR (Tesseract.js or Google Vision API)
3. Forward extracted text to main VERIDICT pipeline
4. Return same VERIDICTResult structure

---

### `POST /api/analyze-conversation`

**File:** `src/app/api/analyze-conversation/route.ts`

**Request:**
```json
{
  "conversation": "string (max 100,000 chars)"
}
```

**Response:**
```typescript
ConversationArcResult + { processingTimeMs: number }
```

---

### `POST /api/v2/conversation-risk` (B2B)

**File:** `src/app/api/v2/conversation-risk/route.ts`

**Request:**
```json
{
  "conversation": "string (required, max 100,000 chars)",
  "user_ip": "string (optional)",
  "profile": {
    "account_age_days": number,
    "profile_photo_count": number,
    "messages_sent_today": number,
    "conversation_count": number,
    "has_verified_phone": boolean,
    "platform": "tinder" | "bumble" | "hinge" | string
  }
}
```

**Execution:** `Promise.all([analyzeConversationArc, analyzeIp])` + `scoreProfile()`

**Score weights:**
```
combinedRisk = arcResult.overallRisk × 0.60
             + ipScore × 0.25
             + profileScore × 0.15
```

**Profile Scoring (0–50 pts, doubled to 0–100 for weighting):**

| Condition | Points |
|-----------|--------|
| Account age < 1 day | +30 |
| Account age < 7 days | +22 |
| Account age < 30 days | +12 |
| No profile photos | +18 |
| Only 1 profile photo | +8 |
| messages_sent_today > 30 | +15 |
| conversation_count > 5 | +12 |
| No verified phone | +10 |

**Recommendation strings:**

| Score | Recommendation |
|-------|---------------|
| ≥75 | BLOCK or FLAG — immediate intervention required |
| ≥55 | FLAG for review — multiple risk signals detected |
| ≥35 | MONITOR — moderate risk signals present |
| ≥15 | WATCH — low-level signals detected |
| <15 | ALLOW — no significant risk signals |

**Response:**
```json
{
  "combinedRisk": 72,
  "threatLevel": "HIGH",
  "recommendation": "FLAG for review...",
  "scores": {
    "conversationArc": 65,
    "ipIntelligence": 40,
    "profileRisk": 28
  },
  "weights": { "conversationArc": 0.60, "ipIntelligence": 0.25, "profileRisk": 0.15 },
  "arc": { "type": "PIG_BUTCHERING", "label": "...", "phasesDetected": 4, "phases": [...] },
  "ip": { "address": "...", "country": "Cambodia", "hostingCategory": "datacenter", ... },
  "profileSignals": [{ "finding": "Account only 2 day(s) old", "severity": "high" }],
  "recommendedActions": [...],
  "processingTimeMs": 312
}
```

---

## 21. Infrastructure

### Rate Limiter

**File:** `src/lib/rate-limit.ts`

```typescript
function checkRateLimit(ip: string, isPro: boolean): RateLimitResult
```

- Free tier: 10 requests per 15-minute window
- Pro tier: 100 requests per 15-minute window
- In-memory store (Map) — resets on server restart
- B2B endpoint (`/api/v2/*`): separate limit, 50 req/15min

```typescript
interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  limit: number;
  resetAt: number;  // Unix timestamp ms
}
```

---

### Utility Functions

**File:** `src/lib/utils.ts`

```typescript
// Extract real client IP respecting proxy headers
function getClientIp(req: NextRequest): string | null

// Merge Tailwind class names (clsx + tailwind-merge)
function cn(...inputs: ClassValue[]): string
```

`getClientIp` header priority:
1. `x-forwarded-for` (first IP in chain)
2. `x-real-ip`
3. `x-vercel-forwarded-for`
4. `remote-addr`

---

### Supabase Client

**File:** `src/lib/supabase/client.ts`

```typescript
// Client-side (browser) — uses anon key
function createBrowserClient(): SupabaseClient

// Server-side — uses service role key (bypasses RLS)
function createServiceRoleClient(): SupabaseClient
```

Environment variables required:
- `NEXT_PUBLIC_SUPABASE_URL`
- `NEXT_PUBLIC_SUPABASE_ANON_KEY`
- `SUPABASE_SERVICE_ROLE_KEY`

### Supabase Schema

**`scans` table:**

| Column | Type | Description |
|--------|------|-------------|
| id | uuid | Primary key |
| user_id | uuid | NULL for anonymous |
| input_type | text | "url" / "text" / "screenshot" |
| input_preview | text | First 200 chars of input |
| score | int | 0–100 |
| threat_level | text | SAFE/LOW/MEDIUM/HIGH/CRITICAL |
| category | text | ThreatCategory value |
| result_json | jsonb | Full VERIDICTResult |
| ip_address | text | Hashed client IP |
| created_at | timestamptz | Scan timestamp |

---

## 22. Browser Extension

**Files:** `browser-extension/`

### Core Files

| File | Purpose |
|------|---------|
| `manifest.json` | Extension manifest (Manifest V3) |
| `popup.html` | 350px popup UI |
| `popup.js` | All logic, API calls, rendering |
| `popup.css` | Glassmorphism dark theme styles |
| `background.js` | Service worker for tab access |

### popup.js — Key Functions

```javascript
// Detect if input is URL or text
function detectType(input): "url" | "text"

// Main scan function — calls API, handles loading/error states
async function scan(content): void

// Render API response into popup UI
function renderResult(data): void
```

### API Integration

```javascript
const API_URL = "https://scamshield-green.vercel.app/api/scan";

// POST { type, content } → VERIDICTResult
// Renders: score circle, threat level, category,
//   WHOIS/SSL badges, IP intelligence badges, evidence list,
//   confidence interval bar, processing time
```

### IP Intelligence Badges in Extension

```javascript
// Country risk: badge-bad (critical/high), badge-warn (medium), badge-ok (low)
// Hosting type: 🚨 TOR | 🛡 VPN/Proxy | 🖥 VPS | ☁ Cloud | 🏠 Residential
// IP address: gray badge
```

### Auto-fill on Open

On popup open: queries active tab URL, pre-fills input field if URL starts with `http://` or `https://`.

---

## 23. B2B API Endpoints

### Target Markets

| Endpoint | Primary Buyers | Use Case |
|----------|---------------|---------|
| `POST /api/scan` | Consumer apps, browser extensions | Real-time scam detection |
| `POST /api/v2/conversation-risk` | Dating apps, social platforms, banks | Romance/pig-butchering prevention |
| `POST /api/analyze-conversation` | Trust & Safety teams, investigators | Manual review tooling |

### Regulatory Drivers (buying urgency)

| Regulation | Region | Effective | Mandate |
|-----------|--------|----------|---------|
| UK PSR APP Fraud | UK | Oct 2024 | Banks split losses 50/50 |
| EU AI Act | EU | Aug 2026 | Risk-based AI requirements |
| Australia SPF Act | AU | 2026 | Scam prevention framework |
| Singapore OCHA | SG | Active | Online Criminal Harms Act |
| Online Safety Act | UK | Active | Platform fraud liability |

### Competitive Positioning

- **Chainalysis Alterya** ($150M acquisition): Detects pig-butchering at Phase 2 (crypto transfer). No commercial API for Phase 1 (grooming conversation). **ScamShield fills Phase 1.**
- **Sift / Kount / Sardine**: Focus on transaction fraud, not conversation analysis.
- **No direct competitor** has: Conversation Arc + IP Intelligence + Profile Metadata fused API.

---

## 24. Scoring Quick-Reference

### VERIDICT Layer Weights

| Layer | Weight | Description |
|-------|--------|-------------|
| Fisher Cascade | 30% | Signal information quality |
| Conservation Laws | 25% | Communication law violations |
| Cascade Breaker | 25% | Psychological manipulation triggers |
| Immune Repertoire | 20% | Known pattern matching |

### WHOIS/SSL Score Boosts

| Signal | Boost |
|--------|-------|
| Domain < 7 days | +25 |
| Domain 7–30 days | +15 |
| Domain 30–90 days | +8 |
| SSL invalid | +15 |
| SSL unknown | +5 |

### IP Intelligence Score Boosts (cap: 40)

| Signal | Boost |
|--------|-------|
| TOR node | +35 |
| VPN/Proxy | +22 |
| Bulletproof ASN | +18 |
| Cambodia/Myanmar | +30 |
| Nigeria/Russia | +20 |
| VPS hosting | +12 |
| Cloud hosting | +3 |

### Conversation Arc Phase Weights

| Phase | Weight in Overall Risk |
|-------|----------------------|
| Collection | 40% |
| Pressure Escalation | 25% |
| Investment Hook | 20% |
| Isolation | 10% |
| Trust Development | 5% |
| Rapport Building | 0% (presence-only) |

### B2B Combined Risk Weights

| Signal Source | Weight |
|--------------|--------|
| Conversation Arc | 60% |
| IP Intelligence | 25% |
| Profile Metadata | 15% |

### Global Threat Level Thresholds

| Range | Level | Recommended Action |
|-------|-------|-------------------|
| 0–14 | SAFE | Allow |
| 15–34 | LOW | Monitor |
| 35–54 | MEDIUM | Caution |
| 55–74 | HIGH | Flag for Review |
| 75–100 | CRITICAL | Block / Immediate Intervention |

---

*End of ScamShield Algorithm Reference — 24 sections, 17 algorithm modules, 11 API routes, ~13,000 lines documented.*
