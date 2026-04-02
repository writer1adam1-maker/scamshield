# ScamShield Threat Model
## Security Architecture & Mitigations

**Version**: 1.1.0 (Hardened)
**Date**: 2026-04-02
**Classification**: Internal — Share with security reviewers

---

## 1. System Overview

ScamShield is a website threat detection system with three components:

1. **API Server** (Vercel Edge Functions) — Scrapes URLs, detects threats, generates injection rules
2. **Browser Extension** (Chrome/Firefox MV3) — Injects protective scripts into pages
3. **SYNERGOS Engine** — Proprietary behavioral analysis algorithm

### Data Flow

```
User → Extension → API Server → Target Website
                      ↓
              Threat Analysis (SYNERGOS + VERIDICT)
                      ↓
              Signed Injection Rules
                      ↓
           Extension ← API Response
                      ↓
           Apply protections to page
```

---

## 2. Threat Matrix

### CRITICAL — Addressed

| # | Threat | Attack Vector | Mitigation | Status |
|---|--------|--------------|------------|--------|
| 1 | **SSRF** | User sends internal IP/metadata URL to `/api/vaccine/scan` | `url-validator.ts`: scheme whitelist (http/https only), private IP blocklist (127.x, 10.x, 172.16-31.x, 192.168.x, 169.254.x), cloud metadata path blocklist, DNS obfuscation detection (hex/decimal IPs blocked), redirect re-validation (max 3 hops) | ✅ Fixed |
| 2 | **Injection via own engine** | Poison cache → malicious JS injected into user pages | `payload-signer.ts`: HMAC-SHA256 on all payloads, `injection-engine.ts`: all dynamic data via JSON.stringify (never string concatenation), CSS selector allowlist, rule ID sanitization | ✅ Fixed |
| 3 | **Cache poisoning** | MITM/DNS poison during server scrape → "safe" cached for phishing site | Cache key includes content hash, re-validation after 10 hits, max 1000 entries, 24h TTL | ✅ Fixed |
| 4 | **ReDoS** | Craft HTML triggering catastrophic regex backtracking | All regexes audited: bounded quantifiers (`{0,500}`), input truncated to 512KB before processing, iteration caps on all loops (max 50 scripts, 20 forms, 100 links) | ✅ Fixed |
| 5 | **No API authentication** | Botnet uses scan endpoint as scraping proxy | `rate-limiter.ts`: 10 req/min + 60 scans/hour per IP, abuse flagging (auto-block after 3 violations), hourly cleanup | ✅ Fixed |

### HIGH — Addressed

| # | Threat | Attack Vector | Mitigation | Status |
|---|--------|--------------|------------|--------|
| 6 | **JSDOM not sandbox** | Scraped JS executes on server | Not applicable — using regex-based `WebsiteScraperEdge` (no JSDOM, no JS execution) | ✅ N/A |
| 7 | **No origin validation** | MITM API response → universal XSS | Content script verifies `response.url` hostname matches pinned `API_DOMAIN`, schema validation before injection, no blind `eval` of server responses | ✅ Fixed |
| 8 | **URL injection** | `url=javascript:alert(1)` in query param | `url-validator.ts`: strict `new URL()` parsing, scheme whitelist, credential stripping, sanitized logging | ✅ Fixed |
| 9 | **Overly broad permissions** | Extension has universal page access | Removed `clipboardRead`, `webRequest`, `tabs` permissions. Kept `activeTab` + `scripting` + `storage`. Removed `http://*/*` and `https://*/*` from `host_permissions` (only API domain). Added CSP for extension pages. | ✅ Fixed |
| 10 | **Threshold manipulation** | Attacker crafts page scoring just below block threshold | Randomized jitter (±2.5 points) on all threat level thresholds; overlapping SYNERGOS + VERIDICT detection categories; exact scores not exposed in unauthenticated responses | ✅ Fixed |

### MEDIUM — Addressed

| # | Threat | Attack Vector | Mitigation | Status |
|---|--------|--------------|------------|--------|
| 11 | **No Content-Type validation** | Scrape 10MB binary, zip bomb | `safeFetch`: validates Content-Type header (must be text/html), streams response with 512KB hard limit, aborts on oversized Content-Length | ✅ Fixed |
| 12 | **No TLS validation** | MITM via invalid cert on redirect | `safeFetch`: follows redirects manually, validates each hop URL, Vercel Edge enforces strict TLS by default | ✅ Fixed |
| 13 | **Unencrypted extension storage** | Local malware reads chrome.storage | Content script no longer stores sensitive data in storage; rules applied ephemerally per page load | ✅ Fixed |
| 14 | **No pattern signing** | Tampered threat patterns loaded | All injection payloads signed with HMAC-SHA256; content script verifies freshness (1h max age) | ✅ Fixed |
| 15 | **Cache race condition** | Concurrent requests → conflicting writes | `PENDING_REQUESTS` mutex in background script; first request scans, subsequent wait for result | ✅ Fixed |

---

## 3. Detection Capabilities Added

| Capability | Description | Implementation |
|-----------|-------------|----------------|
| **Shannon Entropy Analysis** | Obfuscated JS has measurably higher entropy (>5.5) than normal code | `threat-detector.ts`: `shannonEntropy()` on all script content |
| **Homoglyph Detection** | Catch `аpple.com` (Cyrillic) vs `apple.com` | `threat-detector.ts`: Confusable char map + known brand matching |
| **SYNERGOS Behavioral Analysis** | Intent field physics + game theory + evolution tracking | `synergos-core.ts`: 5-stage pipeline, 155ms |

---

## 4. Security Architecture

### API Layer

```
Request → Rate Limiter → URL Validator → SSRF Check
     → safeFetch (Content-Type, size limit, redirect validation)
     → Threat Analysis (VERIDICT + SYNERGOS)
     → Payload Signing (HMAC-SHA256)
     → Sanitized Response (no internal details leaked)
```

### Extension Layer

```
Page Load → Background Script → API Request (pinned domain)
     → Response Validation (origin check, schema validation, freshness check)
     → Local Protection Application (no server JS execution)
     → DOM manipulation via textContent only (no innerHTML with untrusted data)
```

### Trust Boundaries

1. **User Input → API**: Untrusted. URL validated, rate limited.
2. **API → Target Website**: Untrusted. SSRF protected, size limited, Content-Type validated.
3. **API → Extension**: Semi-trusted. Signed payloads, origin verified, schema validated.
4. **Extension → Page DOM**: Controlled. Only known-safe operations, textContent, no eval.

---

## 5. Residual Risks

| Risk | Severity | Likelihood | Mitigation Status |
|------|----------|-----------|-------------------|
| Sophisticated SSRF via DNS rebinding | Medium | Low | Partially mitigated (redirect validation helps, but DNS rebinding during fetch is hard to fully prevent without DNS resolution check) |
| Browser extension compromise via store | High | Very Low | Out of scope (Chrome Web Store review process) |
| API key theft from client-side code | Medium | Medium | Rate limiting + abuse detection is the primary defense; API keys would improve this |
| Deterministic SYNERGOS evasion | Low | Low | Threshold randomization + multi-signal consensus makes evasion hard |

---

## 6. Compliance

- **GDPR**: No personal data stored server-side. Scraped content processed ephemerally.
- **CCPA**: No sale of personal information. Extension collects only URL for analysis.
- **SOC2**: Rate limiting, access controls, audit logging in place.

---

## 7. Recommendations for Production

1. **Add API keys** — Move from IP-based to key-based rate limiting
2. **Add Redis** — Replace in-memory rate limiter and cache with persistent store
3. **Add monitoring** — Track false positive rates, prediction accuracy, abuse attempts
4. **Add WAF** — Cloudflare or Vercel Firewall for additional DDoS protection
5. **Penetration test** — Engage third-party security firm before public launch
6. **Bug bounty** — Consider responsible disclosure program

---

**Prepared for**: Security review, buyer due diligence
**Contact**: ScamShield Security Team
