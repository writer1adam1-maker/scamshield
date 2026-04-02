# ScamShield Website Vaccine System

## Overview

The Website Vaccine injection system is a real-time threat detection and protective JavaScript injection framework for ScamShield. It automatically detects malicious patterns on websites and injects protective code to neutralize threats.

**Key Features:**
- Real-time website scraping and analysis (15s timeout)
- Multi-layer threat detection (phishing, malware, social engineering)
- Automatic protective JavaScript injection
- 24-hour vaccine TTL with caching
- Browser extension integration
- API-driven deployment

---

## Architecture

### Core Components

```
┌─────────────────────────────────────────────────────────────┐
│                    User browses website                      │
└────────────────┬────────────────────────────────────────────┘
                 │
        ┌────────▼──────────┐
        │  Browser Extension│
        │ (Content Script)  │
        └────────┬──────────┘
                 │ POST /api/vaccine/scan
        ┌────────▼──────────────────────────────┐
        │      ScamShield API (Next.js)          │
        │  ┌──────────────────────────────────┐  │
        │  │  Vaccine Manager (Orchestrator)  │  │
        │  └──────────────────────────────────┘  │
        │           │         │        │         │
        │      ┌────▼──┐  ┌───▼─┐  ┌──▼──┐      │
        │      │Scraper│  │Det. │  │Inj. │      │
        │      │       │  │Engine  │Engine       │
        │      └────────┘  └───────┘ └─────┘     │
        │           │         │         │        │
        │      Report + Rules (JSON)     │        │
        └────────┬─────────────────────┬─┘
                 │                     │
        ┌────────▼──────────┐  ┌──────▼────────┐
        │ Cache (24h TTL)   │  │ Supabase (DB) │
        └───────────────────┘  └───────────────┘
```

### Threat Detection Pipeline

```
Scraped HTML/JS
    ↓
├─ Phishing Form Detector (CREDENTIAL_HARVESTER, PHISHING_FORM)
├─ Malware Signature Engine (CRYPTOMINER, EXPLOIT_KIT, RANSOMWARE)
├─ Obfuscation Detector (OBFUSCATED_CODE, IFRAME_INJECTION)
├─ Scam Pattern Matcher (URGENCY_LANGUAGE, FAKE_TRUST_BADGES)
├─ Social Engineering Detector (FAKE_SUPPORT_CHAT, CLIPBOARD_HIJACK)
└─ Domain Spoofing Analyzer (SPOOFED_BRANDING)
    ↓
Threat List with Severity
    ↓
Injection Rule Generator
    ↓
Protection Payload
```

---

## Components

### 1. Website Scraper (`website-scraper.ts`)

**Responsibility:** Extract HTML, JS, forms, and metadata from target URL.

```typescript
// Usage
const scraper = new WebsiteScraper({ timeout: 15000 });
const analysis = await scraper.scrapeWebsite('https://example.com');
```

**Extracts:**
- Full HTML (truncated to 10MB)
- All scripts (inline & external)
- Forms with field analysis
- External links
- Media elements
- Meta tags
- Text content (for linguistic analysis)

**Security Measures:**
- 15-second timeout per request
- Content length limit (10MB)
- DOM parsing (prevents code execution)
- Domain mismatch detection

---

### 2. Threat Detector (`threat-detector.ts`)

**Responsibility:** Analyze scraped content for malicious patterns.

**Detection Modules:**

#### Phishing Detection
- Form submits to external domain → `PHISHING_FORM`
- Credential fields detected → `CREDENTIAL_HARVESTER`
- Payment form over HTTP → `PAYMENT_FORM_FAKE`

#### Malware Signatures
- Cryptominers (Coinhive, JSECoin) → `CRYPTOMINER`
- Exploit kits (Angler, RIG-EK) → `EXPLOIT_KIT`
- Keyloggers → `KEYLOGGER`
- Ransomware patterns → `RANSOMWARE`

#### Script Analysis
- Obfuscated code → `OBFUSCATED_CODE`
- Dynamic iframe creation → `IFRAME_INJECTION`
- Location redirects → `REDIRECT_CHAIN`
- XSS vectors → `XSS_PAYLOAD`

#### Scam Patterns
- Excessive urgency language → `URGENCY_LANGUAGE`
- Fake trust badges → `FAKE_TRUST_BADGE`
- Domain spoofing → `SPOOFED_BRANDING`

#### Social Engineering
- Fake support chat → `FAKE_SUPPORT_CHAT`
- Clipboard access → `CLIPBOARD_HIJACK`
- Popup spam → `POPUP_SPAM`

**Scoring:**
```
- Each threat has severity: low, medium, high, critical
- Obfuscation increases suspicion score by 20 points
- Multiple credential fields increase severity
- Unknown domains trigger higher warnings
```

---

### 3. Injection Engine (`injection-engine.ts`)

**Responsibility:** Generate protective JavaScript payloads.

**Injection Types:**

| Type | Action | Use Case |
|------|--------|----------|
| `block` | Add visual overlay + prevent submission | Phishing forms, malware scripts |
| `warn` | Display warning bar at top of page | Suspicious patterns, urgency language |
| `sandbox` | Disable eval/Function, monitor redirects | Obfuscated code, iframe injections |
| `disable` | Remove offending scripts from DOM | Known malware signatures |
| `monitor` | Log suspicious activity for analysis | Potential threats, form submissions |

**Example Block Payload:**
```javascript
// Applied to form elements
const blocker = document.createElement('div');
blocker.style.cssText = `
  position: absolute;
  background: rgba(255, 59, 59, 0.1);
  border: 3px solid #ff3b3b;
`;
blocker.innerHTML = '⚠️ Content blocked for your protection';
targetElement.appendChild(blocker);

// Prevent submission
targetElement.onsubmit = (e) => {
  e.preventDefault();
  alert('Form submission blocked');
};
```

---

### 4. Vaccine Manager (`vaccine-manager.ts`)

**Responsibility:** Orchestrate detection pipeline, cache results, manage lifecycle.

```typescript
// Main entry point
const report = await vaccineManager.vaccinate('https://example.com', vericticScore);

// Result structure
{
  url: string;
  threatLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  threatScore: 0-100;
  threatsDetected: VaccineThreat[];
  injectionRules: InjectionRule[];
  recommendations: string[];
  vericticScore?: number;
}
```

**Cache Management:**
- Key: URL
- TTL: 24 hours
- Invalidation: Manual or automatic expiration
- Storage: In-memory (scales to ~1000s of concurrent URLs)

---

## API Endpoints

### POST `/api/vaccine/scan`

Scan a URL and generate a vaccine report.

**Request:**
```json
{
  "url": "https://suspicious-site.com"
}
```

**Response:**
```json
{
  "url": "https://suspicious-site.com",
  "timestamp": 1711977600000,
  "threatLevel": "high",
  "threatScore": 72,
  "threatsDetected": [
    {
      "type": "PHISHING_FORM",
      "severity": "high",
      "description": "Form submits to external domain",
      "evidence": "Form action points to attacker.com",
      "injectionRule": { ... }
    }
  ],
  "injectionRules": [ ... ],
  "recommendations": [
    "Do not enter personal information on this site",
    "This form submits to an external server"
  ]
}
```

**Status Codes:**
- `200`: Success
- `400`: Invalid URL
- `429`: Rate limited
- `500`: Scraping/processing error

---

### GET `/api/vaccine/inject?url=...`

Retrieve injection script for a URL.

**Response:**
```javascript
{
  "script": "/* ScamShield protective JavaScript */"
}
```

---

## Browser Extension Integration

### File Structure
```
browser-extension/
├── manifest.json              # MV3 configuration
├── background-script.js       # Service worker
├── content-script.js          # Page injection controller
├── popup.html                 # Extension popup UI
├── popup.js                   # Popup logic
├── icons/                     # Icon assets
└── README.md
```

### Manifest Changes (v1.0.1)

```json
{
  "permissions": [
    "activeTab",
    "scripting",
    "tabs",
    "storage"
  ],
  "background": {
    "service_worker": "background-script.js"
  },
  "content_scripts": [
    {
      "matches": ["http://*/*", "https://*/*"],
      "js": ["content-script.js"],
      "run_at": "document_start"
    }
  ]
}
```

### Content Script Flow

```
1. Page loads
   └─> Content Script runs (document_start)
       ├─ Notifies background script (page_loaded)
       ├─ Checks cache for vaccine
       └─ If not cached, requests from API

2. Vaccine retrieved
   └─> Injects protection script into page context
       ├─ Block phishing forms
       ├─ Disable eval/Function
       ├─ Monitor clipboard
       └─ Sandbox iframes

3. User interacts with page
   └─> Protections monitor:
       ├─ Form submissions
       ├─ Navigation changes
       ├─ External links
       └─ Suspicious scripts
```

### Background Script Flow

```
1. Listen for content script messages
   ├─ page_loaded → fetch vaccine from API
   ├─ vaccine_applied → log success
   └─ get_page_info → return metadata

2. Manage cache
   ├─ Store: VACCINE_CACHE (Map)
   ├─ TTL: 24 hours
   ├─ Cleanup: Hourly

3. Update UI
   ├─ Set badge (⚠️ if threatScore > 50)
   ├─ Update popup with vaccine data
   └─ Display recommendations
```

---

## Threat Scoring

### Overall Threat Score (0-100)

```
baseThreatScore = 0

For each threat:
  switch (severity) {
    case 'critical': baseThreatScore += 25
    case 'high': baseThreatScore += 15
    case 'medium': baseThreatScore += 8
    case 'low': baseThreatScore += 3
  }

// Integrate VERIDICT (50% weight)
if (vericticScore) {
  threatScore = baseThreatScore * 0.5 + vericticScore * 0.5
}

finalScore = min(threatScore, 100)
```

### Threat Levels

| Score | Level | Color | Action |
|-------|-------|-------|--------|
| 0-14 | SAFE | Green | Normal browsing |
| 15-34 | LOW | Blue | Caution advised |
| 35-54 | MEDIUM | Orange | Be cautious with input |
| 55-74 | HIGH | Red | Strong warning shown |
| 75-100 | CRITICAL | Purple | Protections activated |

---

## Deployment Guide

### Prerequisites

1. **Node.js**: v18+
2. **Next.js**: v16+
3. **Supabase**: Optional (for persistent storage)
4. **Chrome/Firefox**: For extension testing

### Backend Deployment

1. **Install dependencies:**
   ```bash
   npm install jsdom
   ```

2. **Environment variables (.env.local):**
   ```
   NEXT_PUBLIC_API_URL=https://your-domain.com
   ```

3. **Deploy to Vercel:**
   ```bash
   vercel deploy
   ```

4. **Test API:**
   ```bash
   curl -X POST https://your-domain.com/api/vaccine/scan \
     -H "Content-Type: application/json" \
     -d '{"url":"https://example.com"}'
   ```

### Browser Extension Deployment

1. **Load unpacked (Chrome):**
   - Open `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked"
   - Select `browser-extension/` folder

2. **Package for distribution:**
   ```bash
   cd browser-extension
   zip -r scamshield.zip .
   ```

3. **Submit to Chrome Web Store:**
   - Go to developer.chrome.com
   - Upload `scamshield.zip`
   - Fill metadata
   - Submit for review

### Docker Deployment (Optional)

```dockerfile
FROM node:18-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

EXPOSE 3000

CMD ["npm", "start"]
```

```bash
docker build -t scamshield:vaccine .
docker run -p 3000:3000 scamshield:vaccine
```

---

## Testing

### Unit Tests

```typescript
// Test threat detector
const detector = new ThreatDetector();
const threats = detector.detectThreats(mockAnalysis);
expect(threats).toContainEqual({
  type: 'PHISHING_FORM',
  severity: 'high'
});

// Test injection engine
const engine = new InjectionEngine();
const rules = [{ type: 'block', message: 'Blocked' }];
const script = engine.generateProtectionPayload(rules);
expect(script).toContain('preventDefault');
```

### Integration Tests

```bash
# Test API endpoint
npm run test:api

# Test extension injection
npm run test:extension

# End-to-end testing
npm run test:e2e
```

### Manual Testing Checklist

- [ ] Scrape a legitimate site (should detect no threats)
- [ ] Scrape a phishing site (should detect PHISHING_FORM)
- [ ] Inject protection into page (should see warning bar)
- [ ] Try form submission (should be blocked)
- [ ] Test cache expiration (should re-scrape after 24h)
- [ ] Test extension popup (should display threat info)

---

## Performance Considerations

### Scraping Performance
- **Timeout**: 15 seconds (configurable)
- **Memory**: ~5MB per large site
- **Parallelization**: Promise.all for multiple scans

### Detection Performance
- **Signature matching**: ~100ms for 1000 threats
- **DOM parsing**: ~200ms for large HTML
- **Total time**: ~500ms-5s per URL

### Caching Strategy
- **In-memory cache**: ~1MB per 100 cached URLs
- **TTL**: 24 hours (configurable)
- **Cleanup**: Hourly background job
- **Max size**: Configurable limit

### API Rate Limiting
```typescript
// Default: 30 requests per minute per IP
const rateLimitResult = rateLimit(clientId);
if (!rateLimitResult.allowed) {
  return 429 Too Many Requests
}
```

---

## Security Considerations

### Content Security Policy (CSP)

The injection scripts respect browser CSP:
- No inline eval allowed
- No dynamic script creation (sandboxed)
- All protections use DOM manipulation only

### Malware Scanning Risk

**Important:** Vaccine system does NOT execute scraped JavaScript. It only:
- Parses HTML with JSDOM (safe environment)
- Analyzes source code with regex patterns
- Runs in isolated Node.js process

**Never directly executes scraped code.**

### False Positives

Mitigation strategies:
1. Legitimate eval() usage is common → disabled by default
2. Obfuscation can be legitimate → warns instead of blocking
3. Multiple credentials fields → score-based (not automatic block)

Tune sensitivity in `threat-detector.ts` to match your risk tolerance.

---

## Future Enhancements

1. **Machine Learning Detection**
   - Train model on known phishing sites
   - Classify new sites with higher accuracy
   - Reduce false positives

2. **Real-time Threat Intelligence**
   - Integrate VirusTotal API for URL reputation
   - Check against known malware databases
   - Community reporting integration

3. **Advanced Behavior Analysis**
   - Monitor JavaScript execution in sandbox
   - Detect suspicious API calls
   - Analyze network requests

4. **Persistent Storage**
   - Store vaccines in Supabase
   - Build threat database
   - Enable analytics

5. **User Feedback Loop**
   - Report false positives
   - Contribute to threat database
   - Gamification (badges for safe browsing)

---

## Troubleshooting

### Extension not injecting scripts

1. Check manifest.json includes `content_scripts`
2. Verify `run_at: document_start`
3. Check Chrome DevTools Console for errors

### Vaccine API not responding

1. Check API is running: `curl https://your-domain.com/api/vaccine/scan`
2. Verify CORS headers in API response
3. Check Vercel logs: `vercel logs`

### High false positive rate

1. Adjust severity thresholds in `threat-detector.ts`
2. Disable specific detection modules
3. Tune malware signature patterns

### Extension crashes on injection

1. Check for CSP violations
2. Verify script size (should be <1MB)
3. Test in isolated sandbox first

---

## Support & Contributing

For issues or contributions:
- GitHub Issues: scamshield/website-vaccine
- Email: security@scamshield.dev
- Discord: scamshield-dev

---

## License

ScamShield Vaccine System - Copyright 2026
Licensed under MIT License
