# Website Vaccine API Reference

## Quick Reference

### POST /api/vaccine/scan

Scan a website and generate a threat report.

```bash
curl -X POST https://scamshield.vercel.app/api/vaccine/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

**Status:** 200 OK
```json
{
  "url": "https://example.com",
  "timestamp": 1711977600000,
  "threatLevel": "safe",
  "threatScore": 5,
  "threatsDetected": [],
  "injectionRules": [],
  "recommendations": ["This site appears to be safe."],
  "scrapedAnalysis": {
    "url": "https://example.com",
    "title": "Example Domain",
    "domain": "example.com",
    "scripts": [],
    "forms": [],
    "links": [],
    "isDomainMatch": false
  }
}
```

---

### GET /api/vaccine/inject?url=...

Get protective JavaScript for a URL.

```bash
curl "https://scamshield.vercel.app/api/vaccine/inject?url=https://example.com"
```

**Status:** 200 OK
```json
{
  "script": "/* ScamShield protective JavaScript */...",
  "url": "https://example.com"
}
```

---

## Response Examples

### HIGH Threat Website

```json
{
  "url": "https://phishing-site.example.com",
  "threatLevel": "high",
  "threatScore": 72,
  "threatsDetected": [
    {
      "type": "PHISHING_FORM",
      "severity": "high",
      "description": "Form submits to external domain: attacker.com",
      "evidence": "Form action points to attacker.com instead of phishing-site.example.com",
      "injectionRule": {
        "id": "phishing-form-0",
        "type": "block",
        "selector": "form[0]",
        "message": "This form submits to an external server. Blocked for your protection.",
        "expiresAt": 1712064000000
      }
    },
    {
      "type": "CREDENTIAL_HARVESTER",
      "severity": "high",
      "description": "Form contains 2 credential fields",
      "evidence": "Fields: email, password",
      "injectionRule": {
        "id": "credential-harvest-0",
        "type": "warn",
        "selector": "form[0]",
        "message": "This form is requesting sensitive information. Be cautious.",
        "expiresAt": 1712064000000
      }
    }
  ],
  "recommendations": [
    "CRITICAL: Do not enter any personal information on this site.",
    "This site contains suspicious forms. Avoid entering sensitive information.",
    "This site is impersonating a major company. Verify it's the official website before logging in."
  ]
}
```

### MEDIUM Threat Website

```json
{
  "url": "https://suspicious-site.example.com",
  "threatLevel": "medium",
  "threatScore": 45,
  "threatsDetected": [
    {
      "type": "OBFUSCATED_CODE",
      "severity": "medium",
      "description": "Highly obfuscated script detected",
      "evidence": "Script uses excessive obfuscation techniques",
      "injectionRule": {
        "id": "obfuscated-0",
        "type": "warn",
        "message": "This script is heavily obfuscated and may be suspicious.",
        "expiresAt": 1712064000000
      }
    },
    {
      "type": "URGENCY_LANGUAGE",
      "severity": "medium",
      "description": "Page uses excessive urgency language (4 instances)",
      "evidence": "Found: act now, limited time, urgent, immediately",
      "injectionRule": {
        "id": "urgency-1711977600000",
        "type": "warn",
        "message": "This page uses high-pressure tactics. Take time to verify before acting.",
        "expiresAt": 1712064000000
      }
    }
  ],
  "recommendations": [
    "Review the detected threats above before interacting with this site.",
    "This site contains obfuscated scripts. This is often used to hide malicious code."
  ]
}
```

### SAFE Website

```json
{
  "url": "https://google.com",
  "threatLevel": "safe",
  "threatScore": 2,
  "threatsDetected": [],
  "injectionRules": [],
  "recommendations": [
    "This site appears to be safe. You can proceed with normal browsing."
  ]
}
```

---

## Threat Types

### Phishing
- `PHISHING_FORM` — Form submits to external domain
- `CREDENTIAL_HARVESTER` — Requesting credentials
- `PAYMENT_FORM_FAKE` — Payment form over HTTP

### Malware
- `MALWARE_SIGNATURE` — Known malware pattern
- `EXPLOIT_KIT` — Exploit kit detected
- `CRYPTOMINER` — Cryptocurrency miner
- `KEYLOGGER` — Keylogging capability
- `RANSOMWARE` — Ransomware pattern

### Scripts
- `OBFUSCATED_CODE` — Heavily obfuscated JavaScript
- `IFRAME_INJECTION` — Dynamic iframe creation
- `REDIRECT_CHAIN` — Page redirection code
- `XSS_PAYLOAD` — XSS vulnerability

### Scams
- `URGENCY_LANGUAGE` — High-pressure tactics
- `FAKE_TRUST_BADGE` — Fake security seals
- `SPOOFED_BRANDING` — Domain impersonation
- `FAKE_REVIEWS` — Fake testimonials

### Social Engineering
- `FAKE_SUPPORT_CHAT` — Fake support interface
- `FAKE_URGENCY` — Artificial time pressure
- `CLIPBOARD_HIJACK` — Clipboard access
- `POPUP_SPAM` — Excessive popups

---

## Threat Levels

| Level | Score | Color | Meaning |
|-------|-------|-------|---------|
| SAFE | 0-14 | Green | No threats detected |
| LOW | 15-34 | Blue | Minor concerns |
| MEDIUM | 35-54 | Orange | Be cautious |
| HIGH | 55-74 | Red | Strong warning |
| CRITICAL | 75-100 | Purple | Major threats |

---

## Injection Rule Types

| Type | Action | Effect |
|------|--------|--------|
| `block` | Add overlay + prevent submission | Blocks dangerous interaction |
| `warn` | Display warning bar | User can dismiss and continue |
| `sandbox` | Disable eval/Function, monitor redirects | Limits code execution |
| `disable` | Remove script from DOM | Eliminates threat source |
| `monitor` | Log suspicious activity | Tracks threats for analysis |

---

## Error Responses

### 400 Bad Request
```json
{
  "error": "URL is required"
}
```

### 429 Rate Limited
```json
{
  "error": "Rate limit exceeded"
}
```

### 500 Server Error
```json
{
  "error": "Failed to scrape website: Connection timeout after 15000ms"
}
```

---

## Integration Examples

### Node.js / Express

```javascript
const express = require('express');
const app = express();

app.post('/check-url', async (req, res) => {
  const { url } = req.body;

  const response = await fetch('https://scamshield.vercel.app/api/vaccine/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url })
  });

  const vaccine = await response.json();

  if (vaccine.threatScore > 70) {
    res.json({ warning: 'Website appears dangerous' });
  } else {
    res.json({ status: 'safe' });
  }
});
```

### Python

```python
import requests

def check_url(url):
    response = requests.post(
        'https://scamshield.vercel.app/api/vaccine/scan',
        json={'url': url}
    )
    vaccine = response.json()
    return vaccine['threatLevel']

threat_level = check_url('https://example.com')
print(f"Threat Level: {threat_level}")
```

### JavaScript (Browser)

```javascript
async function vaccinate(url) {
  const response = await fetch('/api/vaccine/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url })
  });

  const vaccine = await response.json();

  if (vaccine.threatLevel === 'critical') {
    alert('⚠️ This site is dangerous!');
  }

  return vaccine;
}

// Usage
const report = await vaccinate('https://suspicious.com');
console.log(report.recommendations);
```

### cURL

```bash
# Scan URL
curl -X POST https://scamshield.vercel.app/api/vaccine/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}' | jq .

# Get threat level only
curl -s https://scamshield.vercel.app/api/vaccine/scan \
  -d '{"url":"https://example.com"}' | jq '.threatLevel'

# Get threats detected
curl -s https://scamshield.vercel.app/api/vaccine/scan \
  -d '{"url":"https://example.com"}' | jq '.threatsDetected[]'
```

---

## Rate Limiting

**Default Limits:**
- 30 requests per minute per IP address
- Escalates to 5 minute blocks after 3 consecutive limits

**Response Headers:**
```
X-RateLimit-Limit: 30
X-RateLimit-Remaining: 25
X-RateLimit-Reset: 1711977660
```

---

## Performance Tips

1. **Cache results:** Store vaccine reports for 24 hours
2. **Batch processing:** Queue multiple scans instead of sequential
3. **Filter by score:** Only process threatScore > 50
4. **Use webhooks:** Get notified instead of polling

---

## Common Use Cases

### #1: Pre-link Check
```javascript
// Before showing link to user
const vaccine = await fetch('/api/vaccine/scan', {
  method: 'POST',
  body: JSON.stringify({ url: suspiciousUrl })
}).then(r => r.json());

if (vaccine.threatScore > 50) {
  showWarning(`This link may be dangerous (${vaccine.threatLevel})`);
}
```

### #2: User Email Scanner
```javascript
// Check links in user emails
function scanEmailLinks(email) {
  const urlRegex = /(https?:\/\/[^\s]+)/g;
  const urls = email.match(urlRegex) || [];

  return Promise.all(
    urls.map(url =>
      fetch('/api/vaccine/scan', {
        method: 'POST',
        body: JSON.stringify({ url })
      }).then(r => r.json())
    )
  );
}
```

### #3: Content Moderation
```javascript
// Flag user-submitted content
async function moderateUserContent(userUrl) {
  const vaccine = await fetch('/api/vaccine/scan', {
    method: 'POST',
    body: JSON.stringify({ url: userUrl })
  }).then(r => r.json());

  if (vaccine.threatLevel === 'critical') {
    return { action: 'block', reason: 'malicious_content' };
  }

  if (vaccine.threatLevel === 'high') {
    return { action: 'review', reason: 'high_threat' };
  }

  return { action: 'allow' };
}
```

### #4: Browser Extension
```javascript
// Inject vaccine on every page
chrome.webNavigation.onCommitted.addListener(async (details) => {
  const vaccine = await fetch('/api/vaccine/inject', {
    method: 'GET',
    url: `/api/vaccine/inject?url=${encodeURIComponent(details.url)}`
  }).then(r => r.json());

  if (vaccine.script) {
    chrome.scripting.executeScript({
      target: { tabId: details.tabId },
      function: (script) => {
        const s = document.createElement('script');
        s.textContent = script;
        document.head.appendChild(s);
      },
      args: [vaccine.script]
    });
  }
});
```

---

## Pricing (Future)

| Tier | Requests/Month | Cost | Features |
|------|----------------|------|----------|
| Free | 1,000 | Free | Basic scanning |
| Pro | 100,000 | $49 | Priority support |
| Enterprise | Unlimited | Custom | Custom rules, webhooks |

---

## Support

- **Docs:** https://scamshield.dev/docs/vaccine
- **Issues:** https://github.com/scamshield/vaccine/issues
- **Email:** support@scamshield.dev
- **Discord:** discord.gg/scamshield

---

**Last Updated:** April 2, 2026
**API Version:** 1.0.0
**Status:** Production ✓
