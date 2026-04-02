# Deep Scan Report
**Project**: ScamShield
**Scanned**: 2026-03-31
**Type**: Full-stack web app
**Framework**: Next.js 16.2.1 + React 19.2.4 + Supabase + Stripe (App Router)

---

## Summary
| Severity | Count |
|----------|-------|
| CRITICAL | 4 |
| HIGH | 5 |
| MEDIUM | 6 |
| LOW | 3 |
| **Total** | **18** |

---

## Critical Issues

### ROOT CAUSE of "This page couldn't load"

### SW-001 — Service Worker Caches /_next/ Chunks → Stale JS After HMR
- **File**: `public/sw.js:56`
- **Category**: Service Worker / Caching
- **Description**: The SW's catch-all cache-first handler intercepts ALL GET requests including `/_next/static/chunks/*.js`. When Next.js HMR recompiles a file (any save in dev mode), the SW serves the old cached chunk while the new chunk is fetched in the background. React receives a stale bundle → module version mismatch → JavaScript crash → browser shows "This page couldn't load". This is the primary cause of the reported error.
- **Reproduction**: Run dev server. Save any file. Reload page. Click Analyze. The SW serves the stale pre-recompile chunk and the page dies.
- **Fix**: Add `if (url.pathname.startsWith('/_next/')) return;` at the top of the fetch handler.

---

### SW-002 — SW Install Always Fails (Missing Icons)
- **File**: `public/sw.js:7`
- **Category**: Service Worker / Install Failure
- **Description**: `cache.addAll()` tries to cache `/icons/icon-192.png`, `/icons/icon-512.png`. Neither file exists in `public/`. `cache.addAll()` fails atomically → SW install fails → SW enters "redundant" state → retries on every page load forever. The SW never becomes active.
- **Reproduction**: DevTools → Application → Service Workers → see install errors on every load.
- **Fix**: Remove missing assets from `STATIC_ASSETS` or create the icon files.

---

### SEC-001 — SSRF: User URL Fetched Server-Side Without IP Validation
- **File**: `src/lib/whois-ssl.ts:71`
- **Category**: SSRF
- **Description**: `checkSSL(domain)` runs `fetch(\`https://${domain}\`)` with no IP blocklist. An attacker can submit `http://169.254.169.254/latest/meta-data` (AWS metadata), `http://localhost:6379` (Redis), or any internal service URL. The server will make the request on behalf of the attacker.
- **Reproduction**: POST `/api/scan` with `{ "type": "url", "content": "http://169.254.169.254" }`.
- **Fix**: Resolve domain to IP before any server-side fetch. Block RFC 1918 + RFC 3927 ranges.

---

### SEC-002 — SSRF: Incomplete Private IP Regex in analyzeUrlIp
- **File**: `src/lib/ip-intelligence.ts:210`
- **Category**: SSRF
- **Description**: The regex misses 169.254.0.0/16 (APIPA/link-local). A domain resolving to 169.254.169.254 passes the check.
- **Fix**: Add `169.254.` to the regex block list.

---

## High Issues

### LOGIC-001 — ReDoS: Catastrophic Regex Backtracking in cascade-breaker
- **File**: `src/lib/algorithms/cascade-breaker.ts:178`
- **Category**: ReDoS / Performance
- **Description**: Patterns like `/\b(time[- ]sensitive.{0,20}act\s+alone)\b/gi` use `.{0,20}` causing exponential backtracking. An attacker sends 10,000 chars of "time-sensitive " repeated — regex engine hangs, blocking the event loop.
- **Fix**: Replace `.{0,N}` with `[\s\w]{0,N}` or use non-backtracking patterns.

---

### MW-001 — Middleware Has No try/catch Around supabase.auth.getUser()
- **File**: `src/middleware.ts:38`
- **Category**: Error Handling
- **Description**: Every page request runs `await supabase.auth.getUser()` with no try/catch. If Supabase is down or returns a malformed response, the middleware throws an unhandled exception → Edge Runtime returns empty response → browser shows "This page couldn't load."
- **Fix**: Wrap `getUser()` in try/catch; return `NextResponse.next()` on error.

---

### FE-001 — window.location.href = data.url Without Null Check
- **File**: `src/app/pricing/page.tsx:102`
- **Category**: Navigation Safety
- **Description**: If checkout API returns `{ url: undefined }`, `window.location.href = undefined` navigates to the string "undefined" → "This page couldn't load."
- **Fix**: Add `if (!data.url) { setError('Checkout failed'); return; }` before the href assignment.

---

### BE-001 — Stripe Routes Non-Functional (Placeholder Keys)
- **File**: `.env.local:7`
- **Category**: Missing Configuration
- **Description**: `STRIPE_SECRET_KEY=sk_test_placeholder`. `getStripe()` throws when called → all `/api/stripe/*` routes return 500.
- **Fix**: Replace with a real Stripe test key from dashboard.stripe.com.

---

### LOGIC-002 — dashboard.tsx / history.tsx Swallow Supabase Errors
- **File**: `src/app/dashboard/page.tsx:48`, `src/app/history/page.tsx:55`
- **Category**: Missing Error Handling
- **Description**: `.then(({ data }) => ...)` has no `.catch()`. If Supabase query fails, `loading` stays `true` forever — infinite spinner.
- **Fix**: Add `.catch((err) => { console.error(err); setLoading(false); })`.

---

## Medium Issues

### INT-001 — Supabase Insert Errors Silently Swallowed
- **File**: `src/app/api/scan/route.ts:170`
- **Description**: Empty catch block on DB insert. Scan history silently not saved.
- **Fix**: Add `console.error('[scan] persistence failed:', err)` in the catch.

### INT-002 — Promise.all; One Throw Fails Entire Scan
- **File**: `src/app/api/scan/route.ts:98`
- **Description**: `Promise.all([runVERIDICT, whois, ip])` — one rejection fails everything. Use `Promise.allSettled()` for enrichments.

### SW-003 — SW Cache-First May Serve Error Responses
- **File**: `public/sw.js:56`
- **Description**: No guard prevents caching 404/500 responses on first fetch. A broken page can be cached indefinitely.
- **Fix**: Only cache when `response.status === 200` on all code paths.

### LOGIC-003 — Race Condition in Conversation Arc Page
- **File**: `src/app/conversation/page.tsx`
- **Description**: No debounce on Analyze button. Rapid clicks fire multiple concurrent requests.
- **Fix**: Disable button while `analyzing === true`.

### CQ-001 — as any Bypasses Type Safety
- **File**: `src/app/page.tsx:193`, `src/app/api/scan/route.ts:159`
- **Description**: `(results as any).ipIntelligence` and `(db as any).from(...)`. Add `ipIntelligence` to the `VERIDICTResult` type.

### SEC-003 — Incomplete CORS / IP Validation for rdap.org Fallback
- **File**: `src/lib/whois-ssl.ts:25`
- **Description**: RDAP and SSL checks don't validate the domain resolves to a public IP before fetching. Combined fix with SEC-001/SEC-002.

---

## Low Issues

### CQ-002 — Magic Numbers in Scoring Algorithms
- **File**: `src/lib/whois-ssl.ts`, `src/lib/ip-intelligence.ts`
- **Description**: Thresholds (7, 30, 90 days; boosts of 20, 30pts) should be named constants.

### CQ-003 — Sidebar Not Memoized
- **File**: `src/components/layout/sidebar.tsx:34`
- **Description**: No `React.memo()`. Re-runs Supabase auth check on every navigation.

### PERF-001 — extractTextFromImage Iterates Byte-by-Byte
- **File**: `src/app/api/scan/screenshot/route.ts:24`
- **Description**: 10MB image = 10M synchronous iterations blocking the event loop.

---

## Agents Activated
- Frontend & Performance Agent — all pages, components, public/
- Backend & Integration Agent — all API routes, lib/supabase, lib/stripe, .env.local
- Security, Logic & Code Quality Agent — all algorithms, all lib/ files

## Files Scanned
- Total: 53 source files
- Algorithm files: 14
- API routes: 11
- Pages: 9
- Components: 7
- Lib utilities: 6
