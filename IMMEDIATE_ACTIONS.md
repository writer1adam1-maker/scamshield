# 🚀 Immediate Actions Required

## Status: 6/8 Issues Fixed ✅ — Code Ready for Deployment

Your application code is now fully audited and fixed. The build passes TypeScript strict mode. However, **2 critical actions** must be completed before the app is fully functional:

---

## Action 1️⃣: Apply Supabase Migration (CRITICAL)

**⏱️ Estimated Time:** 2 minutes

This migration fixes security-critical RLS policies that currently allow unauthorized access.

### Step-by-Step:

1. **Open** [Supabase Dashboard](https://app.supabase.com)
2. **Select** your ScamShieldy project
3. **Click** "SQL Editor" in the left sidebar
4. **Click** "+ New Query" button
5. **Paste** the entire contents of this file:
   ```
   supabase/migrations/002_fix_rls_and_quotas.sql
   ```
6. **Click** the "Run" button (or Ctrl+Enter)
7. **Wait** for green checkmark ✅
8. **Verify:** No error messages in the output

**What this does:**
- ✅ Secures the scans table (prevents anonymous insert abuse)
- ✅ Enables delete policies (needed for account deletion)
- ✅ Activates quota enforcement
- ❌ Without this: your security measures won't work

---

## Action 2️⃣: Complete Google OAuth Setup (BLOCKING)

**⏱️ Estimated Time:** 5 minutes

### Step 1: Get Your Client Secret

1. **Open** [Google Cloud Console](https://console.cloud.google.com)
2. **Select** your ScamShieldy project
3. **Navigate:** APIs & Services → Credentials (left sidebar)
4. **Find** your OAuth 2.0 Client ID (should say "Web application")
5. **Click** the edit icon (pencil) to open it
6. **Copy** the "Client Secret" value (shown in the modal)
7. **Keep** it visible while doing Step 2

### Step 2: Register with Supabase

1. **Open** [Supabase Dashboard](https://app.supabase.com) (new tab)
2. **Select** your ScamShieldy project
3. **Click** "Authentication" in left sidebar
4. **Click** "Providers" tab
5. **Find** "Google" in the list
6. **Click** the Google row
7. **Toggle** the switch to ON (blue)
8. **Paste** your Client ID (from Google Cloud)
9. **Paste** your Client Secret (from Google Cloud)
10. **Click** "Save" button
11. **Wait** for green checkmark ✅

**What this does:**
- ✅ Enables "Sign in with Google" button
- ✅ Users can create accounts via Google
- ✅ Automatic sync with Supabase auth
- ❌ Without this: login won't work

---

## Action 3️⃣: Deploy (When Ready)

Once Actions 1 & 2 are complete, your app is ready to deploy:

```bash
# Commit your changes
git add -A
git commit -m "Audit fixes: auth integration, quota enforcement, API validation"

# Deploy to Vercel
vercel deploy

# Or for production:
vercel deploy --prod
```

---

## Verify Everything Works

After completing Actions 1 & 2, test these features:

### Test Free User Quota (15 scans/day)
- [ ] Log in as free user
- [ ] Scan 15 URLs/texts
- [ ] 16th scan returns 429 error: "Daily scan limit reached"
- [ ] Next day (UTC), quota resets

### Test Pro User (Unlimited)
- [ ] Log in as pro user
- [ ] Scan 50+ items
- [ ] No rate limit errors
- [ ] All scans saved in history

### Test Screenshot Endpoint
- [ ] Upload screenshot as free user
- [ ] Verify it counts toward 15/day limit
- [ ] Verify `scan_count_today` increments in Supabase

### Test Feedback Submission
- [ ] Complete a scan
- [ ] Click "Report as Scam" button
- [ ] Check browser DevTools → Network
- [ ] Verify POST to /api/feedback succeeds (201 status)
- [ ] Verify data appears in `community_reports` table

### Test Google OAuth
- [ ] Click "Sign in with Google"
- [ ] Use test Google account (must be added to OAuth consent screen)
- [ ] Verify successful login
- [ ] Check Supabase → Authentication → Users (shows new user)

### Test API v1 Endpoint
```bash
# Get an API key from /settings (after logging in as pro user)
# Then test with curl:

curl -X POST https://scamshieldy.com/api/v1/scan \
  -H "X-API-Key: ss_live_YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{"type":"url", "content":"https://example.com"}'

# Should return:
# - 200 status
# - X-RateLimit-Limit: 10000 (pro) or 100 (free)
# - X-RateLimit-Remaining: decrements with each call
# - X-RateLimit-Reset: unix timestamp
```

---

## Troubleshooting

### "Migration failed with syntax error"
→ Check you pasted the entire file contents (all lines including trailing semicolons)

### "Google OAuth button doesn't work"
→ Verify:
- [ ] Client Secret is correct (not Client ID)
- [ ] You toggled the Google provider ON (toggle is blue)
- [ ] You clicked Save
- [ ] Your Google test user is on the OAuth consent screen

### "Quota not enforcing"
→ Migration not applied. Go back to **Action 1** and run the SQL.

### "Feedback submissions fail"
→ Check browser console for errors. Verify:
- [ ] You're logged in
- [ ] /api/feedback endpoint exists (should in route list)
- [ ] No TypeScript errors in build (run `npm run build`)

### "API rate limit not working"
→ Verify:
- [ ] API key exists in your users' api_keys table
- [ ] API key is marked as "pro" or "free" plan
- [ ] API key is not revoked (`revoked_at IS NULL`)

---

## Summary

| Step | Status | Blocker? | Time |
|------|--------|----------|------|
| Code Audit Fixes | ✅ Complete | No | Done |
| Supabase Migration | ⏳ Pending | YES | 2 min |
| Google OAuth Setup | ⏳ Pending | YES | 5 min |
| Deployment | ⏳ Ready | No | 1 min |
| **Total Time** | | | **~8 minutes** |

---

**Ready to get started?** Begin with [Action 1](#action-1️⃣-apply-supabase-migration-critical) above!

Need help? Check `AUDIT_REPORT.md` and `FIXES_SUMMARY.md` for detailed explanations of each fix.
