-- ============================================================================
-- 008 — Gmail Shield integration tables
-- Stores OAuth connections + per-email scan results
-- Email body content is NEVER persisted (only subject preview + scan result)
-- ============================================================================

-- API key lookup index (needed for extension queries)
CREATE INDEX IF NOT EXISTS api_keys_last_used_at_idx ON public.api_keys(last_used_at DESC);

-- ── gmail_connections ────────────────────────────────────────────────────────
-- One row per ScamShield user with a connected Gmail account
CREATE TABLE IF NOT EXISTS public.gmail_connections (
  id                        uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id                   uuid        NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  google_email              text        NOT NULL,
  encrypted_refresh_token   text        NOT NULL,  -- AES-256-GCM encrypted, base64(iv:ciphertext)
  history_id                text,                   -- last Gmail historyId processed for incremental sync
  connected_at              timestamptz NOT NULL DEFAULT now(),
  last_polled_at            timestamptz,
  emails_scanned_total      integer     NOT NULL DEFAULT 0,
  threats_found_total       integer     NOT NULL DEFAULT 0,
  is_active                 boolean     NOT NULL DEFAULT true,
  UNIQUE(user_id)           -- one Gmail account per ScamShield user
);

ALTER TABLE public.gmail_connections ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can read own Gmail connection"
  ON public.gmail_connections FOR SELECT
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own Gmail connection"
  ON public.gmail_connections FOR DELETE
  USING (auth.uid() = user_id);

-- Service role (cron poll) can do everything
CREATE POLICY "Service role full access on gmail_connections"
  ON public.gmail_connections FOR ALL
  USING (true)
  WITH CHECK (true);

-- ── gmail_scan_results ───────────────────────────────────────────────────────
-- One row per scanned email — no body content stored, only metadata + result
CREATE TABLE IF NOT EXISTS public.gmail_scan_results (
  id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id           uuid        NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
  gmail_message_id  text        NOT NULL,    -- Gmail message ID (not the email content)
  sender_domain     text,                    -- domain extracted from From header
  subject_preview   text,                    -- first 80 chars of subject
  received_at       timestamptz,             -- Date header of the email
  score             integer     NOT NULL,    -- 0-100 VERIDICT score
  threat_level      text        NOT NULL,    -- SAFE | LOW | MEDIUM | HIGH | CRITICAL
  category          text        NOT NULL,    -- ThreatCategory enum value
  evidence_json     jsonb       NOT NULL DEFAULT '[]',
  scanned_at        timestamptz NOT NULL DEFAULT now(),
  UNIQUE(user_id, gmail_message_id)
);

CREATE INDEX IF NOT EXISTS gmail_scan_results_user_id_idx      ON public.gmail_scan_results(user_id);
CREATE INDEX IF NOT EXISTS gmail_scan_results_scanned_at_idx   ON public.gmail_scan_results(scanned_at DESC);
CREATE INDEX IF NOT EXISTS gmail_scan_results_threat_level_idx ON public.gmail_scan_results(threat_level);

ALTER TABLE public.gmail_scan_results ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can read own Gmail scan results"
  ON public.gmail_scan_results FOR SELECT
  USING (auth.uid() = user_id);

-- Service role (cron poll) can insert results
CREATE POLICY "Service role full access on gmail_scan_results"
  ON public.gmail_scan_results FOR ALL
  USING (true)
  WITH CHECK (true);
