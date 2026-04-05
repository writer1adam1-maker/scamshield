-- Add email digest preferences to gmail_connections
ALTER TABLE gmail_connections
  ADD COLUMN IF NOT EXISTS digest_frequency text NOT NULL DEFAULT 'daily'
    CHECK (digest_frequency IN ('hourly', '12h', 'daily', 'weekly', 'never')),
  ADD COLUMN IF NOT EXISTS last_digest_sent_at timestamptz NULL,
  ADD COLUMN IF NOT EXISTS user_email text NULL;
