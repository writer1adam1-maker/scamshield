-- ============================================================================
-- Migration 003: app_config table for admin-configurable settings
-- ============================================================================

create table if not exists public.app_config (
  key        text primary key,
  value      text not null,
  updated_at timestamptz not null default now()
);

-- Insert default scan limits
insert into public.app_config (key, value)
values
  ('anonymous_scan_limit', '4'),
  ('registered_scan_limit', '10')
on conflict (key) do nothing;

-- Only service role can read/write (admin API uses service role client)
alter table public.app_config enable row level security;

-- No policies = no access from anon/authenticated clients; service role bypasses RLS
