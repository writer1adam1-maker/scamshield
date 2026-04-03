-- ============================================================================
-- Migration 006: WHOIS + IP cache tables to reduce external API costs
-- ============================================================================

create table if not exists public.whois_cache (
  domain      text primary key,
  result      jsonb not null default '{}',
  cached_at   timestamptz not null default now()
);

create table if not exists public.ip_cache (
  ip          text primary key,
  result      jsonb not null default '{}',
  cached_at   timestamptz not null default now()
);

-- Auto-delete entries older than 24 hours (run via pg_cron or periodic cleanup)
-- Index for fast cache expiry checks
create index if not exists whois_cache_cached_at_idx on public.whois_cache(cached_at);
create index if not exists ip_cache_cached_at_idx    on public.ip_cache(cached_at);

-- Service role only — no client access needed
alter table public.whois_cache enable row level security;
alter table public.ip_cache    enable row level security;
