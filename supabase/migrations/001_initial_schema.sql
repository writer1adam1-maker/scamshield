-- ============================================================================
-- ScamShield — Initial Schema Migration
-- Run via: supabase db push  OR  paste into Supabase SQL editor
-- ============================================================================

-- ---------------------------------------------------------------------------
-- users — extends Supabase auth.users with plan/billing info
-- ---------------------------------------------------------------------------
create table if not exists public.users (
  id                    uuid        primary key references auth.users(id) on delete cascade,
  email                 text        not null,
  plan                  text        not null default 'free' check (plan in ('free', 'pro')),
  stripe_customer_id    text        unique,
  stripe_subscription_id text       unique,
  scan_count_today      integer     not null default 0,
  scan_count_total      integer     not null default 0,
  created_at            timestamptz not null default now(),
  updated_at            timestamptz not null default now()
);

-- Auto-create user row when auth.users is created
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.users (id, email)
  values (new.id, new.email)
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- Auto-update updated_at
create or replace function public.set_updated_at()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger users_updated_at
  before update on public.users
  for each row execute function public.set_updated_at();

-- RLS
alter table public.users enable row level security;

create policy "Users can read own row"
  on public.users for select
  using (auth.uid() = id);

create policy "Users can update own row"
  on public.users for update
  using (auth.uid() = id)
  with check (auth.uid() = id);

-- ---------------------------------------------------------------------------
-- scans — every VERIDICT analysis run
-- ---------------------------------------------------------------------------
create table if not exists public.scans (
  id            uuid        primary key default gen_random_uuid(),
  user_id       uuid        references public.users(id) on delete set null,
  input_type    text        not null check (input_type in ('url', 'text', 'screenshot')),
  input_preview text        not null,           -- first 200 chars of input
  score         integer     not null,            -- 0-100
  threat_level  text        not null,            -- SAFE | LOW | MEDIUM | HIGH | CRITICAL
  category      text        not null,            -- ThreatCategory enum value
  result_json   jsonb       not null default '{}', -- full VERIDICTResult
  ip_address    text,
  created_at    timestamptz not null default now()
);

create index if not exists scans_user_id_idx      on public.scans(user_id);
create index if not exists scans_created_at_idx   on public.scans(created_at desc);
create index if not exists scans_category_idx     on public.scans(category);
create index if not exists scans_threat_level_idx on public.scans(threat_level);

-- RLS
alter table public.scans enable row level security;

create policy "Users can read own scans"
  on public.scans for select
  using (auth.uid() = user_id);

create policy "Service role can insert scans"
  on public.scans for insert
  with check (true); -- service role bypasses RLS; anon inserts allowed for unauthenticated scans

-- ---------------------------------------------------------------------------
-- community_reports — user-submitted scam reports / false positive feedback
-- ---------------------------------------------------------------------------
create table if not exists public.community_reports (
  id              uuid        primary key default gen_random_uuid(),
  content_type    text        not null check (content_type in ('url', 'text')),
  content_preview text        not null,
  is_scam         boolean     not null,
  category        text,
  details         text,
  ip_hash         text,       -- SHA-256 hash of IP for spam detection (never raw IP)
  created_at      timestamptz not null default now()
);

create index if not exists community_reports_is_scam_idx    on public.community_reports(is_scam);
create index if not exists community_reports_created_at_idx on public.community_reports(created_at desc);

-- RLS — community reports are write-only from client, read via service role
alter table public.community_reports enable row level security;

create policy "Anyone can submit a report"
  on public.community_reports for insert
  with check (true);

-- No select policy for anon — only service role reads aggregate stats

-- ---------------------------------------------------------------------------
-- api_keys — for public REST API (/api/v1/scan)
-- ---------------------------------------------------------------------------
create table if not exists public.api_keys (
  id            uuid        primary key default gen_random_uuid(),
  user_id       uuid        not null references public.users(id) on delete cascade,
  key_prefix    text        not null unique,     -- e.g. ss_live_XXXX (first 16 chars)
  key_hash      text        not null unique,     -- bcrypt hash of full key
  plan          text        not null default 'free' check (plan in ('free', 'pro')),
  label         text        not null default 'Default',
  requests_today integer    not null default 0,
  requests_total integer    not null default 0,
  last_used_at  timestamptz,
  revoked_at    timestamptz,
  created_at    timestamptz not null default now()
);

create index if not exists api_keys_user_id_idx    on public.api_keys(user_id);
create index if not exists api_keys_key_prefix_idx on public.api_keys(key_prefix);

alter table public.api_keys enable row level security;

create policy "Users can read own API keys"
  on public.api_keys for select
  using (auth.uid() = user_id);

create policy "Users can delete own API keys"
  on public.api_keys for delete
  using (auth.uid() = user_id);
