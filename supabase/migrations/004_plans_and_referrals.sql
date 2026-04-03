-- ============================================================================
-- Migration 004: Expanded plan tiers + referral system
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. Alter users table — expanded plan check + new columns
-- ---------------------------------------------------------------------------

-- Drop old plan check constraint
alter table public.users
  drop constraint if exists users_plan_check;

-- Add new plan check constraint with all tiers
alter table public.users
  add constraint users_plan_check
  check (plan in ('free', 'starter', 'plus', 'pro', 'business'));

-- Add new columns
alter table public.users
  add column if not exists scan_count_month    integer     not null default 0,
  add column if not exists scan_bonus_pool     integer     not null default 0,
  add column if not exists referral_code       text        unique,
  add column if not exists referral_count      integer     not null default 0,
  add column if not exists referred_by         text,
  add column if not exists last_month_reset    timestamptz not null default now();

-- ---------------------------------------------------------------------------
-- 2. referrals table
-- ---------------------------------------------------------------------------
create table if not exists public.referrals (
  id              uuid        primary key default gen_random_uuid(),
  referrer_id     uuid        not null references public.users(id) on delete cascade,
  referred_id     uuid        not null references public.users(id) on delete cascade,
  referral_code   text        not null,
  scans_awarded   integer     not null default 10,
  created_at      timestamptz not null default now(),
  unique (referred_id)  -- each user can only be referred once
);

create index if not exists referrals_referrer_id_idx on public.referrals(referrer_id);
create index if not exists referrals_referred_id_idx on public.referrals(referred_id);
create index if not exists referrals_referral_code_idx on public.referrals(referral_code);

-- RLS
alter table public.referrals enable row level security;

create policy "Users can read own referrals as referrer"
  on public.referrals for select
  using (auth.uid() = referrer_id);

create policy "Users can read own referral as referred"
  on public.referrals for select
  using (auth.uid() = referred_id);

create policy "Service role can insert referrals"
  on public.referrals for insert
  with check (true);  -- service role bypasses RLS; this covers internal API inserts

-- ---------------------------------------------------------------------------
-- 3. app_config — upsert new plan limit values
-- ---------------------------------------------------------------------------
insert into public.app_config (key, value)
values
  ('free_monthly_limit',      '50'),
  ('free_daily_replenish',    '1'),
  ('starter_monthly_limit',   '300'),
  ('starter_daily_replenish', '10'),
  ('plus_monthly_limit',      '1000'),
  ('plus_daily_replenish',    '35'),
  ('pro_monthly_limit',       '2500'),
  ('pro_daily_replenish',     '85'),
  ('referrer_bonus_scans',    '10'),
  ('referred_bonus_scans',    '20'),
  ('max_referrals_per_day',   '5')
on conflict (key) do update
  set value      = excluded.value,
      updated_at = now();

-- ---------------------------------------------------------------------------
-- 4. generate_referral_code() — random 8-char alphanumeric
-- ---------------------------------------------------------------------------
create or replace function public.generate_referral_code()
returns text
language plpgsql
as $$
declare
  chars  text    := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';  -- no 0/O/1/I to avoid confusion
  result text    := '';
  i      integer;
begin
  for i in 1..8 loop
    result := result || substr(chars, floor(random() * length(chars))::integer + 1, 1);
  end loop;
  return result;
end;
$$;

-- ---------------------------------------------------------------------------
-- 5. Trigger — auto-generate referral_code for new users
-- ---------------------------------------------------------------------------
create or replace function public.assign_referral_code()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  code text;
  attempts integer := 0;
begin
  -- Only generate if the code is missing
  if new.referral_code is not null then
    return new;
  end if;

  -- Retry loop to handle (unlikely) collisions
  loop
    code := public.generate_referral_code();
    begin
      new.referral_code := code;
      return new;
    exception when unique_violation then
      attempts := attempts + 1;
      if attempts >= 10 then
        raise exception 'Could not generate a unique referral code after 10 attempts';
      end if;
    end;
  end loop;
end;
$$;

drop trigger if exists assign_referral_code_on_insert on public.users;
create trigger assign_referral_code_on_insert
  before insert on public.users
  for each row execute function public.assign_referral_code();

-- Back-fill referral codes for any existing users who don't have one
do $$
declare
  rec record;
  code text;
  attempts integer;
begin
  for rec in
    select id from public.users where referral_code is null
  loop
    attempts := 0;
    loop
      code := public.generate_referral_code();
      begin
        update public.users set referral_code = code where id = rec.id;
        exit;  -- success, move to next user
      exception when unique_violation then
        attempts := attempts + 1;
        if attempts >= 10 then
          raise exception 'Could not generate a unique referral code for user % after 10 attempts', rec.id;
        end if;
      end;
    end loop;
  end loop;
end;
$$;
