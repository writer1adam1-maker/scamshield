-- ============================================================================
-- Migration 005: Simplified 4-tier plans, rolling 30-day window
-- Removes: plus plan, daily replenishment columns
-- Adds: rolling window support via last_month_reset (already exists from 004)
-- ============================================================================

-- Update plan check constraint to 4 tiers only
alter table public.users drop constraint if exists users_plan_check;
alter table public.users add constraint users_plan_check
  check (plan in ('free', 'starter', 'pro', 'business'));

-- Downgrade any 'plus' users to 'pro'
update public.users set plan = 'pro' where plan = 'plus';

-- Update app_config with rolling limits (no daily replenish)
insert into public.app_config (key, value) values
  ('free_rolling_limit',     '50'),
  ('starter_rolling_limit',  '200'),
  ('pro_rolling_limit',      '500'),
  ('referrer_bonus_scans',   '10'),
  ('referred_bonus_scans',   '20'),
  ('max_referrals_per_day',  '5'),
  ('anonymous_scan_limit',   '4')
on conflict (key) do update set value = excluded.value, updated_at = now();

-- Remove old daily replenishment config keys (cleanup)
delete from public.app_config where key in (
  'free_daily_replenish',
  'starter_daily_replenish',
  'plus_daily_replenish',
  'pro_daily_replenish',
  'plus_monthly_limit',
  'free_monthly_limit',
  'starter_monthly_limit',
  'pro_monthly_limit',
  'registered_scan_limit'
);
