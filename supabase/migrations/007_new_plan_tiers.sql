-- ============================================================================
-- Migration 007: Replace Business plan with Team / Organization / Enterprise
-- ============================================================================

-- Update plan check constraint
alter table public.users drop constraint if exists users_plan_check;
alter table public.users add constraint users_plan_check
  check (plan in ('free', 'starter', 'pro', 'team', 'organization', 'enterprise'));

-- Migrate any existing 'business' users to 'team'
update public.users set plan = 'team' where plan = 'business';

-- Upsert new rolling limits into app_config
insert into public.app_config (key, value) values
  ('team_rolling_limit',         '5000'),
  ('organization_rolling_limit', '20000'),
  ('enterprise_rolling_limit',   '100000')
on conflict (key) do update set value = excluded.value, updated_at = now();

-- Remove old business limit if it exists
delete from public.app_config where key = 'business_rolling_limit';
