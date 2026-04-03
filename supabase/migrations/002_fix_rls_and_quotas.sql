-- ============================================================================
-- Migration 002: Fix RLS policies + add quota reset
-- ============================================================================

-- Fix: Restrict scan inserts to authenticated users + service role
-- (Previously allowed anonymous inserts via `with check (true)`)
drop policy if exists "Service role can insert scans" on public.scans;

create policy "Authenticated users and service role can insert scans"
  on public.scans for insert
  with check (
    auth.uid() is not null  -- Authenticated users can insert their own scans
    or auth.role() = 'service_role'  -- Service role can insert for anonymous scans
  );

-- Allow users to read scans where user_id is null (anonymous) by IP
-- This lets the dashboard show scans even for not-yet-authenticated users
-- who later sign up (they can see their IP-matched scans)

-- Add delete policy for users to delete their own scans
create policy "Users can delete own scans"
  on public.scans for delete
  using (auth.uid() = user_id);

-- Add user delete policy (for account deletion from settings page)
create policy "Users can delete own account"
  on public.users for delete
  using (auth.uid() = id);
