// ============================================================================
// Supabase Client Setup
// ============================================================================

import { createBrowserClient as createBrowser } from "@supabase/ssr";
import { createServerClient as createServer } from "@supabase/ssr";
import { createClient } from "@supabase/supabase-js";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { ThreatCategory, ThreatLevel } from "@/lib/algorithms/types";

// ---------------------------------------------------------------------------
// Database type definitions
// ---------------------------------------------------------------------------

export interface DbScan {
  id: string;
  user_id: string | null;
  input_type: "url" | "text" | "screenshot";
  input_preview: string;
  score: number;
  threat_level: ThreatLevel;
  category: ThreatCategory;
  result_json: Record<string, unknown>;
  ip_address: string | null;
  created_at: string;
}

export interface DbUser {
  id: string;
  email: string;
  plan: "free" | "pro";
  stripe_customer_id: string | null;
  stripe_subscription_id: string | null;
  scan_count_today: number;
  scan_count_total: number;
  created_at: string;
  updated_at: string;
}

export interface DbPattern {
  id: string;
  category: ThreatCategory;
  name: string;
  description: string;
  example: string;
  threat_level: ThreatLevel;
  keywords: string[];
  created_at: string;
  updated_at: string;
}

export interface Database {
  public: {
    Tables: {
      scans: { Row: DbScan; Insert: Omit<DbScan, "id" | "created_at">; Update: Partial<DbScan> };
      users: { Row: DbUser; Insert: Omit<DbUser, "id" | "created_at" | "updated_at">; Update: Partial<DbUser> };
      patterns: { Row: DbPattern; Insert: Omit<DbPattern, "id" | "created_at" | "updated_at">; Update: Partial<DbPattern> };
    };
  };
}

// ---------------------------------------------------------------------------
// Browser client (client components)
// ---------------------------------------------------------------------------

let browserClient: SupabaseClient<Database> | null = null;

export function createBrowserClient(): SupabaseClient<Database> {
  if (browserClient) return browserClient;

  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!url) {
    throw new Error("NEXT_PUBLIC_SUPABASE_URL is not set in environment variables");
  }
  if (!anonKey) {
    throw new Error("NEXT_PUBLIC_SUPABASE_ANON_KEY is not set in environment variables");
  }

  browserClient = createBrowser<Database>(url, anonKey);

  return browserClient;
}

// ---------------------------------------------------------------------------
// Service-role client (server-side only — bypasses RLS, for webhooks/admin)
// NEVER expose SUPABASE_SERVICE_ROLE_KEY to the browser.
// ---------------------------------------------------------------------------

export function createServiceRoleClient(): SupabaseClient<Database> {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const serviceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url) {
    throw new Error("NEXT_PUBLIC_SUPABASE_URL is not set");
  }
  if (!serviceRoleKey) {
    throw new Error("SUPABASE_SERVICE_ROLE_KEY is not set");
  }

  return createClient<Database>(url, serviceRoleKey, {
    auth: { persistSession: false, autoRefreshToken: false },
  });
}

// ---------------------------------------------------------------------------
// Server client (server components / route handlers)
// ---------------------------------------------------------------------------

export function createServerSupabaseClient(
  cookieStore: {
    getAll: () => { name: string; value: string }[];
    set: (name: string, value: string, options?: Record<string, unknown>) => void;
  },
): SupabaseClient<Database> {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const anonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;

  if (!url) {
    throw new Error("NEXT_PUBLIC_SUPABASE_URL is not set in environment variables");
  }
  if (!anonKey) {
    throw new Error("NEXT_PUBLIC_SUPABASE_ANON_KEY is not set in environment variables");
  }

  return createServer<Database>(
    url,
    anonKey,
    {
      cookies: {
        getAll() {
          return cookieStore.getAll();
        },
        setAll(cookiesToSet) {
          try {
            cookiesToSet.forEach(({ name, value, options }) => {
              cookieStore.set(name, value, options);
            });
          } catch {
            // setAll is called from a Server Component — safe to ignore
          }
        },
      },
    },
  );
}
