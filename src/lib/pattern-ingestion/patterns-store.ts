// ============================================================================
// Supabase-backed custom patterns store
// Replaces the filesystem approach (which fails on Vercel read-only /var/task)
// Stores patterns as JSONB in app_config table under key = "custom_patterns"
// ============================================================================

import { createServiceRoleClient } from "@/lib/supabase/client";
import type { ExtractedPattern } from "./pattern-extractor";

const CONFIG_KEY = "custom_patterns";

export async function readPatterns(): Promise<ExtractedPattern[]> {
  try {
    const db = createServiceRoleClient();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data, error } = await (db as any)
      .from("app_config")
      .select("value")
      .eq("key", CONFIG_KEY)
      .single();

    if (error || !data) return [];

    const raw = data.value;

    // value may be stored as a JSON string or already parsed array
    if (Array.isArray(raw)) return raw as ExtractedPattern[];
    if (typeof raw === "string") {
      try { return JSON.parse(raw) as ExtractedPattern[]; }
      catch { return []; }
    }
    return [];
  } catch {
    return [];
  }
}

export async function writePatterns(patterns: ExtractedPattern[]): Promise<void> {
  const db = createServiceRoleClient();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { error } = await (db as any)
    .from("app_config")
    .upsert({ key: CONFIG_KEY, value: patterns }, { onConflict: "key" });

  if (error) {
    throw new Error(`Failed to save patterns to Supabase: ${error.message}`);
  }
}
