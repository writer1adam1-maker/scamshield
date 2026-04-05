// GET /api/admin/patterns/prompt — Returns a fresh LLM extraction prompt with session ID
import { NextRequest, NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { buildLlmExtractionPrompt } from "@/lib/pattern-ingestion/llm-prompt-template";

async function requireAdmin(req: NextRequest): Promise<boolean> {
  try {
    const supabase = createServerClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
      {
        cookies: {
          getAll() { return req.cookies.getAll(); },
          setAll() {},
        },
      }
    );
    const { data: { user } } = await supabase.auth.getUser();
    if (!user) return false;
    const adminEmails = (process.env.ADMIN_EMAILS || "").split(",").map((e) => e.trim().toLowerCase()).filter(Boolean);
    return adminEmails.includes((user.email || "").toLowerCase());
  } catch {
    return false;
  }
}

export async function GET(req: NextRequest) {
  if (!(await requireAdmin(req))) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }
  return NextResponse.json({ prompt: buildLlmExtractionPrompt() });
}
