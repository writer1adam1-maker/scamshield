// ============================================================================
// POST /api/admin/patterns — Upload file -> parse -> extract patterns -> return
// PUT  /api/admin/patterns — Approve patterns (write to custom_patterns.json)
// GET  /api/admin/patterns — List all custom patterns
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { parseUploadedFile } from "@/lib/pattern-ingestion/file-parser";
import { extractPatterns } from "@/lib/pattern-ingestion/pattern-extractor";
import { parseLlmOutput } from "@/lib/pattern-ingestion/llm-prompt-template";
import { readPatterns, writePatterns } from "@/lib/pattern-ingestion/patterns-store";
import type { ExtractedPattern } from "@/lib/pattern-ingestion/pattern-extractor";

// ---------------------------------------------------------------------------
// Admin auth check (copied from /api/admin/users)
// ---------------------------------------------------------------------------

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
    const userEmail = (user.email || "").toLowerCase();
    return adminEmails.length > 0 && userEmail.length > 0 && adminEmails.includes(userEmail);
  } catch {
    return false;
  }
}

// Storage is handled by Supabase (patterns-store.ts) — no filesystem writes

// ---------------------------------------------------------------------------
// POST — Upload file or LLM JSON, parse, extract patterns
// ---------------------------------------------------------------------------

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB
const ALLOWED_TYPES = new Set(["pdf", "csv", "txt"]);

export async function POST(req: NextRequest) {
  if (!(await requireAdmin(req))) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  try {
    const contentType = req.headers.get("content-type") ?? "";

    // --- Branch 1: multipart file upload ---
    if (contentType.includes("multipart/form-data")) {
      const formData = await req.formData();
      const file = formData.get("file");

      if (!file || !(file instanceof Blob)) {
        return NextResponse.json({ error: "No file provided" }, { status: 400 });
      }

      // Access name from the File object
      const fileObj = file as File;
      const filename = fileObj.name ?? "upload.txt";
      const ext = filename.split(".").pop()?.toLowerCase() ?? "";

      if (!ALLOWED_TYPES.has(ext)) {
        return NextResponse.json(
          { error: `Unsupported file type: .${ext}. Accepted: PDF, CSV, TXT.` },
          { status: 400 },
        );
      }

      if (fileObj.size > MAX_FILE_SIZE) {
        return NextResponse.json(
          { error: "File too large. Maximum size: 10 MB." },
          { status: 400 },
        );
      }

      const arrayBuffer = await fileObj.arrayBuffer();
      const buffer = Buffer.from(arrayBuffer);

      const chunks = await parseUploadedFile(buffer, filename);
      if (chunks.length === 0) {
        return NextResponse.json(
          { error: "No text content could be extracted from the file." },
          { status: 400 },
        );
      }

      const patterns = extractPatterns(chunks);

      return NextResponse.json({
        success: true,
        filename,
        chunksExtracted: chunks.length,
        patterns,
      });
    }

    // --- Branch 2: JSON body with LLM output ---
    if (contentType.includes("application/json")) {
      const body = await req.json().catch(() => null);
      if (!body || typeof body.llmOutput !== "string") {
        return NextResponse.json(
          { error: "Expected JSON body with 'llmOutput' string field." },
          { status: 400 },
        );
      }

      const patterns = parseLlmOutput(body.llmOutput);

      return NextResponse.json({
        success: true,
        source: "llm",
        patterns,
      });
    }

    return NextResponse.json(
      { error: "Unsupported content type. Use multipart/form-data for file upload or application/json for LLM output." },
      { status: 400 },
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

// ---------------------------------------------------------------------------
// Severity ranking for upgrade comparison
// ---------------------------------------------------------------------------
const SEVERITY_RANK: Record<string, number> = { low: 1, medium: 2, high: 3, critical: 4 };

// ---------------------------------------------------------------------------
// PUT — Approve patterns (admin selects from extracted, confirms to save)
// Deduplicates, detects upgrades (higher weight/severity replaces old entry)
// ---------------------------------------------------------------------------

export async function PUT(req: NextRequest) {
  if (!(await requireAdmin(req))) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  try {
    const body = await req.json().catch(() => null);
    if (!body || !Array.isArray(body.patterns)) {
      return NextResponse.json(
        { error: "Expected JSON body with 'patterns' array." },
        { status: 400 },
      );
    }

    const incoming = body.patterns as ExtractedPattern[];
    const existing = await readPatterns();

    // Build a map of existing patterns by lowercase text for O(1) lookup
    const existingMap = new Map<string, { index: number; pattern: ExtractedPattern }>();
    existing.forEach((p, i) => existingMap.set(p.text.toLowerCase(), { index: i, pattern: p }));

    let added = 0;
    let duplicatesSkipped = 0;
    let upgraded = 0;

    const merged = [...existing];

    for (const incoming_p of incoming) {
      const key = incoming_p.text.toLowerCase();
      const existing_entry = existingMap.get(key);

      if (!existing_entry) {
        // Brand new pattern — add it
        merged.push(incoming_p);
        existingMap.set(key, { index: merged.length - 1, pattern: incoming_p });
        added++;
      } else {
        // Pattern exists — check if incoming is an upgrade
        const existingRank = SEVERITY_RANK[existing_entry.pattern.suggestedSeverity] ?? 0;
        const incomingRank = SEVERITY_RANK[incoming_p.suggestedSeverity] ?? 0;
        const weightImproved = incoming_p.suggestedWeight > existing_entry.pattern.suggestedWeight;
        const severityImproved = incomingRank > existingRank;

        if (weightImproved || severityImproved) {
          // Upgrade: keep the better version
          merged[existing_entry.index] = {
            ...existing_entry.pattern,
            suggestedWeight: Math.max(existing_entry.pattern.suggestedWeight, incoming_p.suggestedWeight),
            suggestedSeverity: incomingRank >= existingRank
              ? incoming_p.suggestedSeverity
              : existing_entry.pattern.suggestedSeverity,
            specificityScore: Math.max(existing_entry.pattern.specificityScore, incoming_p.specificityScore),
          };
          upgraded++;
        } else {
          duplicatesSkipped++;
        }
      }
    }

    await writePatterns(merged);

    return NextResponse.json({
      success: true,
      added,
      upgraded,
      duplicatesSkipped,
      total: merged.length,
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}

// ---------------------------------------------------------------------------
// GET — List all custom patterns
// ---------------------------------------------------------------------------

export async function GET(req: NextRequest) {
  if (!(await requireAdmin(req))) {
    return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  }

  const patterns = await readPatterns();
  return NextResponse.json({ patterns, total: patterns.length });
}
