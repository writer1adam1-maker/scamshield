// ============================================================================
// POST /api/admin/patterns — Upload file -> parse -> extract patterns -> return
// PUT  /api/admin/patterns — Approve patterns (write to custom_patterns.json)
// GET  /api/admin/patterns — List all custom patterns
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { createServerClient } from "@supabase/ssr";
import { promises as fs } from "fs";
import path from "path";
import { parseUploadedFile } from "@/lib/pattern-ingestion/file-parser";
import { extractPatterns } from "@/lib/pattern-ingestion/pattern-extractor";
import { parseLlmOutput } from "@/lib/pattern-ingestion/llm-prompt-template";
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

// ---------------------------------------------------------------------------
// Storage — custom_patterns.json alongside this route
// ---------------------------------------------------------------------------

const PATTERNS_FILE = path.join(process.cwd(), "data", "custom_patterns.json");

async function ensureDataDir(): Promise<void> {
  const dir = path.dirname(PATTERNS_FILE);
  try {
    await fs.mkdir(dir, { recursive: true });
  } catch {
    // already exists
  }
}

async function readPatterns(): Promise<ExtractedPattern[]> {
  try {
    const raw = await fs.readFile(PATTERNS_FILE, "utf-8");
    return JSON.parse(raw) as ExtractedPattern[];
  } catch {
    return [];
  }
}

async function writePatterns(patterns: ExtractedPattern[]): Promise<void> {
  await ensureDataDir();
  await fs.writeFile(PATTERNS_FILE, JSON.stringify(patterns, null, 2), "utf-8");
}

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
// PUT — Approve patterns (admin selects from extracted, confirms to save)
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

    // Deduplicate by text (case-insensitive)
    const existingTexts = new Set(existing.map((p) => p.text.toLowerCase()));
    const newPatterns = incoming.filter((p) => !existingTexts.has(p.text.toLowerCase()));

    const merged = [...existing, ...newPatterns];
    await writePatterns(merged);

    return NextResponse.json({
      success: true,
      added: newPatterns.length,
      total: merged.length,
      duplicatesSkipped: incoming.length - newPatterns.length,
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
