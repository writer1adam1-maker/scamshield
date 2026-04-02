// ============================================================================
// POST /api/scan/screenshot — Screenshot upload + scan endpoint
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { checkRateLimit } from "@/lib/rate-limit";
import { runVERIDICT } from "@/lib/algorithms/veridict-engine";
import { getClientIp } from "@/lib/utils";

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB
const ALLOWED_TYPES = ["image/png", "image/jpeg", "image/webp", "image/gif"];

/**
 * MVP text extraction from image metadata / filename.
 * In production, replace with Tesseract.js or a cloud OCR API.
 */
function extractTextFromImage(file: File, buffer: ArrayBuffer): string {
  const lines: string[] = [];

  // Try to find readable ASCII strings in the image buffer (basic approach)
  const bytes = new Uint8Array(buffer);
  let current = "";

  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i];
    // Printable ASCII range
    if (byte >= 32 && byte <= 126) {
      current += String.fromCharCode(byte);
    } else {
      if (current.length >= 8) {
        // Only keep strings that look like they might be text content
        if (/[a-zA-Z]{3,}/.test(current)) {
          lines.push(current.trim());
        }
      }
      current = "";
    }
  }

  if (current.length >= 8 && /[a-zA-Z]{3,}/.test(current)) {
    lines.push(current.trim());
  }

  // Also extract from filename (users sometimes name files descriptively)
  const nameWithoutExt = file.name.replace(/\.[^.]+$/, "").replace(/[-_]/g, " ");
  if (nameWithoutExt.length > 3) {
    lines.unshift(nameWithoutExt);
  }

  // Deduplicate and join
  const unique = [...new Set(lines)];
  return unique.join("\n").slice(0, 5000);
}

export async function POST(req: NextRequest) {
  const startTime = performance.now();

  try {
    // --- Rate limiting ---
    const ip = getClientIp(req);
    // TODO: Integrate with Supabase auth to check user session, then look up
    // the user's plan (free/pro) from the users table or Stripe subscription status.
    const isPro = false;
    const rateLimit = checkRateLimit(ip, isPro);

    if (!rateLimit.allowed) {
      return NextResponse.json(
        {
          error: "Rate limit exceeded. Upgrade to Pro for unlimited scans.",
          remaining: rateLimit.remaining,
          resetAt: new Date(rateLimit.resetAt).toISOString(),
        },
        { status: 429 },
      );
    }

    // --- Parse FormData ---
    let formData: FormData;
    try {
      formData = await req.formData();
    } catch {
      return NextResponse.json(
        { error: "Invalid form data. Send a multipart/form-data request with an 'image' field." },
        { status: 400 },
      );
    }

    const file = formData.get("image") as File | null;

    if (!file) {
      return NextResponse.json(
        { error: "Missing 'image' field in form data." },
        { status: 400 },
      );
    }

    if (!ALLOWED_TYPES.includes(file.type)) {
      return NextResponse.json(
        { error: `Unsupported image type '${file.type}'. Allowed: ${ALLOWED_TYPES.join(", ")}` },
        { status: 400 },
      );
    }

    if (file.size > MAX_FILE_SIZE) {
      return NextResponse.json(
        { error: `File too large (${(file.size / 1024 / 1024).toFixed(1)} MB). Maximum is 10 MB.` },
        { status: 400 },
      );
    }

    // --- Extract text from image ---
    const buffer = await file.arrayBuffer();
    const extractedText = extractTextFromImage(file, buffer);

    if (!extractedText || extractedText.trim().length === 0) {
      // Even with no extracted text, run the engine with a placeholder note
      const result = await runVERIDICT({
        screenshotOcrText: "[No text could be extracted from screenshot]",
        text: "[Screenshot uploaded - OCR unavailable in MVP]",
      });

      const processingTimeMs = Math.round(performance.now() - startTime);

      return NextResponse.json({
        ...result,
        processingTimeMs,
        extractedText: null,
        ocrNote: "No readable text was found in the image. For best results, use the text input instead.",
      });
    }

    // --- Run VERIDICT engine on extracted text ---
    const result = await runVERIDICT({
      screenshotOcrText: extractedText,
      text: extractedText,
    });

    const processingTimeMs = Math.round(performance.now() - startTime);

    return NextResponse.json(
      {
        ...result,
        processingTimeMs,
        extractedText,
      },
      {
        status: 200,
        headers: {
          "X-RateLimit-Remaining": String(rateLimit.remaining),
          "X-Processing-Time": `${processingTimeMs}ms`,
        },
      },
    );
  } catch (err) {
    console.error("[/api/scan/screenshot] Unexpected error:", err);
    return NextResponse.json(
      { error: "Internal server error. Please try again." },
      { status: 500 },
    );
  }
}
