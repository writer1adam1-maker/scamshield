// ============================================================================
// File Parser — Ingests PDF, CSV, and TXT fraud reports into text chunks
// Handles: .pdf, .csv, .txt
// Returns: normalized text chunks ready for pattern extraction
// ============================================================================

/**
 * Parse an uploaded file (PDF, CSV, or TXT) and return an array of text chunks.
 * Each chunk represents one logical unit (a page/paragraph, CSV row, or text block).
 */
export async function parseUploadedFile(
  buffer: Buffer,
  filename: string,
): Promise<string[]> {
  const ext = filename.split(".").pop()?.toLowerCase() ?? "";

  switch (ext) {
    case "pdf":
      return parsePdf(buffer);
    case "csv":
      return parseCsv(buffer);
    case "txt":
      return parseTxt(buffer);
    default:
      throw new Error(
        `Unsupported file type: .${ext}. Accepted formats: PDF, CSV, TXT.`,
      );
  }
}

// ---------------------------------------------------------------------------
// PDF parsing — extract text, split by pages then paragraphs
// ---------------------------------------------------------------------------

async function parsePdf(buffer: Buffer): Promise<string[]> {
  // pdf-parse is a CJS module; dynamic import avoids top-level issues in ESM/Next
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const pdfParse = require("pdf-parse") as typeof import("pdf-parse");
  const data = await (pdfParse as unknown as (buf: Buffer) => Promise<{ text: string; numpages: number }>)(buffer);

  const rawText = data.text ?? "";
  if (!rawText.trim()) return [];

  // Try splitting by form-feed (page break) first
  const pages = rawText.split(/\f/).filter((p) => p.trim().length > 0);

  const chunks: string[] = [];
  for (const page of pages) {
    // Within each page, split by double newlines (paragraphs)
    const paragraphs = page
      .split(/\n{2,}/)
      .map((p) => p.replace(/\s+/g, " ").trim())
      .filter((p) => p.length >= 20); // skip tiny fragments

    if (paragraphs.length > 0) {
      chunks.push(...paragraphs);
    } else {
      // If no paragraph breaks, keep the whole page as one chunk
      const cleaned = page.replace(/\s+/g, " ").trim();
      if (cleaned.length >= 20) chunks.push(cleaned);
    }
  }

  return chunks;
}

// ---------------------------------------------------------------------------
// CSV parsing — each row becomes a chunk (prefer fraud-report-relevant columns)
// ---------------------------------------------------------------------------

/** Common column names for fraud report text content */
const PREFERRED_COLUMNS = [
  "description",
  "text",
  "content",
  "narrative",
  "message",
  "body",
  "report",
  "details",
  "complaint",
  "summary",
];

function parseCsv(buffer: Buffer): Promise<string[]> {
  const raw = buffer.toString("utf-8");
  const lines = raw.split(/\r?\n/).filter((l) => l.trim().length > 0);
  if (lines.length < 2) return Promise.resolve([]); // header + at least one row

  const headers = parseCsvLine(lines[0]).map((h) => h.toLowerCase().trim());

  // Find the best text column
  let textColIndex = -1;
  for (const pref of PREFERRED_COLUMNS) {
    const idx = headers.indexOf(pref);
    if (idx !== -1) {
      textColIndex = idx;
      break;
    }
  }

  // Fallback: pick the column with longest average content
  if (textColIndex === -1) {
    const sampleRows = lines.slice(1, Math.min(6, lines.length));
    const avgLengths = headers.map((_, ci) => {
      let total = 0;
      for (const row of sampleRows) {
        const cells = parseCsvLine(row);
        total += (cells[ci] ?? "").length;
      }
      return total / sampleRows.length;
    });
    textColIndex = avgLengths.indexOf(Math.max(...avgLengths));
  }

  const chunks: string[] = [];
  for (let i = 1; i < lines.length; i++) {
    const cells = parseCsvLine(lines[i]);
    const text = (cells[textColIndex] ?? "").trim();
    if (text.length >= 10) {
      chunks.push(text);
    }
  }

  return Promise.resolve(chunks);
}

/** Minimal CSV line parser — handles quoted fields with commas and escaped quotes */
function parseCsvLine(line: string): string[] {
  const cells: string[] = [];
  let current = "";
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"') {
        if (i + 1 < line.length && line[i + 1] === '"') {
          current += '"';
          i++; // skip escaped quote
        } else {
          inQuotes = false;
        }
      } else {
        current += ch;
      }
    } else {
      if (ch === '"') {
        inQuotes = true;
      } else if (ch === ",") {
        cells.push(current);
        current = "";
      } else {
        current += ch;
      }
    }
  }
  cells.push(current);
  return cells;
}

// ---------------------------------------------------------------------------
// TXT parsing — split by double newlines or numbered entries
// ---------------------------------------------------------------------------

function parseTxt(buffer: Buffer): Promise<string[]> {
  const raw = buffer.toString("utf-8");

  // Try numbered entry pattern first: "1." or "1)" at start of line
  const numberedPattern = /(?:^|\n)\s*\d+[\.\)]\s+/;
  if (numberedPattern.test(raw)) {
    const entries = raw
      .split(/\n\s*(?=\d+[\.\)]\s+)/)
      .map((e) => e.replace(/^\s*\d+[\.\)]\s+/, "").replace(/\s+/g, " ").trim())
      .filter((e) => e.length >= 10);
    if (entries.length >= 2) return Promise.resolve(entries);
  }

  // Fallback: split by double newlines
  const blocks = raw
    .split(/\n{2,}/)
    .map((b) => b.replace(/\s+/g, " ").trim())
    .filter((b) => b.length >= 10);

  // If we end up with one giant block, try splitting by single newlines
  if (blocks.length <= 1 && raw.length > 200) {
    const singleNewlineBlocks = raw
      .split(/\n/)
      .map((b) => b.trim())
      .filter((b) => b.length >= 10);
    if (singleNewlineBlocks.length > 1) return Promise.resolve(singleNewlineBlocks);
  }

  return Promise.resolve(blocks);
}
