// ============================================================================
// GET /api/download/extension?browser=chrome|firefox
// Dynamically zips the browser extension files and returns as download.
// ============================================================================

import { NextRequest, NextResponse } from "next/server";
import { readFileSync, readdirSync, statSync, existsSync } from "fs";
import path from "path";

// Simple ZIP builder — creates a valid ZIP file from a directory
// Uses stored (uncompressed) entries for simplicity on serverless
function buildZip(files: Array<{ name: string; data: Buffer }>): Buffer {
  const entries: Buffer[] = [];
  const centralDir: Buffer[] = [];
  let offset = 0;

  for (const file of files) {
    const nameBytes = Buffer.from(file.name, "utf-8");
    const data = file.data;

    // Local file header (30 bytes + name + data)
    const local = Buffer.alloc(30 + nameBytes.length);
    local.writeUInt32LE(0x04034b50, 0); // signature
    local.writeUInt16LE(20, 4);         // version needed
    local.writeUInt16LE(0, 6);          // flags
    local.writeUInt16LE(0, 8);          // compression: stored
    local.writeUInt16LE(0, 10);         // mod time
    local.writeUInt16LE(0, 12);         // mod date
    local.writeUInt32LE(crc32(data), 14); // CRC-32
    local.writeUInt32LE(data.length, 18); // compressed size
    local.writeUInt32LE(data.length, 22); // uncompressed size
    local.writeUInt16LE(nameBytes.length, 26); // name length
    local.writeUInt16LE(0, 28);         // extra length
    nameBytes.copy(local, 30);

    entries.push(local, data);

    // Central directory entry (46 bytes + name)
    const central = Buffer.alloc(46 + nameBytes.length);
    central.writeUInt32LE(0x02014b50, 0); // signature
    central.writeUInt16LE(20, 4);         // version made by
    central.writeUInt16LE(20, 6);         // version needed
    central.writeUInt16LE(0, 8);          // flags
    central.writeUInt16LE(0, 10);         // compression
    central.writeUInt16LE(0, 12);         // mod time
    central.writeUInt16LE(0, 14);         // mod date
    central.writeUInt32LE(crc32(data), 16);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt16LE(0, 30); // extra
    central.writeUInt16LE(0, 32); // comment
    central.writeUInt16LE(0, 34); // disk start
    central.writeUInt16LE(0, 36); // internal attr
    central.writeUInt32LE(0, 38); // external attr
    central.writeUInt32LE(offset, 42); // local header offset
    nameBytes.copy(central, 46);

    centralDir.push(central);
    offset += local.length + data.length;
  }

  const centralDirBuf = Buffer.concat(centralDir);
  const endRecord = Buffer.alloc(22);
  endRecord.writeUInt32LE(0x06054b50, 0);
  endRecord.writeUInt16LE(0, 4);
  endRecord.writeUInt16LE(0, 6);
  endRecord.writeUInt16LE(files.length, 8);
  endRecord.writeUInt16LE(files.length, 10);
  endRecord.writeUInt32LE(centralDirBuf.length, 12);
  endRecord.writeUInt32LE(offset, 16);
  endRecord.writeUInt16LE(0, 20);

  return Buffer.concat([...entries, centralDirBuf, endRecord]);
}

// CRC-32 lookup table
const crcTable = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  crcTable[i] = c;
}
function crc32(buf: Buffer): number {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function collectFiles(dir: string, prefix: string): Array<{ name: string; data: Buffer }> {
  const results: Array<{ name: string; data: Buffer }> = [];
  if (!existsSync(dir)) return results;
  for (const entry of readdirSync(dir)) {
    const full = path.join(dir, entry);
    const rel = prefix ? `${prefix}/${entry}` : entry;
    const stat = statSync(full);
    if (stat.isDirectory()) {
      results.push(...collectFiles(full, rel));
    } else {
      results.push({ name: rel, data: readFileSync(full) });
    }
  }
  return results;
}

export async function GET(req: NextRequest) {
  const browser = req.nextUrl.searchParams.get("browser") ?? "chrome";
  const dirName = browser === "firefox" ? "firefox-extension" : "browser-extension";
  const extDir = path.join(process.cwd(), dirName);

  if (!existsSync(extDir)) {
    return NextResponse.json({ error: "Extension files not found" }, { status: 404 });
  }

  const files = collectFiles(extDir, "scamshield-extension");
  if (files.length === 0) {
    return NextResponse.json({ error: "No extension files" }, { status: 404 });
  }

  const zip = buildZip(files);
  const filename = `scamshield-${browser}-extension.zip`;

  return new NextResponse(new Uint8Array(zip), {
    headers: {
      "Content-Type": "application/zip",
      "Content-Disposition": `attachment; filename="${filename}"`,
      "Content-Length": String(zip.length),
    },
  });
}
