/**
 * AES-256-GCM encryption for Gmail refresh tokens.
 * Key comes from GMAIL_ENCRYPTION_KEY env var (32-byte hex string = 64 hex chars).
 * Storage format: base64(iv_12bytes + ciphertext + authtag_16bytes)
 */

const KEY_HEX = process.env.GMAIL_ENCRYPTION_KEY || "";
const IV_LENGTH = 12;
const TAG_LENGTH = 16;

function getKey(): Promise<CryptoKey> {
  if (!KEY_HEX || KEY_HEX.length !== 64) {
    throw new Error("GMAIL_ENCRYPTION_KEY must be a 64-char hex string (32 bytes)");
  }
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(KEY_HEX.slice(i * 2, i * 2 + 2), 16);
  }
  return crypto.subtle.importKey("raw", bytes, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
}

export async function encryptToken(plaintext: string): Promise<string> {
  const key = await getKey();
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const encoded = new TextEncoder().encode(plaintext);
  const cipherBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, encoded);
  // Concatenate iv + ciphertext(+authtag) into one buffer
  const combined = new Uint8Array(IV_LENGTH + cipherBuf.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(cipherBuf), IV_LENGTH);
  return Buffer.from(combined).toString("base64");
}

export async function decryptToken(b64: string): Promise<string> {
  const key = await getKey();
  const combined = Buffer.from(b64, "base64");
  const iv = combined.slice(0, IV_LENGTH);
  const data = combined.slice(IV_LENGTH);
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
  return new TextDecoder().decode(plainBuf);
}
