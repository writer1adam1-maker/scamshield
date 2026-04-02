/**
 * Injection Payload Signing (HMAC-SHA256)
 *
 * Prevents cache poisoning and injection manipulation by:
 * 1. Signing all injection payloads with HMAC before storage/transmission
 * 2. Verifying signatures before execution in content scripts
 * 3. Including timestamp to prevent replay attacks
 *
 * The secret key is server-side only. The content script receives
 * a signature it can verify via a lightweight challenge-response.
 */

const SIGNING_SECRET = process.env.VACCINE_SIGNING_SECRET || 'scamshield-dev-secret-change-in-prod';
const SIGNATURE_TTL_MS = 60 * 60 * 1000; // 1 hour max age for signed payloads

/**
 * Sign an injection payload with HMAC-SHA256.
 * Uses Web Crypto API for Edge Runtime compatibility.
 */
export async function signPayload(payload: string): Promise<{
  payload: string;
  signature: string;
  timestamp: number;
}> {
  const timestamp = Date.now();
  const message = `${timestamp}:${payload}`;

  const encoder = new TextEncoder();
  const keyData = encoder.encode(SIGNING_SECRET);
  const msgData = encoder.encode(message);

  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const sig = await crypto.subtle.sign('HMAC', key, msgData);
  const signature = arrayBufferToHex(sig);

  return { payload, signature, timestamp };
}

/**
 * Verify a signed payload. Returns true if valid and not expired.
 */
export async function verifyPayload(
  payload: string,
  signature: string,
  timestamp: number
): Promise<boolean> {
  // Check timestamp freshness
  const age = Date.now() - timestamp;
  if (age > SIGNATURE_TTL_MS || age < 0) {
    return false;
  }

  const message = `${timestamp}:${payload}`;
  const encoder = new TextEncoder();
  const keyData = encoder.encode(SIGNING_SECRET);
  const msgData = encoder.encode(message);

  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );

  const sigBuffer = hexToArrayBuffer(signature);
  return crypto.subtle.verify('HMAC', key, sigBuffer, msgData);
}

/**
 * Generate a content hash for cache integrity.
 * Cache key = URL + contentHash, preventing poisoned entries from being
 * served when content changes.
 */
export async function hashContent(content: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(content);
  const hash = await crypto.subtle.digest('SHA-256', data);
  return arrayBufferToHex(hash).substring(0, 16); // 16-char prefix is sufficient
}

function arrayBufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToArrayBuffer(hex: string): ArrayBuffer {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes.buffer;
}
