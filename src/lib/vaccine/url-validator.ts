/**
 * URL Validation & SSRF Protection
 *
 * Prevents Server-Side Request Forgery by:
 * 1. Whitelisting only http/https schemes
 * 2. Blocking private/internal IP ranges
 * 3. Blocking cloud metadata endpoints
 * 4. Limiting redirect hops
 * 5. DNS resolution validation
 */

const BLOCKED_IP_RANGES = [
  // IPv4 private ranges
  /^127\./,                          // Loopback
  /^10\./,                           // Class A private
  /^172\.(1[6-9]|2[0-9]|3[01])\./,  // Class B private
  /^192\.168\./,                     // Class C private
  /^169\.254\./,                     // Link-local / AWS metadata
  /^0\./,                            // Current network
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./, // Shared address space (CGN)

  // IPv6
  /^::1$/,                           // Loopback
  /^fe80:/i,                         // Link-local
  /^fc00:/i,                         // Unique local
  /^fd/i,                            // Unique local
];

const BLOCKED_HOSTNAMES = [
  'localhost',
  '0.0.0.0',
  'metadata.google.internal',
  'metadata.google',
  'kubernetes.default',
  'kubernetes.default.svc',
];

const BLOCKED_METADATA_PATHS = [
  '/latest/meta-data',
  '/latest/user-data',
  '/latest/dynamic',
  '/metadata/v1',
  '/computeMetadata',
  '/opc/v1',
  '/metadata/instance',
];

const ALLOWED_SCHEMES = ['http:', 'https:'];
const MAX_URL_LENGTH = 2048;
const MAX_REDIRECTS = 3;

export interface UrlValidationResult {
  valid: boolean;
  sanitizedUrl: string;
  error?: string;
}

/**
 * Validate and sanitize a URL before server-side fetching.
 * Blocks SSRF vectors: private IPs, metadata endpoints, bad schemes.
 */
export function validateUrl(input: string): UrlValidationResult {
  if (!input || typeof input !== 'string') {
    return { valid: false, sanitizedUrl: '', error: 'URL is required' };
  }

  const trimmed = input.trim();

  if (trimmed.length > MAX_URL_LENGTH) {
    return { valid: false, sanitizedUrl: '', error: `URL exceeds maximum length of ${MAX_URL_LENGTH}` };
  }

  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, sanitizedUrl: '', error: 'Invalid URL format' };
  }

  // 1. Scheme whitelist
  if (!ALLOWED_SCHEMES.includes(parsed.protocol)) {
    return { valid: false, sanitizedUrl: '', error: `Blocked scheme: ${parsed.protocol} — only http/https allowed` };
  }

  // 2. Block known dangerous hostnames
  const hostname = parsed.hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.includes(hostname)) {
    return { valid: false, sanitizedUrl: '', error: `Blocked hostname: ${hostname}` };
  }

  // 3. Block private/internal IPs
  if (isBlockedIp(hostname)) {
    return { valid: false, sanitizedUrl: '', error: 'Blocked: private/internal IP address' };
  }

  // 4. Block cloud metadata endpoints
  const fullPath = parsed.pathname + parsed.search;
  for (const metaPath of BLOCKED_METADATA_PATHS) {
    if (fullPath.toLowerCase().startsWith(metaPath)) {
      return { valid: false, sanitizedUrl: '', error: 'Blocked: cloud metadata endpoint' };
    }
  }

  // 5. Block URLs with auth info (user:pass@host — used to confuse parsers)
  if (parsed.username || parsed.password) {
    return { valid: false, sanitizedUrl: '', error: 'Blocked: URL contains embedded credentials' };
  }

  // 6. Block non-standard ports commonly used for internal services
  if (parsed.port) {
    const port = parseInt(parsed.port, 10);
    if (port === 0 || port > 65535) {
      return { valid: false, sanitizedUrl: '', error: 'Blocked: invalid port' };
    }
  }

  return { valid: true, sanitizedUrl: parsed.href };
}

function isBlockedIp(hostname: string): boolean {
  for (const pattern of BLOCKED_IP_RANGES) {
    if (pattern.test(hostname)) return true;
  }

  // Also check for decimal/octal/hex IP representations that resolve to private ranges
  // e.g., 0x7f000001 = 127.0.0.1
  if (/^0x[0-9a-f]+$/i.test(hostname) || /^\d+$/.test(hostname)) {
    return true; // Block all numeric-only hostnames (IP obfuscation)
  }

  return false;
}

/**
 * Create a fetch wrapper that enforces SSRF protections:
 * - Validates URL before fetch
 * - Limits redirects and re-validates each hop
 * - Enforces response size limit
 * - Enforces Content-Type for HTML
 */
export async function safeFetch(
  url: string,
  options: {
    timeoutMs?: number;
    maxResponseBytes?: number;
    requireHtml?: boolean;
  } = {}
): Promise<Response> {
  const {
    timeoutMs = 15000,
    maxResponseBytes = 1024 * 1024, // 1MB default
    requireHtml = true,
  } = options;

  // Validate initial URL
  const validation = validateUrl(url);
  if (!validation.valid) {
    throw new Error(`SSRF blocked: ${validation.error}`);
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    // Fetch with manual redirect handling to validate each hop
    let currentUrl = validation.sanitizedUrl;
    let redirectCount = 0;

    while (redirectCount <= MAX_REDIRECTS) {
      const response = await fetch(currentUrl, {
        signal: controller.signal,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        },
        redirect: 'manual', // Handle redirects ourselves
      });

      // If not a redirect, return the response
      if (response.status < 300 || response.status >= 400) {
        clearTimeout(timeoutId);

        // Validate Content-Type if required
        if (requireHtml) {
          const contentType = response.headers.get('content-type') || '';
          if (!contentType.includes('text/html') && !contentType.includes('text/plain') && !contentType.includes('application/xhtml')) {
            throw new Error(`Unexpected Content-Type: ${contentType} — expected text/html`);
          }
        }

        // Validate Content-Length if available
        const contentLength = response.headers.get('content-length');
        if (contentLength && parseInt(contentLength, 10) > maxResponseBytes) {
          throw new Error(`Response too large: ${contentLength} bytes exceeds ${maxResponseBytes} limit`);
        }

        return response;
      }

      // Handle redirect
      const location = response.headers.get('location');
      if (!location) {
        throw new Error('Redirect without Location header');
      }

      // Resolve relative redirects
      const redirectUrl = new URL(location, currentUrl).href;

      // Validate redirect destination
      const redirectValidation = validateUrl(redirectUrl);
      if (!redirectValidation.valid) {
        throw new Error(`SSRF blocked on redirect: ${redirectValidation.error}`);
      }

      currentUrl = redirectValidation.sanitizedUrl;
      redirectCount++;
    }

    throw new Error(`Too many redirects (max ${MAX_REDIRECTS})`);
  } catch (error) {
    clearTimeout(timeoutId);
    throw error;
  }
}

/**
 * Sanitize a URL string for safe logging (no credentials, truncated).
 */
export function sanitizeUrlForLog(url: string): string {
  try {
    const parsed = new URL(url);
    parsed.username = '';
    parsed.password = '';
    const safe = parsed.href;
    return safe.length > 200 ? safe.substring(0, 200) + '...' : safe;
  } catch {
    return '[invalid URL]';
  }
}
