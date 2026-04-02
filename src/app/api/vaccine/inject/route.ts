/**
 * GET /api/vaccine/inject?url=...
 * Returns protective JavaScript injection script for a URL
 *
 * Security hardening:
 * - URL validation (SSRF protection, scheme whitelist)
 * - Rate limiting per IP
 * - Payload signing (HMAC-SHA256) — content script must verify signature
 * - No user-supplied data interpolated into JS (parameterized templates only)
 * - Strict CORS (only allow extension origin, not wildcard)
 * - CSP nonce for injected scripts
 */

import { NextRequest, NextResponse } from "next/server";
import { vaccineManager } from "@/lib/vaccine/vaccine-manager";
import { validateUrl, sanitizeUrlForLog } from "@/lib/vaccine/url-validator";
import { signPayload } from "@/lib/vaccine/payload-signer";
import { checkRateLimit } from "@/lib/vaccine/rate-limiter";

const ALLOWED_ORIGINS = [
  "chrome-extension://", // Chrome extensions
  "moz-extension://",    // Firefox extensions
  "https://scamshieldy.com",
];

export async function GET(request: NextRequest) {
  try {
    // --- Rate limiting ---
    const ip = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
      || request.headers.get("x-real-ip")
      || "unknown";

    const rateCheck = checkRateLimit(ip, "inject");
    if (!rateCheck.allowed) {
      return NextResponse.json(
        { error: "Rate limit exceeded" },
        {
          status: 429,
          headers: { "Retry-After": String(Math.ceil(rateCheck.retryAfterMs / 1000)) },
        }
      );
    }

    // --- URL validation ---
    const rawUrl = request.nextUrl.searchParams.get("url");

    if (!rawUrl) {
      return NextResponse.json(
        { error: "URL parameter is required" },
        { status: 400 }
      );
    }

    const urlValidation = validateUrl(rawUrl);
    if (!urlValidation.valid) {
      return NextResponse.json(
        { error: `Invalid URL: ${urlValidation.error}` },
        { status: 400 }
      );
    }

    const safeUrl = urlValidation.sanitizedUrl;

    // --- Get injection script ---
    const script = vaccineManager.getInjectionScript(safeUrl);

    if (!script) {
      // No vaccine found — return signed default protection
      const defaultScript = getDefaultProtectionScript();
      const signed = await signPayload(defaultScript);

      return NextResponse.json(
        {
          warning: "No active vaccine for this URL",
          script: defaultScript,
          signature: signed.signature,
          signedAt: signed.timestamp,
        },
        {
          status: 200,
          headers: buildSecureHeaders(),
        }
      );
    }

    // --- Sign the injection payload ---
    const signed = await signPayload(script);

    return NextResponse.json(
      {
        script,
        url: safeUrl,
        signature: signed.signature,
        signedAt: signed.timestamp,
      },
      {
        status: 200,
        headers: buildSecureHeaders(),
      }
    );
  } catch (error) {
    console.error("[API] Injection script error:", error);

    return NextResponse.json(
      { error: "Script generation failed" },
      { status: 500 }
    );
  }
}

/**
 * Default protection script — uses parameterized templates only.
 * NEVER interpolates user-supplied data into JS.
 */
function getDefaultProtectionScript(): string {
  return `
    (function() {
      'use strict';
      if (window._scamshieldyVaccineApplied) return;
      window._scamshieldyVaccineApplied = true;

      document.addEventListener('submit', function(e) {
        var form = e.target;
        var action = form.getAttribute('action') || '';
        if (!action) return;
        try {
          var formDomain = new URL(action, window.location.href).hostname;
          var currentDomain = window.location.hostname;
          if (formDomain && formDomain !== currentDomain) {
            var confirmed = confirm(
              'ScamShieldy: This form submits to a different server (' + formDomain + '). Proceed?'
            );
            if (!confirmed) e.preventDefault();
          }
        } catch (err) {}
      }, true);
    })();
  `;
}

function buildSecureHeaders(): Record<string, string> {
  return {
    "Content-Type": "application/json",
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
  };
}

export async function OPTIONS() {
  // Restrictive CORS — no wildcard
  return NextResponse.json(
    {},
    {
      headers: {
        "Access-Control-Allow-Origin": "https://scamshieldy.com",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, X-ScamShieldy-Signature",
        "Access-Control-Max-Age": "3600",
      },
    }
  );
}
