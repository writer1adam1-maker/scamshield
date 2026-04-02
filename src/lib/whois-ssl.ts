// ============================================================================
// Live WHOIS (via RDAP) + SSL enrichment for URL scans
// All calls are fire-and-await with hard 4-second timeout
// ============================================================================

export interface WhoisSslResult {
  domainAge: number | null;      // days since registration, null = unknown
  sslValid: boolean | null;      // null = could not determine
  registrar: string | null;
  evidence: { finding: string; severity: "low" | "medium" | "high" | "critical" }[];
  scoreBoost: number;            // additional score points (positive = more suspicious)
}

// Extract root domain from a URL or hostname string
function extractDomain(input: string): string | null {
  try {
    const url = input.startsWith("http") ? input : `https://${input}`;
    return new URL(url).hostname.replace(/^www\./, "");
  } catch {
    return null;
  }
}

// RDAP lookup — completely free, no API key, run by IANA
async function rdapLookup(domain: string): Promise<{ ageDays: number | null; registrar: string | null }> {
  try {
    const res = await fetch(`https://rdap.org/domain/${domain}`, {
      headers: { Accept: "application/rdap+json" },
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return { ageDays: null, registrar: null };

    const data = await res.json();

    // Domain age from registration event
    const regEvent = (data.events ?? []).find(
      (e: { eventAction: string; eventDate?: string }) => e.eventAction === "registration",
    );
    let ageDays: number | null = null;
    if (regEvent?.eventDate) {
      ageDays = Math.floor((Date.now() - new Date(regEvent.eventDate).getTime()) / 86_400_000);
    }

    // Registrar name
    let registrar: string | null = null;
    const entities: { roles?: string[]; vcardArray?: unknown[] }[] = data.entities ?? [];
    for (const entity of entities) {
      if (entity.roles?.includes("registrar")) {
        const vcard = entity.vcardArray?.[1];
        if (Array.isArray(vcard)) {
          for (const field of vcard) {
            if (Array.isArray(field) && field[0] === "fn" && typeof field[3] === "string") {
              registrar = field[3];
              break;
            }
          }
        }
        break;
      }
    }

    return { ageDays, registrar };
  } catch {
    return { ageDays: null, registrar: null };
  }
}

// SSL validity — attempt HTTPS connection and check for cert errors
async function checkSSL(domain: string): Promise<boolean | null> {
  try {
    await fetch(`https://${domain}`, {
      method: "HEAD",
      signal: AbortSignal.timeout(4000),
      redirect: "follow",
    });
    return true; // Got a response → SSL OK
  } catch (err) {
    const msg = String(err).toLowerCase();
    // Certificate-specific errors
    if (
      msg.includes("certificate") ||
      msg.includes("ssl") ||
      msg.includes("tls") ||
      msg.includes("cert") ||
      msg.includes("self_signed") ||
      msg.includes("depth_zero") ||
      msg.includes("unable to verify")
    ) {
      return false;
    }
    // Connection refused / timeout / DNS failure → can't determine
    return null;
  }
}

// Main export — runs RDAP + SSL in parallel with 4s hard limit
export async function enrichUrlWithWhoisSsl(urlInput: string): Promise<WhoisSslResult> {
  const domain = extractDomain(urlInput);
  if (!domain) {
    return { domainAge: null, sslValid: null, registrar: null, evidence: [], scoreBoost: 0 };
  }

  // Run both in parallel
  const [rdap, ssl] = await Promise.all([rdapLookup(domain), checkSSL(domain)]);

  const evidence: WhoisSslResult["evidence"] = [];
  let scoreBoost = 0;

  // --- Domain age scoring ---
  if (rdap.ageDays !== null) {
    if (rdap.ageDays < 7) {
      evidence.push({ finding: `Domain registered ${rdap.ageDays} day(s) ago — extremely new`, severity: "critical" });
      scoreBoost += 30;
    } else if (rdap.ageDays < 30) {
      evidence.push({ finding: `Domain registered ${rdap.ageDays} days ago — very new`, severity: "high" });
      scoreBoost += 20;
    } else if (rdap.ageDays < 90) {
      evidence.push({ finding: `Domain registered ${rdap.ageDays} days ago — recently created`, severity: "medium" });
      scoreBoost += 10;
    } else if (rdap.ageDays < 365) {
      evidence.push({ finding: `Domain age: ${rdap.ageDays} days (under 1 year)`, severity: "low" });
      scoreBoost += 5;
    }
    // Older domains: no penalty, slight positive signal handled by absence of boost
  } else {
    // Can't determine age — mildly suspicious (could be hidden via privacy protection)
    evidence.push({ finding: "Domain registration date hidden (WHOIS privacy)", severity: "low" });
    scoreBoost += 3;
  }

  // --- SSL scoring ---
  if (ssl === false) {
    evidence.push({ finding: "Invalid or missing SSL certificate", severity: "high" });
    scoreBoost += 20;
  } else if (ssl === true && rdap.ageDays !== null && rdap.ageDays < 30) {
    // New domain with valid SSL — phishing kits get free SSL from Let's Encrypt
    evidence.push({ finding: "SSL certificate present but domain is very new (common in phishing kits)", severity: "medium" });
    scoreBoost += 5;
  }

  return {
    domainAge: rdap.ageDays,
    sslValid: ssl,
    registrar: rdap.registrar,
    evidence,
    scoreBoost,
  };
}
