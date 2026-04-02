// ============================================================================
// IP Intelligence Engine
// ============================================================================
// Resolves a domain's server IP, runs geolocation + ASN classification,
// detects datacenters/VPN/TOR, and scores high-risk hosting geography.
// Uses the free ip-api.com endpoint (45 req/min, no API key required).
// Falls back gracefully — the scan still completes if IP lookup fails.

import { promises as dns } from "dns";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type HostingCategory =
  | "residential"     // legitimate ISP — low risk
  | "cloud"           // major cloud (AWS, GCP, Azure, Cloudflare) — medium risk
  | "vps"             // VPS/hosting provider (DigitalOcean, Vultr, Hetzner…) — high risk
  | "vpn_proxy"       // VPN / proxy / anonymizer — high risk
  | "tor"             // Tor exit node — critical risk
  | "unknown";

export interface IpIntelligenceResult {
  ip: string;
  country: string;
  countryCode: string;
  region: string;
  city: string;
  isp: string;
  org: string;
  asn: string;
  hostingCategory: HostingCategory;
  isDatacenter: boolean;
  isVpnOrProxy: boolean;
  countryRiskLevel: "low" | "medium" | "high" | "critical";
  scoreBoost: number;         // pts to add to VERIDICT composite score
  evidence: {
    finding: string;
    severity: "low" | "medium" | "high" | "critical";
  }[];
  flags: string[];
  processingTimeMs: number;
}

// ---------------------------------------------------------------------------
// Country risk registry
// Source: FBI IC3 2024, FTC 2025, UN scam-compound reporting
// ---------------------------------------------------------------------------

const HIGH_RISK_COUNTRIES: Record<string, { risk: "medium" | "high" | "critical"; reason: string; boost: number }> = {
  // Advanced-fee / romance scam hubs
  NG: { risk: "high",     reason: "Nigeria — top advance-fee & romance scam origin (FBI IC3 #1)", boost: 20 },
  GH: { risk: "high",     reason: "Ghana — high romance scam & advance-fee origin", boost: 18 },
  CM: { risk: "high",     reason: "Cameroon — significant romance scam origin", boost: 15 },
  CI: { risk: "high",     reason: "Côte d'Ivoire — advance-fee & romance scam hub", boost: 15 },
  BJ: { risk: "medium",   reason: "Benin — advance-fee scam origin", boost: 10 },
  SN: { risk: "medium",   reason: "Senegal — advance-fee scam involvement", boost: 8 },
  // Pig-butchering / cyber compound operations
  KH: { risk: "critical", reason: "Cambodia — known pig-butchering scam compound operations", boost: 30 },
  MM: { risk: "critical", reason: "Myanmar — major cyber-scam compound operations (UN documented)", boost: 30 },
  LA: { risk: "high",     reason: "Laos — cyber-scam compound involvement", boost: 22 },
  TH: { risk: "medium",   reason: "Thailand — scam operation transit & support", boost: 10 },
  PH: { risk: "medium",   reason: "Philippines — pig-butchering scam recruitment/operations", boost: 12 },
  VN: { risk: "high",     reason: "Vietnam — cyber-scam workforce hub", boost: 18 },
  CN: { risk: "medium",   reason: "China — pig-butchering financial infrastructure", boost: 15 },
  HK: { risk: "medium",   reason: "Hong Kong — scam financial layer routing", boost: 10 },
  // Eastern European cybercrime
  RO: { risk: "medium",   reason: "Romania — phishing & card fraud operations", boost: 12 },
  BG: { risk: "medium",   reason: "Bulgaria — phishing & carding hub", boost: 10 },
  UA: { risk: "medium",   reason: "Ukraine — cybercrime infrastructure (war context)", boost: 8 },
  RU: { risk: "high",     reason: "Russia — major cybercrime & fraud infrastructure", boost: 20 },
  // Other
  IN: { risk: "medium",   reason: "India — tech support & IRS impersonation scams", boost: 12 },
  PK: { risk: "medium",   reason: "Pakistan — tech support scam operations", boost: 8 },
};

// ---------------------------------------------------------------------------
// Datacenter / VPS / cloud ASN/org patterns
// ---------------------------------------------------------------------------

const CLOUD_PROVIDERS = [
  "amazon", "aws", "amazon web services",
  "google", "google cloud", "google llc",
  "microsoft", "azure",
  "cloudflare",
  "akamai",
  "fastly",
];

const VPS_PROVIDERS = [
  "digitalocean", "linode", "akamai", "vultr", "hetzner",
  "ovh", "ovhcloud", "scaleway", "contabo", "hostinger",
  "godaddy", "namecheap", "bluehost", "a2 hosting",
  "hostgator", "dreamhost", "siteground",
  "leaseweb", "psychz", "sharktech",
  "colocrossing", "serverius", "frantech", "buyvm",
  "quadranet", "cogent", "m247",
  "servermania", "ionos", "1&1", "strato",
  "integen", "tzulo", "multacom", "reprise hosting",
  "xneelo", "afrihost",
  "inmotionhosting", "liquidweb", "knownhost",
  "racknerd", "alpharacks", "hostsailor", "hosthatch",
];

const VPN_PROXY_PATTERNS = [
  "vpn", "proxy", "private", "anonymous", "anonymizing",
  "hide", "mask", "nordvpn", "expressvpn", "mullvad",
  "surfshark", "cyberghost", "ipvanish", "pia",
  "private internet access", "protonvpn", "windscribe",
  "torguard", "hidemyass", "purevpn", "ipvpn",
  "perfect privacy", "trust.zone", "zenmate",
  "cloak", "phantom", "stealthvpn",
  "tor exit", "tor-exit", "torexit",
];

const TOR_PATTERNS = ["tor exit", "tor-exit", "torexit", "torproject"];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function orgMatchesAny(org: string, isp: string, patterns: string[]): boolean {
  const combined = (org + " " + isp).toLowerCase();
  return patterns.some(p => combined.includes(p));
}

function classifyHosting(org: string, isp: string, asn: string): HostingCategory {
  const combined = (org + " " + isp + " " + asn).toLowerCase();
  if (TOR_PATTERNS.some(p => combined.includes(p))) return "tor";
  if (VPN_PROXY_PATTERNS.some(p => combined.includes(p))) return "vpn_proxy";
  if (CLOUD_PROVIDERS.some(p => combined.includes(p))) return "cloud";
  if (VPS_PROVIDERS.some(p => combined.includes(p))) return "vps";
  return "residential";
}

// ---------------------------------------------------------------------------
// ip-api.com lookup
// ---------------------------------------------------------------------------

interface IpApiResponse {
  status: string;
  message?: string;
  query: string;
  country: string;
  countryCode: string;
  region: string;
  regionName: string;
  city: string;
  isp: string;
  org: string;
  as: string;  // "AS13335 Cloudflare, Inc."
}

async function ipApiLookup(ip: string): Promise<IpApiResponse | null> {
  const fields = "status,message,query,country,countryCode,region,regionName,city,isp,org,as";
  const url = `http://ip-api.com/json/${encodeURIComponent(ip)}?fields=${fields}`;
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(4000),
      // Force http (ip-api.com free tier is http only)
    });
    if (!res.ok) return null;
    const data = await res.json() as IpApiResponse;
    return data.status === "success" ? data : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// DNS resolution — get first IPv4 of a hostname
// ---------------------------------------------------------------------------

async function resolveIp(hostname: string): Promise<string | null> {
  try {
    const addresses = await dns.resolve4(hostname);
    return addresses[0] ?? null;
  } catch {
    // Fallback: try lookup
    try {
      const { address } = await dns.lookup(hostname, { family: 4 });
      return address;
    } catch {
      return null;
    }
  }
}

// ---------------------------------------------------------------------------
// Main exported function
// ---------------------------------------------------------------------------

export async function analyzeIp(
  /** IP address or hostname */
  target: string,
): Promise<IpIntelligenceResult | null> {
  const startTime = performance.now();

  // Determine whether target is already an IP or a hostname
  const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(target.trim());
  let ip: string | null = isIp ? target.trim() : null;

  if (!ip) {
    ip = await resolveIp(target.trim());
  }

  if (!ip) return null;

  // Skip RFC-1918 private addresses
  if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|0\.0\.0\.)/.test(ip)) {
    return null;
  }

  const geo = await ipApiLookup(ip);
  if (!geo) return null;

  const org         = geo.org ?? "";
  const isp         = geo.isp ?? "";
  const asnRaw      = geo.as ?? "";
  const countryCode = geo.countryCode ?? "";

  const hostingCategory  = classifyHosting(org, isp, asnRaw);
  const isDatacenter     = hostingCategory !== "residential" && hostingCategory !== "unknown";
  const isVpnOrProxy     = hostingCategory === "vpn_proxy" || hostingCategory === "tor";

  const countryRisk = HIGH_RISK_COUNTRIES[countryCode];

  // Compute country risk level
  const countryRiskLevel: IpIntelligenceResult["countryRiskLevel"] =
    countryRisk?.risk ?? "low";

  // Build evidence + score boost
  const evidence: IpIntelligenceResult["evidence"] = [];
  const flags: string[] = [];
  let scoreBoost = 0;

  // Hosting category signals
  if (hostingCategory === "tor") {
    evidence.push({ finding: `Server IP ${ip} routes through a Tor exit node — strong anonymization signal`, severity: "critical" });
    flags.push("TOR_EXIT_NODE");
    scoreBoost += 35;
  } else if (hostingCategory === "vpn_proxy") {
    evidence.push({ finding: `Server IP ${ip} belongs to a VPN/proxy provider (${org}) — hiding origin`, severity: "high" });
    flags.push("VPN_PROXY_HOSTING");
    scoreBoost += 22;
  } else if (hostingCategory === "vps") {
    evidence.push({ finding: `Site hosted on VPS provider (${org}) — scam sites preferentially use cheap VPS hosting`, severity: "medium" });
    flags.push("VPS_DATACENTER");
    scoreBoost += 12;
  } else if (hostingCategory === "cloud") {
    evidence.push({ finding: `Site hosted on major cloud platform (${org})`, severity: "low" });
    flags.push("CLOUD_HOSTED");
    scoreBoost += 3;
  }

  // Country risk signals
  if (countryRisk) {
    const sev: "medium" | "high" | "critical" = countryRisk.risk;
    evidence.push({ finding: `Server located in ${geo.country} — ${countryRisk.reason}`, severity: sev });
    flags.push(`HIGH_RISK_COUNTRY_${countryCode}`);
    scoreBoost += countryRisk.boost;
  }

  // ASN-specific signals — known scam infrastructure hosting
  const asnLower = asnRaw.toLowerCase();
  if (asnLower.includes("integen")) {
    evidence.push({ finding: `ASN associated with high-density scam site hosting (Anansi study: 12+ scam sites/IP)`, severity: "high" });
    scoreBoost += 15;
  }
  if (asnLower.includes("frantech") || asnLower.includes("buyvm")) {
    evidence.push({ finding: `ASN (${asnRaw}) associated with bulletproof hosting — favored by fraud operations`, severity: "high" });
    scoreBoost += 18;
  }

  return {
    ip,
    country:          geo.country ?? "",
    countryCode,
    region:           geo.regionName ?? geo.region ?? "",
    city:             geo.city ?? "",
    isp,
    org,
    asn:              asnRaw,
    hostingCategory,
    isDatacenter,
    isVpnOrProxy,
    countryRiskLevel,
    scoreBoost:       Math.min(40, scoreBoost),   // cap per-IP contribution at 40 pts
    evidence,
    flags,
    processingTimeMs: Math.round(performance.now() - startTime),
  };
}

/** Convenience wrapper: extract hostname from a URL string then analyze */
export async function analyzeUrlIp(urlOrDomain: string): Promise<IpIntelligenceResult | null> {
  try {
    let hostname: string;
    if (/^https?:\/\//i.test(urlOrDomain)) {
      hostname = new URL(urlOrDomain).hostname;
    } else {
      hostname = urlOrDomain.split("/")[0];
    }
    return analyzeIp(hostname);
  } catch {
    return null;
  }
}
