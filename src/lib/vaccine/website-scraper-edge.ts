/**
 * Website Scraper (Edge-compatible)
 * Uses regex-based HTML parsing for Vercel Edge Runtime
 *
 * Security hardening:
 * - SSRF protection via safeFetch (validates URLs, blocks private IPs, limits redirects)
 * - Content-Type validation (only process text/html)
 * - Response size limit (512KB max, streamed with early abort)
 * - ReDoS-safe regexes (no nested quantifiers, input truncated before processing)
 * - TLS enforcement (reject non-HTTPS for sensitive content)
 */

import {
  ScrapedWebsiteAnalysis,
  ScrapedScript,
  ScrapedForm,
  ScrapedLink,
} from "./types";
import { safeFetch, sanitizeUrlForLog } from "./url-validator";

const MAX_HTML_SIZE = 512 * 1024; // 512KB — truncate before regex processing

export class WebsiteScraperEdge {
  async scrapeWebsite(url: string): Promise<ScrapedWebsiteAnalysis> {
    try {
      const domain = this.extractDomain(url);

      // Use safeFetch with SSRF protection, redirect validation, Content-Type check
      const response = await safeFetch(url, {
        timeoutMs: 15000,
        maxResponseBytes: MAX_HTML_SIZE,
        requireHtml: true,
      });

      // Stream response with size limit
      const html = await this.readResponseWithLimit(response, MAX_HTML_SIZE);

      return {
        url,
        timestamp: Date.now(),
        httpStatusCode: response.status,
        title: this.extractTitle(html),
        domain,
        html: html.substring(0, 50000), // Store truncated for analysis
        scripts: this.extractScripts(html),
        forms: this.extractForms(html, domain),
        links: this.extractLinks(html, domain),
        mediaElements: [],
        metaTags: {},
        textContent: this.extractText(html),
        isDomainMatch: domain.length > 0,
      };
    } catch (error) {
      throw new Error(
        `Failed to scrape ${sanitizeUrlForLog(url)}: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Read response body with a hard size limit.
   * Aborts early if response exceeds limit (prevents zip bombs, huge binaries).
   */
  private async readResponseWithLimit(response: Response, maxBytes: number): Promise<string> {
    const reader = response.body?.getReader();
    if (!reader) {
      return await response.text();
    }

    const decoder = new TextDecoder();
    let result = '';
    let totalBytes = 0;

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        totalBytes += value.length;
        if (totalBytes > maxBytes) {
          reader.cancel();
          // Return what we have so far — don't fail, just truncate
          break;
        }

        result += decoder.decode(value, { stream: true });
      }
    } catch {
      // Ignore read errors, return what we have
    }

    return result;
  }

  private extractDomain(url: string): string {
    try {
      return new URL(url).hostname || "";
    } catch {
      return "";
    }
  }

  private extractTitle(html: string): string {
    // ReDoS-safe: no nested quantifiers, non-greedy with bounded length
    const match = html.match(/<title[^>]{0,100}>([\s\S]{0,500}?)<\/title>/i);
    return match ? match[1].trim() : "";
  }

  private extractScripts(html: string): ScrapedScript[] {
    const scripts: ScrapedScript[] = [];
    // ReDoS-safe: [^"]* is linear, no nested quantifiers
    const regex = /<script[^>]{0,500}?src="([^"]{1,2000})"[^>]{0,500}?>/gi;
    let match;
    let count = 0;

    while ((match = regex.exec(html)) !== null && count < 50) {
      const src = match[1];
      scripts.push({
        src,
        inline: false,
        content: "",
        isObfuscated: this.isObfuscated(src),
        suspicionScore: this.isObfuscated(src) ? 0.8 : 0.2,
      });
      count++;
    }

    return scripts;
  }

  private extractForms(html: string, domain: string): ScrapedForm[] {
    const forms: ScrapedForm[] = [];
    // ReDoS-safe: use [\s\S]{0,10000}? with bounded quantifier instead of [\s\S]*?
    const formRegex = /<form[^>]{0,500}?action="([^"]{0,2000})"[^>]{0,500}?>([\s\S]{0,10000}?)<\/form>/gi;
    let match;
    let count = 0;

    while ((match = formRegex.exec(html)) !== null && count < 20) {
      const action = match[1];
      const formHtml = match[2];

      const fields: any[] = [];
      // ReDoS-safe: bounded attribute values
      const inputRegex = /<input[^>]{0,500}?type="([^"]{1,100})"[^>]{0,500}?name="([^"]{1,200})"[^>]{0,500}?>/gi;
      let inputMatch;
      let fieldCount = 0;

      while ((inputMatch = inputRegex.exec(formHtml)) !== null && fieldCount < 50) {
        fields.push({
          type: inputMatch[1],
          name: inputMatch[2],
          fieldSuspicionScore: this.computeFieldSuspicion(inputMatch[2], inputMatch[1]),
        });
        fieldCount++;
      }

      // Determine method safely
      const methodMatch = formHtml.match(/method="(post|get)"/i);
      const method = methodMatch ? methodMatch[1].toUpperCase() : "GET";

      forms.push({
        action: action || "",
        method,
        fields,
        targetDomain:
          action && !action.includes(domain) && action.includes("http")
            ? action
            : undefined,
      });
      count++;
    }

    return forms;
  }

  private extractLinks(html: string, domain: string): ScrapedLink[] {
    const links: ScrapedLink[] = [];
    // ReDoS-safe: bounded attribute and content
    const regex = /<a[^>]{0,500}?href="([^"]{1,2000})"[^>]{0,500}?>([\s\S]{0,500}?)<\/a>/gi;
    let match;
    let count = 0;

    while ((match = regex.exec(html)) !== null && count < 100) {
      const href = match[1];
      if (href && !href.startsWith("#")) {
        links.push({
          url: href,
          text: match[2].substring(0, 100),
          isExternal: href.includes("http") && !href.includes(domain),
        });
      }
      count++;
    }

    return links;
  }

  /**
   * Extract text content safely (replace tags, don't use unbounded regex).
   */
  private extractText(html: string): string {
    // Truncate before processing to prevent ReDoS on large input
    const truncated = html.substring(0, 100000);
    return truncated.replace(/<[^>]{0,1000}>/g, " ").substring(0, 50000);
  }

  private isObfuscated(src: string): boolean {
    return src.length > 100 && /[a-z0-9]{20,}/.test(src);
  }

  /**
   * Compute field suspicion based on name/type patterns.
   */
  private computeFieldSuspicion(name: string, type: string): number {
    const lowerName = name.toLowerCase();
    const lowerType = type.toLowerCase();

    if (/password|pwd|pass|secret/.test(lowerName)) return 40;
    if (/credit|card|cvv|cvc|payment/.test(lowerName)) return 50;
    if (/ssn|social.*security|taxpayer/.test(lowerName)) return 50;
    if (/pin|otp|token|verify|confirm/.test(lowerName)) return 30;
    if (/email|username|login|account/.test(lowerName)) return 20;
    if (lowerType === 'hidden') return 15;
    if (lowerType === 'password') return 35;

    return 5;
  }
}
