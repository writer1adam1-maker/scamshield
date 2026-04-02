/**
 * JavaScript Vaccine Injection Engine
 * Generates protective scripts and injection rules based on detected threats
 *
 * Security hardening:
 * - NO user-supplied data interpolated into generated JavaScript
 * - All dynamic values passed via JSON.stringify (auto-escapes) or data attributes
 * - Parameterized templates only — no string concatenation with untrusted data
 * - Selectors validated against allowlist to prevent injection via CSS selectors
 * - Rule IDs are sanitized (alphanumeric + dash only)
 */

import {
  VaccineThreat,
  InjectionRule,
  VaccineThreatType,
  InjectionPayload,
} from "./types";

// Allowlist of safe CSS selectors (prevents injection via crafted selectors)
const SAFE_SELECTOR_PATTERN = /^[a-zA-Z0-9\[\]="*.,:#\-_ ]+$/;
const SAFE_RULE_ID_PATTERN = /^[a-zA-Z0-9\-_]+$/;

export class InjectionEngine {
  /**
   * Generate injection rules from detected threats
   */
  generateInjectionRules(threats: VaccineThreat[]): InjectionRule[] {
    return threats
      .filter(t => t && t.injectionRule)
      .map((threat) => this.sanitizeRule(threat.injectionRule));
  }

  /**
   * Sanitize a rule before it enters our system.
   */
  private sanitizeRule(rule: InjectionRule): InjectionRule {
    return {
      ...rule,
      id: this.sanitizeRuleId(rule.id),
      selector: rule.selector ? this.sanitizeSelector(rule.selector) : undefined,
      message: rule.message ? this.sanitizeMessage(rule.message) : undefined,
    };
  }

  private sanitizeRuleId(id: string): string {
    // Strip anything that isn't alphanumeric, dash, or underscore
    return id.replace(/[^a-zA-Z0-9\-_]/g, '').substring(0, 100);
  }

  private sanitizeSelector(selector: string): string {
    if (!SAFE_SELECTOR_PATTERN.test(selector)) {
      return 'body'; // fallback to body if selector looks suspicious
    }
    return selector.substring(0, 200);
  }

  private sanitizeMessage(message: string): string {
    // Remove any characters that could break out of JS strings or HTML
    return message
      .replace(/[<>]/g, '')      // Strip HTML tags
      .replace(/['"\\]/g, '')    // Strip quotes and backslashes
      .replace(/[\x00-\x1f]/g, '') // Strip control characters
      .substring(0, 500);
  }

  /**
   * Generate protective JavaScript payload for content script injection.
   *
   * CRITICAL: All dynamic data is injected via JSON.stringify which auto-escapes.
   * No string concatenation with untrusted values.
   */
  generateProtectionPayload(rules: InjectionRule[]): string {
    const sanitizedRules = rules.map(r => this.sanitizeRule(r));
    return this.buildProtectionScript(sanitizedRules);
  }

  /**
   * Build the protection script using parameterized template.
   * Dynamic data is injected ONLY through the RULES_DATA JSON blob.
   */
  private buildProtectionScript(rules: InjectionRule[]): string {
    // JSON.stringify auto-escapes all special characters (quotes, backslashes, etc.)
    const rulesJson = JSON.stringify(rules);

    return `
    (function() {
      'use strict';
      if (window._scamshieldVaccineApplied) return;
      window._scamshieldVaccineApplied = true;

      var RULES = ${rulesJson};

      function applyBlockRules() {
        RULES.filter(function(r) { return r.type === 'block'; }).forEach(function(rule) {
          try {
            var el = rule.selector ? document.querySelector(rule.selector) : null;
            if (!el) return;

            var overlay = document.createElement('div');
            overlay.setAttribute('data-scamshield-block', rule.id);
            overlay.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;background:rgba(255,59,59,0.15);border:3px solid #ff3b3b;pointer-events:all;display:flex;align-items:center;justify-content:center;z-index:999999;font-family:Arial,sans-serif;color:#ff3b3b;font-weight:bold;font-size:14px;';

            var msg = document.createElement('span');
            msg.textContent = rule.message || 'Blocked by ScamShield';
            overlay.appendChild(msg);

            el.style.position = 'relative';
            el.appendChild(overlay);

            if (el.tagName === 'FORM') {
              el.addEventListener('submit', function(e) {
                e.preventDefault();
                e.stopPropagation();
              }, true);
            }
          } catch(e) {}
        });
      }

      function applyWarnRules() {
        RULES.filter(function(r) { return r.type === 'warn'; }).forEach(function(rule) {
          try {
            var bar = document.createElement('div');
            bar.setAttribute('data-scamshield-warn', rule.id);
            bar.style.cssText = 'position:fixed;top:0;left:0;right:0;background:#fff3cd;border-bottom:3px solid #ffc107;padding:12px 16px;z-index:999999;font-family:Arial,sans-serif;font-size:14px;color:#856404;box-shadow:0 2px 4px rgba(0,0,0,0.1);display:flex;justify-content:space-between;align-items:center;';

            var text = document.createElement('span');
            text.textContent = rule.message || 'Warning from ScamShield';
            bar.appendChild(text);

            var btn = document.createElement('button');
            btn.textContent = 'Dismiss';
            btn.style.cssText = 'background:#ffc107;border:none;padding:6px 12px;cursor:pointer;border-radius:4px;font-weight:bold;';
            btn.addEventListener('click', function() { bar.style.display = 'none'; });
            bar.appendChild(btn);

            document.body.insertBefore(bar, document.body.firstChild);
          } catch(e) {}
        });
      }

      function applySandboxRules() {
        RULES.filter(function(r) { return r.type === 'sandbox'; }).forEach(function(rule) {
          try {
            var iframes = document.querySelectorAll('iframe:not([sandbox])');
            iframes.forEach(function(iframe) {
              if (!iframe.src || !iframe.src.startsWith('chrome-extension://')) {
                iframe.setAttribute('sandbox', 'allow-same-origin');
              }
            });

            var observer = new MutationObserver(function(mutations) {
              mutations.forEach(function(m) {
                m.addedNodes.forEach(function(node) {
                  if (node.tagName === 'IFRAME' && !node.getAttribute('sandbox')) {
                    node.setAttribute('sandbox', 'allow-same-origin');
                  }
                });
              });
            });
            observer.observe(document.documentElement, { childList: true, subtree: true });
          } catch(e) {}
        });
      }

      function applyMonitorRules() {
        RULES.filter(function(r) { return r.type === 'monitor'; }).forEach(function(rule) {
          try {
            document.addEventListener('submit', function(e) {
              console.warn('[ScamShield Monitor] Form submission detected:', e.target.action || 'no action');
            }, true);
          } catch(e) {}
        });
      }

      if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
          applyBlockRules(); applyWarnRules(); applySandboxRules(); applyMonitorRules();
        });
      } else {
        applyBlockRules(); applyWarnRules(); applySandboxRules(); applyMonitorRules();
      }
    })();
    `;
  }

  /**
   * Generate complete injection script for browser extension content script.
   *
   * All rule data is serialized via JSON.stringify (safe).
   * No string interpolation with untrusted data.
   */
  generateContentScript(rules: InjectionRule[]): string {
    const sanitizedRules = rules.map(r => this.sanitizeRule(r));
    return this.buildProtectionScript(sanitizedRules);
  }
}

export const injectionEngine = new InjectionEngine();
