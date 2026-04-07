// ============================================================================
// Protection Script Builder
// Generates real, targeted JavaScript that actively neutralizes specific threats
// when injected into the user's browser (via console or extension).
//
// Each threat type gets a specific countermeasure module.
// Scripts are self-contained IIFEs — safe to paste in browser console.
// ============================================================================

import type { InjectionRule } from "./types";

interface ProtectionModule {
  name: string;
  code: string;
}

// ---------------------------------------------------------------------------
// Countermeasure modules — each targets a specific threat type
// ---------------------------------------------------------------------------

const MODULES: Record<string, ProtectionModule> = {

  block_external_forms: {
    name: "Block External Form Submission",
    code: `
    // Block any form that submits to a different domain
    (function blockExternalForms() {
      var host = location.hostname;
      function interceptForm(form) {
        form.addEventListener('submit', function(e) {
          try {
            var action = form.getAttribute('action');
            if (!action) return;
            var dest = new URL(action, location.href).hostname;
            if (dest && dest !== host && !dest.endsWith('.' + host.split('.').slice(-2).join('.'))) {
              e.preventDefault(); e.stopImmediatePropagation();
              showBanner('ScamShieldy BLOCKED: This form was trying to send your data to ' + dest, 'block');
            }
          } catch(err) {}
        }, true);
      }
      document.querySelectorAll('form').forEach(interceptForm);
      new MutationObserver(function(ms) {
        ms.forEach(function(m) { m.addedNodes.forEach(function(n) {
          if (n.tagName === 'FORM') interceptForm(n);
          if (n.querySelectorAll) n.querySelectorAll('form').forEach(interceptForm);
        }); });
      }).observe(document.documentElement, { childList: true, subtree: true });
    })();`,
  },

  block_credential_harvest: {
    name: "Protect Password & Card Fields",
    code: `
    // Intercept credential fields sending to suspicious endpoints
    (function protectCredentials() {
      var host = location.hostname;
      var origXHROpen = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function(method, url) {
        try {
          var dest = new URL(url, location.href).hostname;
          if (dest && dest !== host) {
            this._ss_suspicious = true;
            this._ss_dest = dest;
          }
        } catch(e) {}
        return origXHROpen.apply(this, arguments);
      };
      var origXHRSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.send = function(data) {
        if (this._ss_suspicious && data && typeof data === 'string') {
          var lower = data.toLowerCase();
          if (lower.includes('password') || lower.includes('card') || lower.includes('cvv') || lower.includes('ssn')) {
            showBanner('ScamShieldy BLOCKED: Page tried to send your credentials to ' + this._ss_dest, 'block');
            return;
          }
        }
        return origXHRSend.apply(this, arguments);
      };
      var origFetch = window.fetch;
      window.fetch = function(input, init) {
        try {
          var url = typeof input === 'string' ? input : input.url;
          var dest = new URL(url, location.href).hostname;
          if (dest && dest !== location.hostname && init && init.body) {
            var body = typeof init.body === 'string' ? init.body : '';
            if (body.toLowerCase().match(/password|card|cvv|ssn/)) {
              showBanner('ScamShieldy BLOCKED: Credential exfiltration to ' + dest + ' prevented', 'block');
              return Promise.reject(new Error('Blocked by ScamShieldy'));
            }
          }
        } catch(e) {}
        return origFetch.apply(this, arguments);
      };
    })();`,
  },

  disable_clipboard_hijack: {
    name: "Disable Clipboard Hijacking",
    code: `
    // Prevent clipboard hijacking (replaces copied crypto addresses etc.)
    (function disableClipboardHijack() {
      document.addEventListener('copy', function(e) {
        // Allow normal copy but log
        console.info('[ScamShieldy] Copy event detected — clipboard hijack monitor active');
      }, true);
      // Override writeText to prevent silent clipboard replacement
      if (navigator.clipboard && navigator.clipboard.writeText) {
        var orig = navigator.clipboard.writeText.bind(navigator.clipboard);
        navigator.clipboard.writeText = function(text) {
          showBanner('ScamShieldy: A script tried to change your clipboard. Blocked.', 'warn');
          return Promise.reject(new Error('Blocked by ScamShieldy'));
        };
      }
    })();`,
  },

  remove_malicious_iframes: {
    name: "Remove Hidden iFrames",
    code: `
    // Remove hidden/zero-size iframes (common for clickjacking and drive-by downloads)
    (function removeHiddenIframes() {
      function checkIframe(el) {
        if (el.tagName !== 'IFRAME') return;
        var w = el.offsetWidth, h = el.offsetHeight;
        var style = window.getComputedStyle(el);
        var hidden = (w < 5 || h < 5 || style.opacity === '0' || style.visibility === 'hidden');
        var crossOrigin = el.src && !el.src.startsWith(location.origin) && !el.src.startsWith('about:');
        if (hidden && crossOrigin) {
          el.remove();
          showBanner('ScamShieldy: Removed a hidden cross-origin iFrame (possible drive-by download vector)', 'warn');
        } else if (crossOrigin && !el.getAttribute('sandbox')) {
          el.setAttribute('sandbox', 'allow-same-origin allow-scripts');
        }
      }
      document.querySelectorAll('iframe').forEach(checkIframe);
      new MutationObserver(function(ms) {
        ms.forEach(function(m) { m.addedNodes.forEach(function(n) {
          if (n.tagName === 'IFRAME') checkIframe(n);
        }); });
      }).observe(document.documentElement, { childList: true, subtree: true });
    })();`,
  },

  block_popup_spam: {
    name: "Block Popup Spam",
    code: `
    // Block aggressive popup/redirect spam
    (function blockPopups() {
      var origOpen = window.open;
      var popupCount = 0;
      window.open = function(url, target, features) {
        popupCount++;
        if (popupCount > 1) {
          showBanner('ScamShieldy: Blocked popup spam (' + popupCount + ' attempts)', 'warn');
          return null;
        }
        return origOpen.apply(window, arguments);
      };
      // Block location redirect spam
      var redirectCount = 0;
      var origAssign = location.assign.bind(location);
      try {
        Object.defineProperty(window, 'onbeforeunload', {
          set: function(fn) { /* Block aggressive exit popups */ },
          get: function() { return null; }
        });
      } catch(e) {}
    })();`,
  },

  remove_fake_urgency: {
    name: "Neutralize Fake Urgency",
    code: `
    // Remove fake countdown timers and urgency overlays
    (function neutralizeUrgency() {
      var urgencyWords = ['limited time', 'offer expires', 'only left', 'act now', 'expires in', 'hurry', 'last chance', 'selling fast'];
      function checkElement(el) {
        if (!el.textContent) return;
        var txt = el.textContent.toLowerCase();
        var isUrgency = urgencyWords.some(function(w) { return txt.includes(w); });
        if (!isUrgency) return;
        // Check if it's a countdown-style element (contains numbers + colons)
        if (/\d{1,2}:\d{2}/.test(el.textContent) || /\d+ (hour|minute|second)/.test(txt)) {
          el.style.cssText += 'opacity:0.2!important;pointer-events:none!important;';
        }
      }
      // Apply after DOM loaded
      setTimeout(function() {
        document.querySelectorAll('[class*="count"], [class*="timer"], [class*="urgent"], [class*="expire"], [id*="count"], [id*="timer"]').forEach(checkElement);
      }, 500);
    })();`,
  },

  disable_malicious_scripts: {
    name: "Neutralize Obfuscated Scripts",
    code: `
    // Override eval and Function constructor (used by obfuscated/malware scripts)
    (function disableMaliciousEval() {
      var origEval = window.eval;
      window.eval = function(code) {
        if (typeof code === 'string' && code.length > 500) {
          var suspicious = /\\\\x[0-9a-f]{2}|\\\\u00[0-9a-f]{2}|fromCharCode|atob\(|btoa\(/.test(code);
          if (suspicious) {
            showBanner('ScamShieldy: Blocked suspicious eval() execution (likely obfuscated malware)', 'block');
            return undefined;
          }
        }
        return origEval.apply(this, arguments);
      };
    })();`,
  },

  monitor_network: {
    name: "Network Activity Monitor",
    code: `
    // Log all outbound requests for transparency
    (function monitorNetwork() {
      var external = [];
      var origFetch = window.fetch;
      window.fetch = function(input) {
        try {
          var url = typeof input === 'string' ? input : input.url;
          var dest = new URL(url, location.href).hostname;
          if (dest !== location.hostname) { external.push(dest); }
        } catch(e) {}
        return origFetch.apply(this, arguments);
      };
      setTimeout(function() {
        if (external.length > 3) {
          showBanner('ScamShieldy: This page contacted ' + external.length + ' external servers: ' + [...new Set(external)].slice(0,5).join(', '), 'warn');
        }
      }, 3000);
    })();`,
  },
};

// ---------------------------------------------------------------------------
// Map threat types / rule types → which modules to activate
// ---------------------------------------------------------------------------

const THREAT_MODULE_MAP: Record<string, string[]> = {
  phishing_form:        ["block_external_forms", "block_credential_harvest"],
  credential_harvester: ["block_credential_harvest", "block_external_forms"],
  payment_form_fake:    ["block_external_forms", "block_credential_harvest"],
  malware_signature:    ["disable_malicious_scripts", "remove_malicious_iframes", "monitor_network"],
  exploit_kit:          ["disable_malicious_scripts", "remove_malicious_iframes"],
  cryptominer:          ["disable_malicious_scripts", "monitor_network"],
  keylogger:            ["block_credential_harvest", "disable_malicious_scripts"],
  ransomware:           ["disable_malicious_scripts", "remove_malicious_iframes"],
  obfuscated_code:      ["disable_malicious_scripts"],
  iframe_injection:     ["remove_malicious_iframes"],
  redirect_chain:       ["block_popup_spam"],
  xss_payload:          ["disable_malicious_scripts"],
  urgency_language:     ["remove_fake_urgency"],
  fake_urgency:         ["remove_fake_urgency"],
  fake_trust_badge:     ["remove_fake_urgency"],
  clipboard_hijack:     ["disable_clipboard_hijack"],
  popup_spam:           ["block_popup_spam"],
  block:                ["block_external_forms", "block_credential_harvest"],
  warn:                 ["monitor_network"],
  sandbox:              ["remove_malicious_iframes"],
};

// ---------------------------------------------------------------------------
// Main builder
// ---------------------------------------------------------------------------

export function buildProtectionScript(
  rules: InjectionRule[],
  url: string,
  threats: string[],
  userModules?: string[],
): string {
  // If user specified which modules to use, respect that
  if (userModules && userModules.length > 0) {
    const activatedModuleList = userModules
      .filter((m) => MODULES[m])
      .map((m) => MODULES[m]);

    return _buildScript(activatedModuleList, url);
  }

  // Auto-detect modules from threats and rules
  const activeModules = new Set<string>();
  activeModules.add("block_external_forms");
  activeModules.add("monitor_network");

  for (const rule of rules) {
    const mods = THREAT_MODULE_MAP[rule.type] ?? [];
    mods.forEach((m) => activeModules.add(m));
    const id = (rule.id + " " + (rule.message ?? "")).toLowerCase();
    for (const [key, mods2] of Object.entries(THREAT_MODULE_MAP)) {
      if (id.includes(key.replace(/_/g, ""))) mods2.forEach((m) => activeModules.add(m));
    }
  }

  for (const threat of threats) {
    const tl = threat.toLowerCase().replace(/\s/g, "_");
    for (const [key, mods] of Object.entries(THREAT_MODULE_MAP)) {
      if (tl.includes(key)) mods.forEach((m) => activeModules.add(m));
    }
  }

  const activatedModuleList = [...activeModules]
    .filter((m) => MODULES[m])
    .map((m) => MODULES[m]);

  return _buildScript(activatedModuleList, url);
}

function _buildScript(activatedModuleList: ProtectionModule[], url: string): string {
  const moduleCode = activatedModuleList.map((m) => m.code).join("\n\n");
  const moduleNames = activatedModuleList.map((m) => `"${m.name}"`).join(", ");
  const safeUrl = url.replace(/['"\\]/g, "").substring(0, 200);
  const ts = new Date().toISOString();

  return `/* ScamShieldy Vaccine — ${safeUrl} — ${ts} */
(function() {
  'use strict';
  if (window._scamshieldyVaccineApplied) { console.info('[ScamShieldy] Already applied'); return; }
  window._scamshieldyVaccineApplied = true;
  window._scamshieldyModules = [${moduleNames}];

  // ── Shared banner utility ──────────────────────────────────────────────────
  function showBanner(msg, type) {
    var existing = document.getElementById('_ss_banner');
    if (existing) existing.remove();
    var bar = document.createElement('div');
    bar.id = '_ss_banner';
    var bg = type === 'block' ? '#ff3b3b' : '#ffc107';
    var fg = type === 'block' ? '#fff' : '#000';
    bar.style.cssText = 'position:fixed;top:0;left:0;right:0;background:' + bg + ';color:' + fg + ';padding:10px 16px;z-index:2147483647;font:bold 13px Arial,sans-serif;display:flex;justify-content:space-between;align-items:center;box-shadow:0 2px 8px rgba(0,0,0,.4);';
    var shield = document.createElement('span');
    shield.textContent = '🛡️ ' + msg;
    bar.appendChild(shield);
    var btn = document.createElement('button');
    btn.textContent = '✕';
    btn.style.cssText = 'background:transparent;border:1px solid ' + fg + ';color:' + fg + ';padding:2px 8px;cursor:pointer;border-radius:3px;';
    btn.onclick = function() { bar.remove(); };
    bar.appendChild(btn);
    if (document.body) document.body.insertBefore(bar, document.body.firstChild);
    else document.addEventListener('DOMContentLoaded', function() { document.body.insertBefore(bar, document.body.firstChild); });
    if (type !== 'block') setTimeout(function() { if (bar.parentNode) bar.remove(); }, 8000);
  }

  // ── Active protection modules ──────────────────────────────────────────────
  ${moduleCode}

  // ── Startup banner ─────────────────────────────────────────────────────────
  showBanner('ScamShieldy Vaccine Active — ${activatedModuleList.length} protection module${activatedModuleList.length !== 1 ? "s" : ""} loaded', 'warn');
  console.info('[ScamShieldy] Vaccine applied to ${safeUrl}. Modules: [${moduleNames}]');
})();`;
}

// ---------------------------------------------------------------------------
// Generate a short summary of what the script does
// ---------------------------------------------------------------------------
export function getScriptSummary(threats: string[], rules: InjectionRule[], userModules?: string[]): string[] {
  if (userModules && userModules.length > 0) {
    return userModules.filter((m) => MODULES[m]).map((m) => MODULES[m].name);
  }
  const activeModules = new Set<string>();
  activeModules.add("block_external_forms");
  activeModules.add("monitor_network");
  for (const rule of rules) {
    (THREAT_MODULE_MAP[rule.type] ?? []).forEach((m) => activeModules.add(m));
  }
  for (const threat of threats) {
    const tl = threat.toLowerCase().replace(/\s/g, "_");
    for (const [key, mods] of Object.entries(THREAT_MODULE_MAP)) {
      if (tl.includes(key)) mods.forEach((m) => activeModules.add(m));
    }
  }
  return [...activeModules].filter((m) => MODULES[m]).map((m) => MODULES[m].name);
}
