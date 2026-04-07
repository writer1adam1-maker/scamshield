/**
 * ScamShield Browser Extension - Content Script
 * Injects protective scripts into every webpage
 *
 * Security hardening:
 * - Pinned API domain (no dynamic URLs)
 * - Response schema validation before injection
 * - No blind eval/injection of server responses
 * - Origin check on all API responses
 * - Rate-limited API requests (max 1 per page load)
 * - Signature verification stub (verifies signedAt freshness)
 */

(function () {
  'use strict';

  // ─── PINNED CONFIG (never loaded from external source) ───
  const API_DOMAIN = 'scamshieldy.com';
  const API_BASE = 'https://' + API_DOMAIN;
  const MAX_PAYLOAD_AGE_MS = 60 * 60 * 1000; // 1 hour
  const MAX_SCRIPT_LENGTH = 100000; // 100KB max injection payload

  // Prevent double-injection
  if (window._scamshieldContentScriptLoaded) return;
  window._scamshieldContentScriptLoaded = true;

  // ─── ANNOUNCE EXTENSION PRESENCE + RESPOND TO PINGS ───
  const _isOurDomain = window.location.hostname === 'scamshieldy.com' || window.location.hostname === 'scamshield-green.vercel.app';
  if (_isOurDomain) {
    // Announce immediately and after short delay (handles React mount timing)
    window.postMessage({ type: 'SCAMSHIELDY_EXTENSION_PRESENT', version: '2.0.0' }, window.location.origin);
    setTimeout(() => window.postMessage({ type: 'SCAMSHIELDY_EXTENSION_PRESENT', version: '2.0.0' }, window.location.origin), 400);
    // Also respond to pings from the page
    window.addEventListener('message', function (e) {
      if (e.origin !== window.location.origin) return;
      if (e.data && e.data.type === 'SCAMSHIELDY_PING') {
        window.postMessage({ type: 'SCAMSHIELDY_PONG', version: '2.0.0' }, window.location.origin);
      }
    });
  }

  // ─── NOTIFY BACKGROUND SCRIPT ───
  chrome.runtime.sendMessage(
    { type: 'page_loaded', url: window.location.href },
    (response) => {
      if (chrome.runtime.lastError) return;
      if (response && response.inject && response.injectionRules) {
        if (validateInjectionRules(response.injectionRules)) {
          applyVaccine(response.injectionRules);
        }
      }
    }
  );

  // ─── REQUEST VACCINE FROM API ───
  async function requestVaccine() {
    try {
      const url = API_BASE + '/api/vaccine/inject?url=' + encodeURIComponent(window.location.href);

      const response = await fetch(url, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
      });

      if (!response.ok) {
        console.warn('ScamShield: Vaccine request failed', response.status);
        return null;
      }

      // Verify response came from our domain
      const responseUrl = new URL(response.url);
      if (responseUrl.hostname !== API_DOMAIN) {
        console.error('ScamShield: Response origin mismatch, rejecting');
        return null;
      }

      const data = await response.json();

      // Validate response schema
      if (!validateApiResponse(data)) {
        console.error('ScamShield: Invalid API response schema, rejecting');
        return null;
      }

      // Verify payload freshness (prevent replay)
      if (data.signedAt && (Date.now() - data.signedAt) > MAX_PAYLOAD_AGE_MS) {
        console.warn('ScamShield: Stale payload rejected');
        return null;
      }

      return data.script;
    } catch (error) {
      console.warn('ScamShield: Vaccine request error', error);
      return null;
    }
  }

  // ─── SCHEMA VALIDATION ───

  /**
   * Validate API response before using any of its data.
   * Rejects anything that doesn't match expected shape.
   */
  function validateApiResponse(data) {
    if (!data || typeof data !== 'object') return false;
    if (data.script && typeof data.script !== 'string') return false;
    if (data.script && data.script.length > MAX_SCRIPT_LENGTH) return false;
    if (data.signature && typeof data.signature !== 'string') return false;
    if (data.signedAt && typeof data.signedAt !== 'number') return false;
    return true;
  }

  /**
   * Validate injection rules array before processing.
   */
  function validateInjectionRules(rules) {
    if (!Array.isArray(rules)) return false;
    if (rules.length > 50) return false; // Sanity cap

    const validTypes = ['block', 'warn', 'sandbox', 'disable', 'monitor'];

    for (const rule of rules) {
      if (!rule || typeof rule !== 'object') return false;
      if (!rule.type || !validTypes.includes(rule.type)) return false;
      if (rule.id && typeof rule.id !== 'string') return false;
      if (rule.selector && typeof rule.selector !== 'string') return false;
      if (rule.message && typeof rule.message !== 'string') return false;

      // Block potentially dangerous selectors (CSS injection)
      if (rule.selector && /[{}();]/.test(rule.selector)) return false;
    }

    return true;
  }

  // ─── APPLY VACCINE ───

  /**
   * Apply vaccine protection using validated rules.
   * Does NOT inject raw server scripts. Instead, reads rule data
   * and applies protections locally with known-safe code.
   */
  function applyVaccine(rules) {
    try {
      if (!Array.isArray(rules)) return;

      // Store rules for page-context access via data attribute (not global)
      const rulesData = JSON.stringify(rules);

      // Apply protections using our own local code (not server-provided JS)
      applyBlockProtections(rules);
      applyWarnProtections(rules);
      applySandboxProtections(rules);
      applyMonitorProtections(rules);

      console.log('ScamShield: Vaccine applied with', rules.length, 'rules');
    } catch (error) {
      console.error('ScamShield: Vaccine application error', error);
    }
  }

  // ─── LOCAL PROTECTION FUNCTIONS (never from server) ───

  function applyBlockProtections(rules) {
    const blockRules = rules.filter(function (r) { return r.type === 'block'; });
    if (blockRules.length === 0) return;

    document.addEventListener('submit', function (e) {
      var form = e.target;
      var action = form.getAttribute('action') || '';
      if (!action) return;

      try {
        var formDomain = new URL(action, window.location.href).hostname;
        var currentDomain = window.location.hostname;

        if (formDomain && formDomain !== currentDomain) {
          e.preventDefault();
          e.stopPropagation();
          console.warn('ScamShield: blocked form submission to external domain:', formDomain);
        }
      } catch (err) { }
    }, true);

    // Visual overlay on blocked forms
    blockRules.forEach(function (rule) {
      if (!rule.selector) return;
      try {
        var el = document.querySelector(rule.selector);
        if (!el) return;

        var overlay = document.createElement('div');
        overlay.style.cssText = 'position:absolute;top:0;left:0;width:100%;height:100%;background:rgba(255,59,59,0.12);border:3px solid #ff3b3b;display:flex;align-items:center;justify-content:center;z-index:999999;font-family:Arial,sans-serif;pointer-events:all;';

        var span = document.createElement('span');
        span.style.cssText = 'color:#ff3b3b;font-weight:bold;font-size:14px;';
        // Use textContent, not innerHTML (XSS-safe)
        span.textContent = rule.message || 'Blocked by ScamShield';
        overlay.appendChild(span);

        el.style.position = 'relative';
        el.appendChild(overlay);
      } catch (e) { }
    });
  }

  function applyWarnProtections(rules) {
    // Warn rules are logged silently — no intrusive banner
    var warnRules = rules.filter(function (r) { return r.type === 'warn'; });
    if (warnRules.length > 0) {
      console.warn('ScamShield: ' + warnRules.length + ' warning(s) on this page');
    }
  }

  function applySandboxProtections(rules) {
    var sandboxRules = rules.filter(function (r) { return r.type === 'sandbox'; });
    if (sandboxRules.length === 0) return;

    // Sandbox existing iframes
    var iframes = document.querySelectorAll('iframe:not([sandbox])');
    iframes.forEach(function (iframe) {
      if (!iframe.src || !iframe.src.startsWith('chrome-extension://')) {
        iframe.setAttribute('sandbox', 'allow-same-origin');
      }
    });

    // Watch for new iframes
    var observer = new MutationObserver(function (mutations) {
      mutations.forEach(function (m) {
        m.addedNodes.forEach(function (node) {
          if (node.tagName === 'IFRAME' && !node.getAttribute('sandbox')) {
            node.setAttribute('sandbox', 'allow-same-origin');
          }
        });
      });
    });
    observer.observe(document.documentElement, { childList: true, subtree: true });
  }

  function applyMonitorProtections(rules) {
    var monitorRules = rules.filter(function (r) { return r.type === 'monitor'; });
    if (monitorRules.length === 0) return;

    document.addEventListener('submit', function (e) {
      console.warn('[ScamShield Monitor] Form submission:', e.target.action || '(no action)');
    }, true);
  }

  // ─── VACCINE INJECT FROM WEB PAGE (via window.postMessage) ───
  // Allows scamshieldy.com vaccine page to push rules directly to extension.
  window.addEventListener('message', function (event) {
    // Only trust messages from scamshieldy.com
    if (event.origin !== 'https://scamshieldy.com' && event.origin !== 'https://scamshield-green.vercel.app') return;
    if (!event.data || event.data.type !== 'SCAMSHIELDY_VACCINE_INJECT') return;

    var url = event.data.url;
    var rules = event.data.rules;

    if (!url || typeof url !== 'string') return;
    if (!validateInjectionRules(rules)) return;

    // Forward to background script to cache for that URL
    chrome.runtime.sendMessage(
      { type: 'store_vaccine', url: url, rules: rules },
      function (response) {
        if (chrome.runtime.lastError) return;
        if (response && response.status === 'stored') {
          console.log('ScamShield: Vaccine stored for', url);
        }
      }
    );
  });

  // ─── MESSAGE LISTENER ───
  chrome.runtime.onMessage.addListener(function (request, sender, sendResponse) {
    if (request.type === 'inject_vaccine') {
      if (validateInjectionRules(request.rules)) {
        applyVaccine(request.rules);
        sendResponse({ status: 'injected' });
      } else {
        sendResponse({ status: 'rejected', reason: 'invalid rules' });
      }
    } else if (request.type === 'get_page_info') {
      sendResponse({
        url: window.location.href,
        title: document.title,
        domain: window.location.hostname,
      });
    }
  });

  // ─── INITIAL VACCINE REQUEST ───
  // Small delay to ensure document is ready; only one request per page load
  setTimeout(async function () {
    var script = await requestVaccine();
    // NOTE: We no longer blindly inject server-returned scripts.
    // The server now returns rule data, and we apply protections locally.
    // This prevents a compromised API from injecting arbitrary JS.
    if (script && typeof script === 'string' && script.length < MAX_SCRIPT_LENGTH) {
      // Parse rules from the signed payload if it contains JSON rules
      try {
        // If the server sends structured rules, use them
        if (script.startsWith('{') || script.startsWith('[')) {
          var parsed = JSON.parse(script);
          if (validateInjectionRules(parsed)) {
            applyVaccine(parsed);
          }
        }
        // Otherwise, the default protection script was returned — that's fine,
        // our local protections are already active from the background script rules.
      } catch (e) {
        // Script wasn't JSON rules — local protections still active
      }
    }
  }, 100);
})();
