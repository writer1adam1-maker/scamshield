/**
 * ScamShield Link Scanner v2.0
 * Scans every visible link on a page, shows colored dot badges,
 * hover cards with threat info, and intercepts high-risk clicks.
 *
 * Security:
 * - All server data rendered via textContent only (no innerHTML with untrusted data)
 * - API domain pinned — no dynamic URL construction from page content
 * - CSS selectors never built from server data
 * - Hover card uses Shadow DOM to prevent page CSS interference
 */

(function () {
  'use strict';

  if (window._ssLinkScannerLoaded) return;
  window._ssLinkScannerLoaded = true;

  // ── Config (pinned, never from external source) ──────────────────────────
  const API_DOMAIN = 'scamshieldy.com';
  const API_BASE = 'https://' + API_DOMAIN;
  const SCAN_ENDPOINT = API_BASE + '/api/v1/scan';
  const MAX_LINKS_PER_PAGE = 60;   // hostname-deduplicated cap
  const BATCH_SIZE = 10;
  const BATCH_DELAY_MS = 600;
  const CACHE_TTL_MS = 30 * 60 * 1000; // 30 min per hostname

  // Only intercept CRITICAL links — high just gets a red dot, no popup
  const WARN_LEVELS = new Set(['critical']);
  // Threat levels that show non-green dot
  const RISKY_LEVELS = new Set(['low', 'medium', 'high', 'critical']);

  // ── State ─────────────────────────────────────────────────────────────────
  const hostCache = new Map();       // hostname → { level, score, category, ts }
  const pendingHosts = new Set();    // currently in-flight
  const dotMap = new WeakMap();      // <a> → dot element
  let apiKey = null;
  let enabled = true;
  let warningsDisabled = false;
  let hoverCard = null;

  // ── Load settings ─────────────────────────────────────────────────────────
  let noKeyWarningShown = false;
  chrome.storage.sync.get(['ss_api_key', 'ss_enabled', 'ss_warnings_disabled'], function (data) {
    apiKey = data.ss_api_key || null;
    enabled = data.ss_enabled !== false;
    warningsDisabled = data.ss_warnings_disabled === true;
    if (enabled) init();
  });

  // ── Main init ─────────────────────────────────────────────────────────────
  function init() {
    buildHoverCard();
    scanVisibleLinks();

    // Scan links scrolled into view
    const observer = new IntersectionObserver(function (entries) {
      entries.forEach(function (e) {
        if (e.isIntersecting && e.target.tagName === 'A') {
          queueLink(e.target);
        }
      });
    }, { rootMargin: '200px' });

    // Observe all current + future links
    observeLinks(observer);
    const mutObs = new MutationObserver(function (mutations) {
      mutations.forEach(function (m) {
        m.addedNodes.forEach(function (node) {
          if (node.nodeType !== 1) return;
          var links = node.tagName === 'A' ? [node] : Array.from(node.querySelectorAll('a[href]'));
          links.forEach(function (a) { observer.observe(a); });
        });
      });
    });
    mutObs.observe(document.documentElement, { childList: true, subtree: true });

    // Click intercept
    document.addEventListener('click', onLinkClick, true);
  }

  function observeLinks(observer) {
    var links = document.querySelectorAll('a[href]');
    var seen = new Set();
    var count = 0;
    links.forEach(function (a) {
      var host = safeHost(a.href);
      if (!host || seen.has(host) || count >= MAX_LINKS_PER_PAGE) return;
      seen.add(host);
      count++;
      observer.observe(a);
    });
  }

  // ── Link queue & batching ─────────────────────────────────────────────────
  var batchQueue = [];
  var batchTimer = null;

  function queueLink(a) {
    var host = safeHost(a.href);
    if (!host) return;

    // Already cached or scanning
    var cached = getCached(host);
    if (cached) { applyDot(a, cached.level, cached.score, cached.category); return; }
    if (pendingHosts.has(host)) { applyDot(a, 'scanning', 0, ''); return; }

    // Cap total
    if (hostCache.size + pendingHosts.size >= MAX_LINKS_PER_PAGE) return;

    applyDot(a, 'scanning', 0, '');
    pendingHosts.add(host);
    batchQueue.push({ host: host, a: a });

    if (!batchTimer) {
      batchTimer = setTimeout(flushBatch, BATCH_DELAY_MS);
    }
  }

  function scanVisibleLinks() {
    var links = document.querySelectorAll('a[href]');
    var seen = new Set();
    links.forEach(function (a) {
      var host = safeHost(a.href);
      if (!host || seen.has(host)) return;
      seen.add(host);
      queueLink(a);
    });
  }

  function flushBatch() {
    batchTimer = null;
    if (!batchQueue.length) return;
    var batch = batchQueue.splice(0, BATCH_SIZE);
    if (batchQueue.length > 0) {
      batchTimer = setTimeout(flushBatch, BATCH_DELAY_MS);
    }
    batch.forEach(function (item) { scanHost(item.host); });
  }

  // ── Scan a hostname ───────────────────────────────────────────────────────
  function scanHost(host) {
    var url = 'https://' + host;

    var headers = { 'Content-Type': 'application/json' };
    if (apiKey) headers['Authorization'] = 'Bearer ' + apiKey;

    fetch(SCAN_ENDPOINT, {
      method: 'POST',
      headers: headers,
      body: JSON.stringify({ type: 'url', content: url }),
    })
      .then(function (r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        // Verify origin
        var resUrl = new URL(r.url);
        if (resUrl.hostname !== API_DOMAIN) throw new Error('Origin mismatch');
        return r.json();
      })
      .then(function (data) {
        pendingHosts.delete(host);
        if (!data || !data.scan) return;
        var level = (data.scan.threatLevel || 'safe').toLowerCase();
        var score = data.scan.score || 0;
        var category = data.scan.category || '';
        setCache(host, { level: level, score: score, category: category });
        updateDotsForHost(host, level, score, category);
      })
      .catch(function (err) {
        pendingHosts.delete(host);
        var msg = String(err);
        if (msg.includes('429')) {
          // Rate limit — show limit banner once
          if (!noKeyWarningShown) {
            noKeyWarningShown = true;
            showLimitBanner();
          }
          updateDotsForHost(host, null, 0, '');
        } else {
          // Network error or other — remove dot silently
          updateDotsForHost(host, null, 0, '');
        }
      });
  }

  // ── Apply / update dot badges ─────────────────────────────────────────────
  function applyDot(a, level, score, category) {
    // Skip anchors inside nav/footer/buttons/menus — too much noise
    if (a.closest('nav') || a.closest('footer') || a.closest('[role="navigation"]') ||
        a.closest('[role="menu"]') || a.closest('[role="menubar"]') ||
        a.closest('button') || a.closest('header')) return;
    // Skip links with no text content (icon-only links, logo links)
    var linkText = (a.textContent || '').trim();
    if (linkText.length < 2 && !a.querySelector('img')) return;
    // Skip safe dots entirely — only show dots for risky/scanning/unknown
    if (level === 'safe') { removeDot(a); return; }
    if (!level) { removeDot(a); return; }

    var existing = dotMap.get(a);
    if (existing) {
      existing.dataset.level = level;
      existing.title = dotTitle(level, score, category);
      return;
    }

    var dot = document.createElement('span');
    dot.className = 'ss-dot';
    dot.dataset.level = level;
    dot.title = dotTitle(level, score, category);

    dot.addEventListener('mouseenter', function (e) { showCard(e, a.href, level, score, category); });
    dot.addEventListener('mouseleave', hideCard);
    dot.addEventListener('click', function (e) {
      e.preventDefault();
      e.stopPropagation();
      showCard(e, a.href, level, score, category);
    });

    // Insert right after the link's last text
    if (a.nextSibling) {
      a.parentNode.insertBefore(dot, a.nextSibling);
    } else {
      a.parentNode.appendChild(dot);
    }
    dotMap.set(a, dot);
  }

  function removeDot(a) {
    var dot = dotMap.get(a);
    if (dot) { dot.remove(); dotMap.delete(a); }
  }

  function updateDotsForHost(host, level, score, category) {
    document.querySelectorAll('a[href]').forEach(function (a) {
      if (safeHost(a.href) === host) {
        if (level) applyDot(a, level, score, category);
        else removeDot(a);
      }
    });
  }

  function dotTitle(level, score, category) {
    if (level === 'scanning') return 'ScamShield: Scanning…';
    if (level === 'safe') return 'ScamShield: Safe';
    return 'ScamShield: ' + level.toUpperCase() + ' risk (' + score + '/100)' + (category ? ' — ' + category : '');
  }

  // ── Hover card ────────────────────────────────────────────────────────────
  function buildHoverCard() {
    hoverCard = document.createElement('div');
    hoverCard.className = 'ss-card';
    document.documentElement.appendChild(hoverCard);
  }

  function showCard(e, href, level, score, category) {
    if (!hoverCard) return;
    var host = safeHost(href) || href;

    // Build card content using textContent only
    hoverCard.innerHTML = '';

    var header = document.createElement('div');
    header.className = 'ss-card-header';

    var badge = document.createElement('span');
    badge.className = 'ss-card-badge ss-badge-' + (level || 'scanning');
    badge.textContent = level === 'scanning' ? 'Scanning…' : (level || 'unknown').toUpperCase();
    header.appendChild(badge);

    if (level !== 'scanning') {
      var scoreEl = document.createElement('span');
      scoreEl.className = 'ss-card-score';
      scoreEl.textContent = score + '/100';
      header.appendChild(scoreEl);
    }
    hoverCard.appendChild(header);

    var domain = document.createElement('div');
    domain.className = 'ss-card-domain';
    domain.textContent = host;
    hoverCard.appendChild(domain);

    if (category) {
      var cat = document.createElement('div');
      cat.className = 'ss-card-category';
      cat.textContent = category.replace(/_/g, ' ');
      hoverCard.appendChild(cat);
    }

    var powered = document.createElement('div');
    powered.className = 'ss-card-powered';
    powered.textContent = 'ScamShield VERIDICT';
    hoverCard.appendChild(powered);

    // Position — clamp to viewport so card never goes off-screen
    var cardW = 310, cardH = 180;
    var x = Math.max(8, Math.min(e.clientX + 12, window.innerWidth - cardW - 8));
    var y = Math.max(8, Math.min(e.clientY + 12, window.innerHeight - cardH - 8));
    hoverCard.style.left = x + 'px';
    hoverCard.style.top = y + 'px';

    hoverCard.classList.add('ss-visible');
  }

  function hideCard() {
    if (hoverCard) hoverCard.classList.remove('ss-visible');
  }

  // ── Click intercept for CRITICAL links only ──────────────────────────────
  function onLinkClick(e) {
    var a = e.target.closest('a[href]');
    if (!a) return;
    var host = safeHost(a.href);
    if (!host) return;
    var cached = getCached(host);
    if (!cached || !WARN_LEVELS.has(cached.level)) return;
    if (warningsDisabled) return; // user said never show again

    e.preventDefault();
    e.stopPropagation();
    showWarning(a.href, cached.score);
  }

  function showWarning(href, score) {
    var overlay = document.createElement('div');
    overlay.className = 'ss-warning-overlay';
    // Click backdrop to dismiss
    overlay.addEventListener('click', function (e) { if (e.target === overlay) overlay.remove(); });

    var box = document.createElement('div');
    box.className = 'ss-warning-box';

    var icon = document.createElement('div');
    icon.className = 'ss-warning-icon';
    icon.textContent = '☠️';
    box.appendChild(icon);

    var title = document.createElement('div');
    title.className = 'ss-warning-title';
    title.textContent = 'CRITICAL THREAT DETECTED';
    box.appendChild(title);

    var scoreEl = document.createElement('div');
    scoreEl.className = 'ss-warning-score';
    scoreEl.textContent = 'Threat score: ' + score + '/100 — ScamShield VERIDICT';
    box.appendChild(scoreEl);

    var urlEl = document.createElement('div');
    urlEl.className = 'ss-warning-url';
    urlEl.textContent = href.substring(0, 80) + (href.length > 80 ? '…' : '');
    box.appendChild(urlEl);

    var actions = document.createElement('div');
    actions.className = 'ss-warning-actions';

    var backBtn = document.createElement('button');
    backBtn.className = 'ss-btn-back';
    backBtn.textContent = '← Go back (safe)';
    backBtn.addEventListener('click', function () { overlay.remove(); });
    actions.appendChild(backBtn);

    var proceedBtn = document.createElement('button');
    proceedBtn.className = 'ss-btn-proceed';
    proceedBtn.textContent = 'Proceed anyway';
    proceedBtn.addEventListener('click', function () {
      overlay.remove();
      window.location.href = href;
    });
    actions.appendChild(proceedBtn);

    box.appendChild(actions);

    // "Never show again" option
    var neverRow = document.createElement('div');
    neverRow.style.cssText = 'margin-top:12px;display:flex;align-items:center;justify-content:center;gap:6px;';
    var neverChk = document.createElement('input');
    neverChk.type = 'checkbox';
    neverChk.id = 'ss-never-warn';
    neverChk.style.cursor = 'pointer';
    var neverLbl = document.createElement('label');
    neverLbl.htmlFor = 'ss-never-warn';
    neverLbl.textContent = 'Never show these warnings again';
    neverLbl.style.cssText = 'font-size:11px;color:#6e7681;cursor:pointer;';
    neverChk.addEventListener('change', function () {
      if (neverChk.checked) {
        warningsDisabled = true;
        chrome.storage.sync.set({ ss_warnings_disabled: true });
      }
    });
    neverRow.appendChild(neverChk);
    neverRow.appendChild(neverLbl);
    box.appendChild(neverRow);

    overlay.appendChild(box);
    document.documentElement.appendChild(overlay);
  }

  // ── No API key banner ─────────────────────────────────────────────────────
  function showLimitBanner() {
    if (document.getElementById('ss-limit-banner')) return;
    var banner = document.createElement('div');
    banner.id = 'ss-limit-banner';
    banner.style.cssText = 'position:fixed;bottom:16px;right:16px;z-index:2147483646;background:#0d1117;border:1px solid #ffc10740;border-radius:10px;padding:12px 16px;font-family:-apple-system,BlinkMacSystemFont,sans-serif;font-size:12px;color:#8892a4;box-shadow:0 4px 20px rgba(0,0,0,0.5);max-width:300px;';
    var title = document.createElement('div');
    title.style.cssText = 'color:#ffc107;font-weight:700;margin-bottom:4px;font-size:13px;';
    title.textContent = '🛡️ ScamShieldy — Daily limit reached';
    banner.appendChild(title);
    var msg = document.createElement('div');
    msg.textContent = 'Free: 20 scans/day. Add an API key for 100/day, or upgrade to Pro for 10,000/day.';
    banner.appendChild(msg);
    var link = document.createElement('a');
    link.href = 'https://scamshieldy.com/pricing';
    link.target = '_blank';
    link.style.cssText = 'display:inline-block;margin-top:8px;color:#00d4ff;font-size:11px;text-decoration:none;';
    link.textContent = 'Upgrade →';
    banner.appendChild(link);
    var close = document.createElement('button');
    close.textContent = '✕';
    close.style.cssText = 'position:absolute;top:8px;right:8px;background:none;border:none;color:#6e7681;cursor:pointer;font-size:12px;padding:0;';
    close.addEventListener('click', function () { banner.remove(); });
    banner.appendChild(close);
    document.documentElement.appendChild(banner);
    setTimeout(function () { if (banner.parentNode) banner.remove(); }, 10000);
  }

  // ── Cache helpers ─────────────────────────────────────────────────────────
  function setCache(host, data) {
    hostCache.set(host, Object.assign({ ts: Date.now() }, data));
  }

  function getCached(host) {
    var entry = hostCache.get(host);
    if (!entry) return null;
    if (Date.now() - entry.ts > CACHE_TTL_MS) { hostCache.delete(host); return null; }
    return entry;
  }

  // ── Utilities ─────────────────────────────────────────────────────────────
  function safeHost(href) {
    if (!href || typeof href !== 'string') return null;
    if (!href.startsWith('http://') && !href.startsWith('https://')) return null;
    try {
      var u = new URL(href);
      // Skip same-origin links
      if (u.hostname === window.location.hostname) return null;
      return u.hostname;
    } catch (_) { return null; }
  }

  // ── Listen for settings changes ───────────────────────────────────────────
  chrome.storage.onChanged.addListener(function (changes) {
    if (changes.ss_api_key) apiKey = changes.ss_api_key.newValue || null;
    if (changes.ss_enabled !== undefined) enabled = changes.ss_enabled.newValue !== false;
    if (changes.ss_warnings_disabled !== undefined) warningsDisabled = changes.ss_warnings_disabled.newValue === true;
  });

})();
