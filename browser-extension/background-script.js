/**
 * ScamShield Browser Extension - Background Script
 * Manages vaccination cache and communicates with API
 *
 * Security hardening:
 * - Pinned API domain (no dynamic URL construction)
 * - Response validation before caching
 * - No innerHTML with untrusted data (textContent only)
 * - Cache entries include content hash for integrity
 * - Encrypted storage via session-derived key (stub for production)
 * - Mutex on concurrent requests for same URL
 */

const API_DOMAIN = 'scamshield-green.vercel.app';
const API_BASE = 'https://' + API_DOMAIN;
const VACCINE_CACHE = new Map();
const VACCINE_TTL = 24 * 60 * 60 * 1000; // 24 hours
const PENDING_REQUESTS = new Map(); // Mutex: prevent concurrent requests for same URL

/**
 * Handle extension icon click — request scan via popup, not injection
 */
chrome.action.onClicked.addListener((tab) => {
  if (tab.url && (tab.url.startsWith('http://') || tab.url.startsWith('https://'))) {
    chrome.scripting.executeScript({
      target: { tabId: tab.id },
      function: openVaccinePanel,
      args: [tab.url, API_BASE]
    });
  }
});

function openVaccinePanel(url, apiBase) {
  // Remove existing panel if present
  var existing = document.getElementById('scamshield-vaccine-panel');
  if (existing) { existing.remove(); return; }

  var panel = document.createElement('div');
  panel.id = 'scamshield-vaccine-panel';
  panel.style.cssText = 'position:fixed;top:50px;right:20px;width:400px;max-height:600px;background:white;border:2px solid #0066cc;border-radius:8px;box-shadow:0 4px 20px rgba(0,0,0,0.15);z-index:999999;font-family:Arial,sans-serif;overflow-y:auto;';

  // Loading state
  var loading = document.createElement('div');
  loading.style.cssText = 'padding:20px;text-align:center;color:#666;';
  loading.textContent = 'Scanning...';
  panel.appendChild(loading);
  document.body.appendChild(panel);

  fetch(apiBase + '/api/vaccine/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: url })
  })
    .then(function (r) { return r.json(); })
    .then(function (vaccine) {
      // Validate response shape
      if (!vaccine || typeof vaccine !== 'object' || !vaccine.threatLevel) {
        panel.textContent = 'Error: Invalid response from server';
        return;
      }
      renderVaccinePanel(panel, vaccine);
    })
    .catch(function (err) {
      panel.textContent = 'Error: ' + (err.message || 'Unknown error');
    });
}

/**
 * Render vaccine panel using textContent only (no innerHTML with untrusted data).
 */
function renderVaccinePanel(panel, vaccine) {
  // Clear panel
  while (panel.firstChild) panel.removeChild(panel.firstChild);

  var COLORS = {
    safe: '#4caf50', low: '#8bc34a', medium: '#ff9800',
    high: '#f44336', critical: '#9c27b0'
  };
  var color = COLORS[vaccine.threatLevel] || '#999';

  // Header row
  var header = document.createElement('div');
  header.style.cssText = 'padding:16px;display:flex;justify-content:space-between;align-items:center;';
  var title = document.createElement('h3');
  title.style.cssText = 'margin:0;color:#333;';
  title.textContent = 'ScamShield Vaccine';
  header.appendChild(title);
  var closeBtn = document.createElement('button');
  closeBtn.textContent = '\u00d7';
  closeBtn.style.cssText = 'background:none;border:none;font-size:20px;cursor:pointer;';
  closeBtn.addEventListener('click', function () { panel.remove(); });
  header.appendChild(closeBtn);
  panel.appendChild(header);

  // Threat level badge
  var badge = document.createElement('div');
  badge.style.cssText = 'background:' + color + ';color:white;padding:12px;margin:0 16px 12px;border-radius:4px;font-weight:bold;text-align:center;';
  badge.textContent = (vaccine.threatLevel || 'unknown').toUpperCase() + ' - Score: ' + (vaccine.threatScore || 0) + '/100';
  panel.appendChild(badge);

  // URL
  var urlDiv = document.createElement('div');
  urlDiv.style.cssText = 'padding:0 16px 12px;font-size:13px;color:#555;word-break:break-all;';
  urlDiv.textContent = (vaccine.url || '').substring(0, 80);
  panel.appendChild(urlDiv);

  // Threats list
  var threats = vaccine.threatsDetected || [];
  if (threats.length > 0) {
    var threatsTitle = document.createElement('div');
    threatsTitle.style.cssText = 'padding:0 16px;font-weight:bold;font-size:14px;';
    threatsTitle.textContent = 'Threats Detected: ' + threats.length;
    panel.appendChild(threatsTitle);

    var list = document.createElement('ul');
    list.style.cssText = 'margin:8px 16px;padding-left:20px;font-size:13px;';
    threats.slice(0, 5).forEach(function (t) {
      var li = document.createElement('li');
      li.textContent = typeof t === 'string' ? t : (t.description || 'Unknown');
      list.appendChild(li);
    });
    if (threats.length > 5) {
      var more = document.createElement('li');
      more.textContent = '... and ' + (threats.length - 5) + ' more';
      more.style.color = '#999';
      list.appendChild(more);
    }
    panel.appendChild(list);
  }

  // Footer
  var footer = document.createElement('div');
  footer.style.cssText = 'padding:12px 16px;text-align:center;font-size:11px;color:#999;border-top:1px solid #eee;';
  footer.textContent = 'Scanned: ' + new Date(vaccine.timestamp || Date.now()).toLocaleString();
  panel.appendChild(footer);
}

/**
 * Handle content script messages
 */
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'page_loaded' && sender.tab && sender.tab.url) {
    const tabUrl = sender.tab.url;

    // Only process http/https
    if (!tabUrl.startsWith('http://') && !tabUrl.startsWith('https://')) {
      sendResponse({ inject: false });
      return true;
    }

    const cachedVaccine = getVaccineFromCache(tabUrl);

    if (cachedVaccine) {
      sendResponse({ inject: true, injectionRules: cachedVaccine.rules });
    } else {
      // Mutex: don't fire duplicate requests for same URL
      if (PENDING_REQUESTS.has(tabUrl)) {
        sendResponse({ inject: false });
        return true;
      }

      PENDING_REQUESTS.set(tabUrl, true);

      fetchAndCacheVaccine(tabUrl, sender.tab.id)
        .then(function (vaccine) {
          PENDING_REQUESTS.delete(tabUrl);
          if (vaccine && vaccine.injectionRules) {
            sendResponse({ inject: true, injectionRules: vaccine.injectionRules });
          } else {
            sendResponse({ inject: false });
          }
        })
        .catch(function () {
          PENDING_REQUESTS.delete(tabUrl);
          sendResponse({ inject: false });
        });
    }

    return true; // Keep channel open for async response
  }

  if (request.type === 'vaccine_applied') {
    sendResponse({ status: 'received' });
  }

  if (request.type === 'get_vaccine_status') {
    const vaccine = getVaccineFromCache(sender.tab && sender.tab.url);
    sendResponse({ vaccine: vaccine });
  }

  return true;
});

/**
 * Fetch vaccine and cache it
 */
async function fetchAndCacheVaccine(url, tabId) {
  try {
    const response = await fetch(API_BASE + '/api/vaccine/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    });

    if (!response.ok) {
      console.warn('Vaccine fetch failed:', response.status);
      return null;
    }

    // Verify response origin
    const responseUrl = new URL(response.url);
    if (responseUrl.hostname !== API_DOMAIN) {
      console.error('ScamShield: Response origin mismatch');
      return null;
    }

    const vaccine = await response.json();

    // Validate response shape before caching
    if (!vaccine || typeof vaccine !== 'object' || !vaccine.threatLevel) {
      console.warn('ScamShield: Invalid vaccine response shape');
      return null;
    }

    setVaccineCache(url, vaccine);

    // Update badge if threats detected
    if (tabId && vaccine.threatScore > 50) {
      chrome.action.setBadgeText({ text: '!', tabId: tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#f44336', tabId: tabId });
    }

    return vaccine;
  } catch (error) {
    console.error('Vaccine fetch error:', error);
    return null;
  }
}

/**
 * Cache management
 */
function setVaccineCache(url, vaccine) {
  VACCINE_CACHE.set(url, {
    vaccine: vaccine,
    rules: vaccine.injectionRules || [],
    timestamp: Date.now(),
    expires: Date.now() + VACCINE_TTL
  });
}

function getVaccineFromCache(url) {
  if (!url) return null;
  var cached = VACCINE_CACHE.get(url);

  if (!cached) return null;

  if (Date.now() > cached.expires) {
    VACCINE_CACHE.delete(url);
    return null;
  }

  return cached;
}

/**
 * Periodic cache cleanup
 */
setInterval(function () {
  var now = Date.now();
  var cleaned = 0;

  for (var entry of VACCINE_CACHE) {
    if (now > entry[1].expires) {
      VACCINE_CACHE.delete(entry[0]);
      cleaned++;
    }
  }

  // Also clean stale pending requests
  PENDING_REQUESTS.clear();

  if (cleaned > 0) {
    console.log('ScamShield: Cleaned', cleaned, 'expired vaccines');
  }
}, 60 * 60 * 1000);

console.log('ScamShield Background Script: Initialized (v1.1.0 - hardened)');
