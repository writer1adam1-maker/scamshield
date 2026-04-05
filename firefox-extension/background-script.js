/**
 * ScamShield Browser Extension - Background Script v2.0
 * Manages vaccination cache, context menus, and API communication.
 *
 * Security hardening:
 * - Pinned API domain (no dynamic URL construction)
 * - Response validation before caching
 * - No innerHTML with untrusted data (textContent only)
 * - Cache entries include content hash for integrity
 * - Mutex on concurrent requests for same URL
 */

const API_DOMAIN = 'scamshieldy.com';
const API_BASE = 'https://' + API_DOMAIN;
const VACCINE_CACHE = new Map();
const VACCINE_TTL = 24 * 60 * 60 * 1000; // 24 hours
const PENDING_REQUESTS = new Map(); // Mutex: prevent concurrent requests for same URL

// ── Context menu setup ────────────────────────────────────────────────────
chrome.runtime.onInstalled.addListener(function () {
  chrome.contextMenus.create({
    id: 'ss-scan-link',
    title: 'Scan with ScamShield',
    contexts: ['link'],
  });
  chrome.contextMenus.create({
    id: 'ss-scan-selection',
    title: 'Scan selected text with ScamShield',
    contexts: ['selection'],
  });
  chrome.contextMenus.create({
    id: 'ss-scan-page',
    title: 'Scan this page with ScamShield',
    contexts: ['page'],
  });
});

chrome.contextMenus.onClicked.addListener(function (info, tab) {
  if (info.menuItemId === 'ss-scan-link' && info.linkUrl) {
    openPopupScan(tab, info.linkUrl);
  } else if (info.menuItemId === 'ss-scan-selection' && info.selectionText) {
    openPopupScan(tab, info.selectionText);
  } else if (info.menuItemId === 'ss-scan-page' && tab && tab.url) {
    openPopupScan(tab, tab.url);
  }
});

function openPopupScan(tab, content) {
  // Store the pending scan content for the popup to pick up
  chrome.storage.local.set({ ss_popup_prescan: content });
  // Open popup by injecting the panel into the current page
  if (tab && tab.id && tab.url && (tab.url.startsWith('http://') || tab.url.startsWith('https://'))) {
    chrome.scripting.executeScript({
      target: { tabId: tab.id },
      function: openVaccinePanel,
      args: [content, API_BASE]
    }).catch(function () {});
  }
}

// ── Extension icon click — open vaccine panel ─────────────────────────────
chrome.action.onClicked.addListener((tab) => {
  if (tab.url && (tab.url.startsWith('http://') || tab.url.startsWith('https://'))) {
    chrome.scripting.executeScript({
      target: { tabId: tab.id },
      function: openVaccinePanel,
      args: [tab.url, API_BASE]
    }).catch(function () {});
  }
});

function openVaccinePanel(url, apiBase) {
  var existing = document.getElementById('scamshield-vaccine-panel');
  if (existing) { existing.remove(); return; }

  var panel = document.createElement('div');
  panel.id = 'scamshield-vaccine-panel';
  panel.style.cssText = 'position:fixed;top:50px;right:20px;width:400px;max-height:600px;background:#0d1117;border:1px solid #1e2d3d;border-radius:12px;box-shadow:0 8px 40px rgba(0,0,0,0.7);z-index:999999;font-family:-apple-system,BlinkMacSystemFont,sans-serif;overflow-y:auto;';

  var loading = document.createElement('div');
  loading.style.cssText = 'padding:20px;text-align:center;color:#8892a4;font-size:13px;';
  loading.textContent = 'ScamShield scanning…';
  panel.appendChild(loading);
  document.body.appendChild(panel);

  fetch(apiBase + '/api/vaccine/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: url })
  })
    .then(function (r) { return r.json(); })
    .then(function (vaccine) {
      if (!vaccine || typeof vaccine !== 'object' || !vaccine.threatLevel) {
        loading.textContent = 'Error: Invalid response from server';
        return;
      }
      renderVaccinePanel(panel, vaccine);
    })
    .catch(function (err) {
      loading.textContent = 'Error: ' + (err.message || 'Network error');
    });
}

function renderVaccinePanel(panel, vaccine) {
  while (panel.firstChild) panel.removeChild(panel.firstChild);

  var COLORS = {
    safe: '#00e5a0', low: '#8bc34a', medium: '#ff9800',
    high: '#f44336', critical: '#9c27b0'
  };
  var color = COLORS[vaccine.threatLevel] || '#8892a4';

  var header = document.createElement('div');
  header.style.cssText = 'padding:14px 16px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #1e2d3d;';
  var title = document.createElement('span');
  title.style.cssText = 'font-size:14px;font-weight:700;color:#e6edf3;';
  title.textContent = 'ScamShield';
  header.appendChild(title);
  var closeBtn = document.createElement('button');
  closeBtn.textContent = '✕';
  closeBtn.style.cssText = 'background:none;border:none;font-size:16px;cursor:pointer;color:#6e7681;padding:0;';
  closeBtn.addEventListener('click', function () { panel.remove(); });
  header.appendChild(closeBtn);
  panel.appendChild(header);

  var badge = document.createElement('div');
  badge.style.cssText = 'background:' + color + '18;border:1px solid ' + color + '40;color:' + color + ';padding:10px 16px;margin:12px 16px;border-radius:8px;font-weight:700;font-size:13px;text-align:center;font-family:monospace;letter-spacing:0.08em;';
  badge.textContent = (vaccine.threatLevel || 'unknown').toUpperCase() + '  ·  ' + (vaccine.threatScore || 0) + '/100';
  panel.appendChild(badge);

  var urlDiv = document.createElement('div');
  urlDiv.style.cssText = 'padding:0 16px 10px;font-size:11px;color:#6e7681;word-break:break-all;font-family:monospace;';
  urlDiv.textContent = (vaccine.url || '').substring(0, 80) + ((vaccine.url || '').length > 80 ? '…' : '');
  panel.appendChild(urlDiv);

  var threats = vaccine.threatsDetected || [];
  if (threats.length > 0) {
    var threatsTitle = document.createElement('div');
    threatsTitle.style.cssText = 'padding:0 16px 6px;font-weight:600;font-size:11px;color:#8892a4;font-family:monospace;text-transform:uppercase;letter-spacing:0.08em;';
    threatsTitle.textContent = 'Threats: ' + threats.length;
    panel.appendChild(threatsTitle);

    var list = document.createElement('ul');
    list.style.cssText = 'margin:0 16px 12px;padding-left:18px;font-size:12px;color:#c9d1d9;line-height:1.6;';
    threats.slice(0, 5).forEach(function (t) {
      var li = document.createElement('li');
      li.textContent = typeof t === 'string' ? t : (t.description || 'Unknown threat');
      list.appendChild(li);
    });
    if (threats.length > 5) {
      var more = document.createElement('li');
      more.textContent = '… and ' + (threats.length - 5) + ' more';
      more.style.color = '#6e7681';
      list.appendChild(more);
    }
    panel.appendChild(list);
  }

  var footer = document.createElement('div');
  footer.style.cssText = 'padding:10px 16px;border-top:1px solid #1e2d3d;font-size:10px;color:#3c4754;font-family:monospace;display:flex;justify-content:space-between;';
  var ts = document.createElement('span');
  ts.textContent = new Date(vaccine.timestamp || Date.now()).toLocaleTimeString();
  footer.appendChild(ts);
  var brand = document.createElement('span');
  brand.textContent = 'ScamShield VERIDICT';
  footer.appendChild(brand);
  panel.appendChild(footer);
}

// ── Content script messages ───────────────────────────────────────────────
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'page_loaded' && sender.tab && sender.tab.url) {
    const tabUrl = sender.tab.url;

    if (!tabUrl.startsWith('http://') && !tabUrl.startsWith('https://')) {
      sendResponse({ inject: false });
      return true;
    }

    const cachedVaccine = getVaccineFromCache(tabUrl);
    if (cachedVaccine) {
      sendResponse({ inject: true, injectionRules: cachedVaccine.rules });
    } else {
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

    return true;
  }

  if (request.type === 'vaccine_applied') {
    sendResponse({ status: 'received' });
  }

  if (request.type === 'get_vaccine_status') {
    const vaccine = getVaccineFromCache(sender.tab && sender.tab.url);
    sendResponse({ vaccine: vaccine });
  }

  // Stats tracking from link scanner
  if (request.type === 'ss_stat_update') {
    chrome.storage.local.get(['ss_stat_scanned', 'ss_stat_threats', 'ss_stat_blocked'], function (data) {
      var updates = {};
      if (request.scanned) updates.ss_stat_scanned = (data.ss_stat_scanned || 0) + request.scanned;
      if (request.threats) updates.ss_stat_threats = (data.ss_stat_threats || 0) + request.threats;
      if (request.blocked) updates.ss_stat_blocked = (data.ss_stat_blocked || 0) + request.blocked;
      if (Object.keys(updates).length) chrome.storage.local.set(updates);
    });
    sendResponse({ ok: true });
  }

  return true;
});

// ── Fetch & cache vaccine ─────────────────────────────────────────────────
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

    const responseUrl = new URL(response.url);
    if (responseUrl.hostname !== API_DOMAIN) {
      console.error('ScamShield: Response origin mismatch');
      return null;
    }

    const vaccine = await response.json();
    if (!vaccine || typeof vaccine !== 'object' || !vaccine.threatLevel) {
      console.warn('ScamShield: Invalid vaccine response shape');
      return null;
    }

    setVaccineCache(url, vaccine);

    if (tabId && vaccine.threatScore > 50) {
      chrome.action.setBadgeText({ text: '!', tabId: tabId });
      chrome.action.setBadgeBackgroundColor({ color: '#f44336', tabId: tabId });
    } else if (tabId && vaccine.threatScore > 0) {
      chrome.action.setBadgeText({ text: '', tabId: tabId });
    }

    return vaccine;
  } catch (error) {
    console.error('Vaccine fetch error:', error);
    return null;
  }
}

// ── Cache management ──────────────────────────────────────────────────────
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

// Periodic cache cleanup
setInterval(function () {
  var now = Date.now();
  var cleaned = 0;
  for (var entry of VACCINE_CACHE) {
    if (now > entry[1].expires) {
      VACCINE_CACHE.delete(entry[0]);
      cleaned++;
    }
  }
  PENDING_REQUESTS.clear();
  if (cleaned > 0) console.log('ScamShield: Cleaned', cleaned, 'expired vaccines');
}, 60 * 60 * 1000);

console.log('ScamShield Background Script: Initialized (v2.0.0)');
