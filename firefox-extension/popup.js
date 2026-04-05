// ScamShield Browser Extension — popup.js
// Calls the ScamShield API and renders the result

const API_URL = "https://scamshieldy.com/api/scan";
const MAX_EVIDENCE = 6;

// ── DOM refs ──────────────────────────────────────────────────────────────────
const inputField  = document.getElementById("inputField");
const btnScan     = document.getElementById("btnScan");
const btnCurrent  = document.getElementById("btnCurrent");
const loading     = document.getElementById("loading");
const errorBox    = document.getElementById("errorBox");
const resultDiv   = document.getElementById("result");
const scoreRow    = document.getElementById("scoreRow");
const scoreCircle = document.getElementById("scoreCircle");
const threatLevel = document.getElementById("threatLevel");
const categoryEl  = document.getElementById("category");
const metaRow     = document.getElementById("metaRow");
const evidenceList= document.getElementById("evidenceList");
const ciRow       = document.getElementById("ciRow");
const ciFill      = document.getElementById("ciFill");
const ciVal       = document.getElementById("ciVal");
const procTime    = document.getElementById("procTime");

// ── Helpers ───────────────────────────────────────────────────────────────────
function levelClass(level) {
  return level.toLowerCase().replace("_", "-");
}

function hide(...els) { els.forEach(e => { e.style.display = "none"; }); }
function show(el, display = "block") { el.style.display = display; }

function setError(msg) {
  hide(loading, resultDiv);
  errorBox.textContent = msg;
  show(errorBox);
  btnScan.disabled = false;
}

function detectType(input) {
  const trimmed = input.trim();
  if (/^https?:\/\//i.test(trimmed)) return "url";
  if (/^[a-z0-9-]+\.[a-z]{2,}/i.test(trimmed)) return "url";
  return "text";
}

// ── Scan function ─────────────────────────────────────────────────────────────
async function scan(content) {
  if (!content || !content.trim()) {
    setError("Please enter a URL or text to scan.");
    return;
  }

  hide(errorBox, resultDiv);
  show(loading, "flex");
  btnScan.disabled = true;

  const type = detectType(content);

  try {
    const res = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ type, content: content.trim() }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `API error ${res.status}`);
    }

    const data = await res.json();
    hide(loading);
    renderResult(data);
  } catch (err) {
    setError(err.message || "Failed to reach ScamShield API. Check your connection.");
  } finally {
    btnScan.disabled = false;
  }
}

// ── Render result ─────────────────────────────────────────────────────────────
function renderResult(data) {
  const lvl   = (data.threatLevel || "SAFE").toLowerCase();
  const score = data.score ?? 0;
  const cat   = (data.category || "GENERIC").replace(/_/g, " ");

  // Score circle & row
  scoreCircle.textContent = score;
  scoreCircle.className   = `score-circle color-${lvl}`;
  scoreRow.className      = `score-row level-${lvl}`;
  threatLevel.textContent = data.threatLevel || "SAFE";
  threatLevel.className   = `threat-level color-${lvl}`;
  categoryEl.textContent  = cat;

  // Safe helper: create a badge span using textContent only (no innerHTML with untrusted data)
  function makeBadge(cls, text) {
    const span = document.createElement("span");
    span.className = "meta-badge " + cls;
    span.textContent = text;
    return span;
  }

  // WHOIS/SSL + IP meta badges
  while (metaRow.firstChild) metaRow.removeChild(metaRow.firstChild);
  if (data.whoisSsl) {
    const w = data.whoisSsl;

    // Domain age badge
    if (w.domainAge !== null) {
      const age = Number(w.domainAge);
      if (Number.isFinite(age)) {
        let cls = "badge-ok";
        if (age < 7)   cls = "badge-bad";
        else if (age < 90) cls = "badge-warn";
        metaRow.appendChild(makeBadge(cls, "Domain: " + age + "d old" + (age < 7 ? " ⚠" : "")));
      }
    } else {
      metaRow.appendChild(makeBadge("badge-gray", "Domain age: unknown"));
    }

    // SSL badge
    if (w.sslValid === true) {
      metaRow.appendChild(makeBadge("badge-ok", "SSL: valid ✓"));
    } else if (w.sslValid === false) {
      metaRow.appendChild(makeBadge("badge-bad", "SSL: invalid ✗"));
    } else {
      metaRow.appendChild(makeBadge("badge-gray", "SSL: unknown"));
    }

    // Registrar — textContent only, no interpolation
    if (w.registrar && typeof w.registrar === "string") {
      metaRow.appendChild(makeBadge("badge-gray", w.registrar.substring(0, 22)));
    }
  }

  // IP Intelligence badges
  if (data.ipIntelligence) {
    const ip = data.ipIntelligence;

    const countryRiskMap = { critical: "badge-bad", high: "badge-bad", medium: "badge-warn", low: "badge-ok" };
    const countryCls = countryRiskMap[ip.countryRiskLevel] || "badge-gray";
    const countryCode = typeof ip.countryCode === "string" ? ip.countryCode.substring(0, 3) : "??";
    const city = typeof ip.city === "string" ? ip.city.substring(0, 14) : "";
    metaRow.appendChild(makeBadge(countryCls, "📍 " + countryCode + (city ? " · " + city : "")));

    const hostingLabelMap = {
      tor:         { cls: "badge-bad",  label: "🚨 TOR node" },
      vpn_proxy:   { cls: "badge-bad",  label: "🛡 VPN/Proxy" },
      vps:         { cls: "badge-warn", label: "🖥 VPS hosting" },
      cloud:       { cls: "badge-warn", label: "☁ Cloud hosted" },
      residential: { cls: "badge-ok",  label: "🏠 Residential" },
      unknown:     { cls: "badge-gray", label: "Host: unknown" },
    };
    const hKey = String(ip.hostingCategory || "unknown");
    const h = hostingLabelMap[hKey] || hostingLabelMap.unknown;
    metaRow.appendChild(makeBadge(h.cls, h.label));

    if (typeof ip.ip === "string" && /^[\d.:a-f]+$/i.test(ip.ip)) {
      metaRow.appendChild(makeBadge("badge-gray", ip.ip));
    }
  }

  // Evidence — textContent only (XSS fix: was using innerHTML with ev.finding)
  while (evidenceList.firstChild) evidenceList.removeChild(evidenceList.firstChild);
  const evidence = (data.evidence || []).slice(0, MAX_EVIDENCE);
  for (const ev of evidence) {
    const sev = (ev.severity || "low").toLowerCase();
    const dotClass = ["critical", "high", "medium", "low"].includes(sev) ? "dot-" + sev : "dot-low";
    const li = document.createElement("li");
    li.className = "evidence-item";
    const dot = document.createElement("span");
    dot.className = "dot " + dotClass;
    const txt = document.createElement("span");
    txt.textContent = typeof ev.finding === "string" ? ev.finding : "Unknown finding";
    li.appendChild(dot);
    li.appendChild(txt);
    evidenceList.appendChild(li);
  }
  if (evidence.length === 0) {
    const li = document.createElement("li");
    li.className = "evidence-item";
    const dot = document.createElement("span");
    dot.className = "dot dot-low";
    const txt = document.createElement("span");
    txt.textContent = "No suspicious signals detected";
    li.appendChild(dot);
    li.appendChild(txt);
    evidenceList.appendChild(li);
  }

  // Confidence interval
  if (data.confidenceInterval) {
    const ci = data.confidenceInterval;
    const width = Math.max(5, ci.upper - ci.lower);
    const center = (ci.lower + ci.upper) / 2;
    ciFill.style.width = `${Math.min(100, center)}%`;
    ciVal.textContent = `${ci.lower}–${ci.upper}`;
    show(ciRow, "flex");
  } else {
    hide(ciRow);
  }

  // Processing time
  if (data.processingTimeMs) {
    procTime.textContent = `${data.processingTimeMs}ms`;
  }

  show(resultDiv);
}

// ── Event listeners ───────────────────────────────────────────────────────────
btnScan.addEventListener("click", () => scan(inputField.value));

inputField.addEventListener("keydown", (e) => {
  if (e.key === "Enter") scan(inputField.value);
});

btnCurrent.addEventListener("click", () => {
  if (typeof chrome !== "undefined" && chrome.tabs) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url || "";
      if (url) {
        inputField.value = url;
        scan(url);
      } else {
        setError("Cannot access current tab URL.");
      }
    });
  } else {
    setError("Tab access not available.");
  }
});

// ── Settings link ──────────────────────────────────────────────────────────────
var settingsLink = document.getElementById("settingsLink");
if (settingsLink) {
  settingsLink.addEventListener("click", function (e) {
    e.preventDefault();
    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.openOptionsPage) {
      chrome.runtime.openOptionsPage();
    }
  });
}

// ── Auto-fill current tab URL on open ─────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  // Check for pre-scan content from context menu
  if (typeof chrome !== "undefined" && chrome.storage) {
    chrome.storage.session.get('ss_popup_prescan', function (data) {
      if (data.ss_popup_prescan) {
        inputField.value = data.ss_popup_prescan;
        chrome.storage.session.remove('ss_popup_prescan');
        scan(data.ss_popup_prescan);
        return;
      }
    });
  }

  if (typeof chrome !== "undefined" && chrome.tabs) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url || "";
      if (url && /^https?:\/\//i.test(url)) {
        inputField.value = url;
      }
    });
  }
});
