// ScamShield Browser Extension — popup.js
// Calls the ScamShield API and renders the result

const API_URL = "https://scamshield-green.vercel.app/api/scan";
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

  // WHOIS/SSL + IP meta badges
  metaRow.innerHTML = "";
  if (data.whoisSsl) {
    const w = data.whoisSsl;

    // Domain age badge
    if (w.domainAge !== null) {
      const age = w.domainAge;
      let cls = "badge-ok";
      let label = `${age}d old`;
      if (age < 7)   { cls = "badge-bad";  label = `${age}d old ⚠`; }
      else if (age < 90) { cls = "badge-warn"; label = `${age}d old`; }
      metaRow.insertAdjacentHTML("beforeend", `<span class="meta-badge ${cls}">Domain: ${label}</span>`);
    } else {
      metaRow.insertAdjacentHTML("beforeend", `<span class="meta-badge badge-gray">Domain age: unknown</span>`);
    }

    // SSL badge
    if (w.sslValid === true) {
      metaRow.insertAdjacentHTML("beforeend", `<span class="meta-badge badge-ok">SSL: valid ✓</span>`);
    } else if (w.sslValid === false) {
      metaRow.insertAdjacentHTML("beforeend", `<span class="meta-badge badge-bad">SSL: invalid ✗</span>`);
    } else {
      metaRow.insertAdjacentHTML("beforeend", `<span class="meta-badge badge-gray">SSL: unknown</span>`);
    }

    // Registrar
    if (w.registrar) {
      metaRow.insertAdjacentHTML("beforeend", `<span class="meta-badge badge-gray">${w.registrar.substring(0, 22)}</span>`);
    }
  }

  // IP Intelligence badges
  if (data.ipIntelligence) {
    const ip = data.ipIntelligence;

    // Country risk badge
    const countryRiskMap = { critical: "badge-bad", high: "badge-bad", medium: "badge-warn", low: "badge-ok" };
    const countryCls = countryRiskMap[ip.countryRiskLevel] || "badge-gray";
    const countryLabel = ip.city
      ? `${ip.countryCode} · ${ip.city.substring(0, 14)}`
      : ip.countryCode;
    metaRow.insertAdjacentHTML("beforeend", `<span class="meta-badge ${countryCls}">📍 ${countryLabel}</span>`);

    // Hosting type badge
    const hostingLabelMap = {
      tor:       { cls: "badge-bad",  label: "🚨 TOR node" },
      vpn_proxy: { cls: "badge-bad",  label: "🛡 VPN/Proxy" },
      vps:       { cls: "badge-warn", label: "🖥 VPS hosting" },
      cloud:     { cls: "badge-warn", label: "☁ Cloud hosted" },
      residential: { cls: "badge-ok", label: "🏠 Residential" },
      unknown:   { cls: "badge-gray", label: "Host: unknown" },
    };
    const h = hostingLabelMap[ip.hostingCategory] || hostingLabelMap.unknown;
    metaRow.insertAdjacentHTML("beforeend", `<span class="meta-badge ${h.cls}">${h.label}</span>`);

    // IP address badge (greyed)
    metaRow.insertAdjacentHTML("beforeend", `<span class="meta-badge badge-gray">${ip.ip}</span>`);
  }

  // Evidence
  evidenceList.innerHTML = "";
  const evidence = (data.evidence || []).slice(0, MAX_EVIDENCE);
  for (const ev of evidence) {
    const sev = (ev.severity || "low").toLowerCase();
    const dotClass = ["critical", "high", "medium", "low"].includes(sev) ? `dot-${sev}` : "dot-low";
    const li = document.createElement("li");
    li.className = "evidence-item";
    li.innerHTML = `<span class="dot ${dotClass}"></span><span>${ev.finding}</span>`;
    evidenceList.appendChild(li);
  }
  if (evidence.length === 0) {
    evidenceList.innerHTML = `<li class="evidence-item"><span class="dot dot-low"></span><span>No suspicious signals detected</span></li>`;
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

// ── Auto-fill current tab URL on open ─────────────────────────────────────────
document.addEventListener("DOMContentLoaded", () => {
  if (typeof chrome !== "undefined" && chrome.tabs) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url || "";
      if (url && /^https?:\/\//i.test(url)) {
        inputField.value = url;
      }
    });
  }
});
