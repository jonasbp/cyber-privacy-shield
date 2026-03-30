/**
 * Privacy Shield - Popup Script
 * Gerencia a interface da extensão
 */

// ============================================================
// Estado local
// ============================================================
let currentData = null;
let currentSettings = null;

// ============================================================
// Inicialização
// ============================================================
document.addEventListener("DOMContentLoaded", async function() {
  setupTabs();
  await loadSettings();
  await refreshData();

  // Atualizar dados periodicamente
  setInterval(refreshData, 3000);
});

// ============================================================
// Tabs
// ============================================================
function setupTabs() {
  const tabs = document.querySelectorAll(".tab-btn");
  tabs.forEach(btn => {
    btn.addEventListener("click", function() {
      tabs.forEach(b => b.classList.remove("active"));
      document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
      this.classList.add("active");
      document.getElementById("tab-" + this.dataset.tab).classList.add("active");
    });
  });
}

// ============================================================
// Carregar dados do background
// ============================================================
async function refreshData() {
  try {
    const data = await browser.runtime.sendMessage({ type: "GET_TAB_DATA" });
    if (data && !data.error) {
      currentData = data;
      renderAll(data);
    }
  } catch (e) {
    console.warn("[Privacy Shield] Erro ao carregar dados:", e);
  }
}

async function loadSettings() {
  try {
    const result = await browser.runtime.sendMessage({ type: "GET_SETTINGS" });
    if (result && result.settings) {
      currentSettings = result.settings;
      applySettingsToUI(result.settings);
    }
    setupSettingsListeners();
  } catch (e) {
    console.warn("[Privacy Shield] Erro ao carregar configurações:", e);
  }
}

// ============================================================
// Renderizar tudo
// ============================================================
function renderAll(data) {
  renderHeader(data);
  renderScore(data);
  renderAlerts(data);
  renderOverview(data);
  renderTrackers(data);
  renderCookies(data);
  renderStorage(data);
}

// ============================================================
// Header
// ============================================================
function renderHeader(data) {
  const domainEl = document.getElementById("current-domain");
  domainEl.textContent = data.hostname || "Página desconhecida";
  domainEl.title = data.url || "";

  const blockingToggle = document.getElementById("toggle-blocking");
  blockingToggle.checked = data.blockingEnabled !== false;
  blockingToggle.onchange = function() {
    sendSettings({ blockingEnabled: this.checked });
  };
}

// ============================================================
// Score
// ============================================================
function renderScore(data) {
  const score = data.privacyScore || 0;
  const rating = data.scoreRating || {};
  const details = data.scoreDetails || [];

  document.getElementById("score-number").textContent = score;
  document.getElementById("score-grade").textContent = rating.grade || "?";
  document.getElementById("score-label").textContent = rating.label || "Calculando";
  document.getElementById("score-label").style.color = rating.color || "#fff";

  // Classe do círculo
  const circle = document.getElementById("score-circle");
  circle.className = "score-circle";
  if (score >= 80) circle.classList.add("excellent");
  else if (score >= 60) circle.classList.add("good");
  else if (score >= 40) circle.classList.add("fair");
  else if (score >= 20) circle.classList.add("poor");
  else circle.classList.add("bad");

  circle.style.borderColor = rating.color || "#4ade80";

  // Detalhes do score
  const detailsEl = document.getElementById("score-details");
  if (details.length > 0) {
    detailsEl.innerHTML = details.slice(0, 3).map(d =>
      `<div class="score-detail-item penalty">${d.icon} ${d.label} (${d.penalty})</div>`
    ).join("");
  } else {
    detailsEl.innerHTML = `<div class="score-detail-item">✅ Nenhuma ameaça detectada</div>`;
  }
}

// ============================================================
// Alertas
// ============================================================
function renderAlerts(data) {
  const hookAlert = document.getElementById("hook-alert");
  const canvasAlert = document.getElementById("canvas-alert");
  const syncAlert = document.getElementById("cookie-sync-alert");

  hookAlert.style.display = data.hookDetected ? "block" : "none";
  canvasAlert.style.display = data.canvasFingerprint ? "block" : "none";
  syncAlert.style.display = data.cookieSyncDetected ? "block" : "none";
}

// ============================================================
// Overview Tab
// ============================================================
function renderOverview(data) {
  document.getElementById("stat-blocked").textContent = data.blockedDomains ? data.blockedDomains.length : 0;
  document.getElementById("stat-trackers").textContent = data.trackerDomains ? data.trackerDomains.length : 0;
  document.getElementById("stat-third-party").textContent = data.thirdPartyDomains ? data.thirdPartyDomains.length : 0;
  document.getElementById("stat-cookies").textContent = data.cookies ? data.cookies.total : 0;

  renderRiskList(data);
  renderRequestsList(data);
}

function renderRiskList(data) {
  const el = document.getElementById("risk-list");
  const items = [];

  // Itens baseados nos dados
  const blockedCount = (data.blockedDomains || []).length;
  const trackerCount = (data.trackerDomains || []).length;
  const thirdPartyCount = (data.thirdPartyDomains || []).length;
  const cookieTotal = data.cookies ? data.cookies.total : 0;
  const tpCookies = data.cookies ? data.cookies.thirdParty.length : 0;

  if (blockedCount > 0) {
    items.push({ level: "high", icon: "🚫", text: `${blockedCount} rastreador(es) bloqueado(s)` });
  }
  if (trackerCount > 0) {
    items.push({ level: "high", icon: "🕵️", text: `${trackerCount} rastreador(es) detectado(s)` });
  }
  if (data.canvasFingerprint) {
    items.push({ level: "high", icon: "🖼️", text: "Canvas Fingerprinting detectado" });
  }
  if (data.hookDetected) {
    items.push({ level: "high", icon: "⚠️", text: "Tentativa de hook/hijacking detectada!" });
  }
  if (tpCookies > 0) {
    items.push({ level: "medium", icon: "🍪", text: `${tpCookies} cookie(s) de terceira parte` });
  }
  if ((data.supercookies || []).length > 0) {
    items.push({ level: "medium", icon: "🦠", text: `${data.supercookies.length} supercookie(s) detectado(s)` });
  }
  if (data.cookieSyncDetected) {
    items.push({ level: "medium", icon: "🔄", text: "Sincronismo de cookies entre rastreadores" });
  }
  if (data.localStorageKeys > 0) {
    items.push({ level: "low", icon: "💾", text: `LocalStorage: ${data.localStorageKeys} chave(s)` });
  }
  if (data.indexedDBUsed) {
    items.push({ level: "low", icon: "🗄️", text: "IndexedDB em uso" });
  }
  if (thirdPartyCount > 0) {
    items.push({ level: "low", icon: "🌐", text: `${thirdPartyCount} domínio(s) de terceira parte` });
  }

  if (items.length === 0) {
    el.innerHTML = `<div class="risk-item risk-ok"><span class="risk-icon">✅</span><span class="risk-text">Nenhuma ameaça detectada nesta página</span></div>`;
    return;
  }

  el.innerHTML = items.map(item =>
    `<div class="risk-item risk-${item.level}">
      <span class="risk-icon">${item.icon}</span>
      <span class="risk-text">${item.text}</span>
    </div>`
  ).join("");
}

function renderRequestsList(data) {
  const el = document.getElementById("requests-list");
  const requests = (data.requests || []).slice(-20).reverse();

  if (requests.length === 0) {
    el.innerHTML = `<div class="loading">Nenhuma requisição registrada</div>`;
    return;
  }

  el.innerHTML = requests.map(r => {
    let statusClass = "first-party";
    let itemClass = "";
    if (r.blocked) { statusClass = "blocked"; itemClass = "is-blocked"; }
    else if (r.isTracker) { statusClass = "tracker"; itemClass = "is-tracker"; }
    else if (r.isThirdParty) { statusClass = "third-party"; itemClass = "is-third-party"; }

    return `<div class="request-item ${itemClass}">
      <div class="request-status ${statusClass}"></div>
      <span class="request-host" title="${r.url}">${r.hostname}</span>
      <span class="request-type">${r.type || ""}</span>
    </div>`;
  }).join("");
}

// ============================================================
// Trackers Tab
// ============================================================
function renderTrackers(data) {
  renderDomainList("trackers-list", data.trackerDomains || [], "tracker", "badge-trackers");
  renderDomainList("blocked-list", data.blockedDomains || [], "blocked", "badge-blocked");
  renderDomainList("third-party-list", data.thirdPartyDomains || [], "third-party", "badge-third-party");
}

function renderDomainList(elementId, domains, type, badgeId) {
  const el = document.getElementById(elementId);
  const badge = document.getElementById(badgeId);
  if (badge) badge.textContent = domains.length;

  if (!domains || domains.length === 0) {
    el.innerHTML = `<div class="empty-state">Nenhum domínio nesta categoria</div>`;
    return;
  }

  const categoryClass = type === "tracker" ? "tracker-cat" : type === "blocked" ? "blocked-cat" : "";
  const label = type === "tracker" ? "Rastreador" : type === "blocked" ? "Bloqueado" : "3ª Parte";

  el.innerHTML = domains.map(domain =>
    `<div class="domain-item ${type}">
      <span class="domain-name" title="${domain}">${domain}</span>
      <span class="domain-category ${categoryClass}">${label}</span>
    </div>`
  ).join("");
}

// ============================================================
// Cookies Tab
// ============================================================
function renderCookies(data) {
  const cookies = data.cookies || { firstParty: [], thirdParty: [], session: 0, persistent: 0, total: 0 };

  document.getElementById("cookie-total").textContent = cookies.total || 0;
  document.getElementById("cookie-first").textContent = cookies.firstParty.length;
  document.getElementById("cookie-third").textContent = cookies.thirdParty.length;
  document.getElementById("cookie-session").textContent = cookies.session || 0;
  document.getElementById("cookie-persistent").textContent = cookies.persistent || 0;

  // Cookies de terceira parte
  renderCookieList("cookies-third-party-list", cookies.thirdParty, "third-party");

  // Supercookies
  renderSupercookieList(data.supercookies || []);

  // Cookie Sync
  renderCookieSyncList(data.cookieSyncDetails || []);

  // Cookies de primeira parte
  renderCookieList("cookies-first-party-list", cookies.firstParty, "first-party");
}

function renderCookieList(elementId, cookies, type) {
  const el = document.getElementById(elementId);
  if (!cookies || cookies.length === 0) {
    el.innerHTML = `<div class="empty-state">Nenhum cookie nesta categoria</div>`;
    return;
  }

  el.innerHTML = cookies.map(c => {
    const tags = [];
    if (c.session) tags.push(`<span class="cookie-tag">Sessão</span>`);
    else tags.push(`<span class="cookie-tag warning">Persistente</span>`);
    if (c.secure) tags.push(`<span class="cookie-tag success">Secure</span>`);
    if (c.httpOnly) tags.push(`<span class="cookie-tag success">HttpOnly</span>`);
    if (c.sameSite && c.sameSite !== "none") tags.push(`<span class="cookie-tag">SameSite:${c.sameSite}</span>`);
    else if (!c.secure) tags.push(`<span class="cookie-tag danger">Inseguro</span>`);

    return `<div class="cookie-item ${type}">
      <div class="cookie-name">${escapeHtml(c.name)} <small style="color:#8892b0">— ${c.domain}</small></div>
      <div class="cookie-meta">${tags.join("")}</div>
    </div>`;
  }).join("");
}

function renderSupercookieList(supercookies) {
  const el = document.getElementById("supercookies-list");
  if (!supercookies || supercookies.length === 0) {
    el.innerHTML = `<div class="empty-state">Nenhum supercookie detectado</div>`;
    return;
  }

  el.innerHTML = supercookies.map(sc =>
    `<div class="cookie-item supercookie">
      <div class="cookie-name">${escapeHtml(sc.type || "Supercookie")} <small style="color:#8892b0">— ${sc.domain}</small></div>
      <div class="cookie-meta">
        <span class="cookie-tag danger">Supercookie</span>
        <span class="cookie-tag warning">${sc.isThirdParty ? "3ª Parte" : "1ª Parte"}</span>
      </div>
    </div>`
  ).join("");
}

function renderCookieSyncList(syncDetails) {
  const el = document.getElementById("cookie-sync-list");
  if (!syncDetails || syncDetails.length === 0) {
    el.innerHTML = `<div class="empty-state">Nenhum sincronismo detectado</div>`;
    return;
  }

  el.innerHTML = syncDetails.map(sd =>
    `<div class="cookie-item third-party">
      <div class="cookie-name">${escapeHtml(sd.type)}</div>
      <div class="cookie-meta">
        <span class="cookie-tag warning">${sd.domain}</span>
      </div>
    </div>`
  ).join("");
}

// ============================================================
// Storage Tab
// ============================================================
function renderStorage(data) {
  // LocalStorage
  const localCount = data.localStorageKeys || 0;
  document.getElementById("localstorage-count").textContent = `${localCount} chave(s)`;
  const localIndicator = document.getElementById("localstorage-indicator");
  localIndicator.className = "storage-indicator" + (localCount > 0 ? " warn" : "");

  // SessionStorage
  const sessionCount = data.sessionStorageKeys || 0;
  document.getElementById("sessionstorage-count").textContent = `${sessionCount} chave(s)`;
  const sessionIndicator = document.getElementById("sessionstorage-indicator");
  sessionIndicator.className = "storage-indicator" + (sessionCount > 0 ? " warn" : "");

  // IndexedDB
  document.getElementById("indexeddb-status").textContent = data.indexedDBUsed ? "Em uso" : "Não utilizado";
  const idbIndicator = document.getElementById("indexeddb-indicator");
  idbIndicator.className = "storage-indicator" + (data.indexedDBUsed ? " active" : "");

  // Canvas Fingerprint
  document.getElementById("canvas-status").textContent = data.canvasFingerprint ? "DETECTADO ⚠️" : "Não detectado";
  const canvasIndicator = document.getElementById("canvas-indicator");
  canvasIndicator.className = "storage-indicator" + (data.canvasFingerprint ? " active" : "");

  // Detalhes de storage
  renderStorageDetails(data.storageDetails || []);

  // Hook list
  renderHookList(data.suspiciousScripts || []);
}

function renderStorageDetails(details) {
  const el = document.getElementById("storage-details-list");
  if (!details || details.length === 0) {
    el.innerHTML = `<div class="empty-state">Nenhum dado armazenado detectado</div>`;
    return;
  }

  el.innerHTML = details.map(d => {
    const typeClass = d.type === "localStorage" ? "local" : d.type === "sessionStorage" ? "session" : "indexed";
    return `<div class="storage-detail-item">
      <span class="storage-detail-type ${typeClass}">${d.type}</span>
      <div class="storage-detail-key">${escapeHtml(d.key)}</div>
      <div class="storage-detail-value">${escapeHtml(d.valuePreview)}</div>
    </div>`;
  }).join("");
}

function renderHookList(hooks) {
  const el = document.getElementById("hook-list");
  if (!hooks || hooks.length === 0) {
    el.innerHTML = `<div class="empty-state">Nenhuma ameaça detectada</div>`;
    return;
  }

  el.innerHTML = hooks.map(h =>
    `<div class="hook-item">
      <div class="hook-method">⚠️ ${escapeHtml(h.method || "Ameaça desconhecida")}</div>
      <div class="hook-desc">${escapeHtml(h.description || "")}</div>
      ${h.url ? `<div class="hook-desc" style="margin-top:2px;font-size:10px;word-break:break-all;">${escapeHtml(h.url.substring(0, 80))}</div>` : ""}
    </div>`
  ).join("");
}

// ============================================================
// Settings
// ============================================================
function applySettingsToUI(settings) {
  const blockTrackers = document.getElementById("setting-block-trackers");
  const blockAnalytics = document.getElementById("setting-block-analytics");
  const blockAds = document.getElementById("setting-block-ads");
  const blockSocial = document.getElementById("setting-block-social");
  const customBlocklist = document.getElementById("custom-blocklist");
  const customWhitelist = document.getElementById("custom-whitelist");

  if (blockTrackers) blockTrackers.checked = settings.blockingEnabled !== false;
  if (blockAnalytics) blockAnalytics.checked = settings.blockAnalytics !== false;
  if (blockAds) blockAds.checked = settings.blockAds !== false;
  if (blockSocial) blockSocial.checked = settings.blockSocialTrackers !== false;
  if (customBlocklist) customBlocklist.value = (settings.customBlocklist || []).join("\n");
  if (customWhitelist) customWhitelist.value = (settings.customWhitelist || []).join("\n");
}

function setupSettingsListeners() {
  const saveBtn = document.getElementById("save-lists");
  if (saveBtn) {
    saveBtn.addEventListener("click", saveCustomLists);
  }

  ["setting-block-trackers", "setting-block-analytics", "setting-block-ads", "setting-block-social"].forEach(id => {
    const el = document.getElementById(id);
    if (el) {
      el.addEventListener("change", saveSettingsFromUI);
    }
  });
}

function saveSettingsFromUI() {
  const settings = {
    blockingEnabled: document.getElementById("setting-block-trackers")?.checked !== false,
    blockAnalytics: document.getElementById("setting-block-analytics")?.checked !== false,
    blockAds: document.getElementById("setting-block-ads")?.checked !== false,
    blockSocialTrackers: document.getElementById("setting-block-social")?.checked !== false
  };
  sendSettings(settings);
}

async function saveCustomLists() {
  const blocklistText = document.getElementById("custom-blocklist").value;
  const whitelistText = document.getElementById("custom-whitelist").value;

  const customBlocklist = blocklistText.split("\n")
    .map(d => d.trim().toLowerCase())
    .filter(d => d && d.length > 2);

  const customWhitelist = whitelistText.split("\n")
    .map(d => d.trim().toLowerCase())
    .filter(d => d && d.length > 2);

  await sendSettings({ customBlocklist, customWhitelist });

  const feedback = document.getElementById("save-feedback");
  feedback.style.display = "block";
  setTimeout(() => { feedback.style.display = "none"; }, 2000);
}

async function sendSettings(partialSettings) {
  try {
    const current = currentSettings || {};
    const merged = { ...current, ...partialSettings };
    await browser.runtime.sendMessage({ type: "UPDATE_SETTINGS", settings: merged });
    currentSettings = merged;
  } catch (e) {
    console.warn("[Privacy Shield] Erro ao salvar configurações:", e);
  }
}

// ============================================================
// Utilitários
// ============================================================
function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
