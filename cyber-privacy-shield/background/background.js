/**
 * Privacy Shield - Background Script
 * Responsável por:
 * - Monitorar requisições web (webRequest API)
 * - Detectar domínios de terceira parte
 * - Identificar e bloquear rastreadores
 * - Analisar cookies (Set-Cookie headers)
 * - Calcular pontuação de privacidade
 * - Detectar sincronismo de cookies (cookie syncing)
 */

// ============================================================
// Estado por aba
// ============================================================
const tabData = {};

function initTabData(tabId) {
  tabData[tabId] = {
    url: null,
    hostname: null,
    thirdPartyDomains: new Set(),
    trackerDomains: new Set(),
    blockedDomains: new Set(),
    cookies: {
      firstParty: [],
      thirdParty: [],
      session: 0,
      persistent: 0,
      total: 0
    },
    supercookies: [],
    canvasFingerprint: false,
    localStorageKeys: 0,
    sessionStorageKeys: 0,
    indexedDBUsed: false,
    hookDetected: false,
    suspiciousScripts: [],
    cookieSyncDetected: false,
    cookieSyncDetails: [],
    requests: [],
    startTime: Date.now(),
    privacyScore: 100,
    scoreDetails: []
  };
}

// ============================================================
// Configurações
// ============================================================
let settings = {
  blockingEnabled: true,
  customBlocklist: [],
  customWhitelist: [],
  blockSocialTrackers: true,
  blockAnalytics: true,
  blockAds: true
};

// Carregar configurações salvas
browser.storage.local.get(["settings"]).then(result => {
  if (result.settings) {
    settings = { ...settings, ...result.settings };
  }
});

// ============================================================
// Utilitários
// ============================================================
function getHostname(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    return null;
  }
}

function getRootDomain(hostname) {
  if (!hostname) return null;
  const parts = hostname.split(".");
  if (parts.length >= 2) {
    return parts.slice(-2).join(".");
  }
  return hostname;
}

function isThirdParty(requestUrl, pageUrl) {
  if (!pageUrl || pageUrl === "" || pageUrl.startsWith("about:") || pageUrl.startsWith("moz-extension:")) {
    return false;
  }
  const reqHost = getHostname(requestUrl);
  const pageHost = getHostname(pageUrl);
  if (!reqHost || !pageHost) return false;

  const reqRoot = getRootDomain(reqHost);
  const pageRoot = getRootDomain(pageHost);
  return reqRoot !== pageRoot;
}

function isKnownTracker(hostname) {
  if (!hostname) return false;
  if (KNOWN_TRACKERS.has(hostname)) return true;
  // Verificar domínio pai
  const parts = hostname.split(".");
  for (let i = 0; i < parts.length - 1; i++) {
    const domain = parts.slice(i).join(".");
    if (KNOWN_TRACKERS.has(domain)) return true;
  }
  return false;
}

function isInCustomBlocklist(hostname) {
  return settings.customBlocklist.some(domain => {
    const d = domain.trim().toLowerCase();
    return hostname === d || hostname.endsWith("." + d);
  });
}

function isInCustomWhitelist(hostname) {
  return settings.customWhitelist.some(domain => {
    const d = domain.trim().toLowerCase();
    return hostname === d || hostname.endsWith("." + d);
  });
}

// ============================================================
// Detecção de Cookie Sync
// Rastreadores passam IDs de usuários entre si via parâmetros de URL
// ============================================================
const COOKIE_SYNC_PATTERNS = [
  { pattern: /uid=([a-zA-Z0-9_-]{8,})/i, name: "UID Sync" },
  { pattern: /user_id=([a-zA-Z0-9_-]{8,})/i, name: "User ID Sync" },
  { pattern: /gdpr_consent=([a-zA-Z0-9_-]{8,})/i, name: "GDPR Consent Sync" },
  { pattern: /gdpr=1/i, name: "GDPR Sync" },
  { pattern: /uuid=([a-zA-Z0-9_-]{8,})/i, name: "UUID Sync" },
  { pattern: /[?&]id=([a-zA-Z0-9_-]{16,})/i, name: "ID Sync" },
  { pattern: /[?&]eid=([a-zA-Z0-9_-]{8,})/i, name: "External ID Sync" },
  { pattern: /[?&]puid=([a-zA-Z0-9_-]{8,})/i, name: "Publisher UID Sync" },
  { pattern: /[?&]buyeruid=([a-zA-Z0-9_-]{8,})/i, name: "Buyer UID Sync" },
  { pattern: /[?&]tdid=([a-zA-Z0-9_-]{8,})/i, name: "Trade Desk ID Sync" },
  { pattern: /[?&]cm_dsp_id=/i, name: "DSP Cookie Sync" },
  { pattern: /cm\?/i, name: "Cookie Match Request" },
  { pattern: /cookiematch/i, name: "Cookie Match" },
  { pattern: /cookiesync/i, name: "Cookie Sync" },
  { pattern: /pixel\.sync/i, name: "Pixel Sync" }
];

function detectCookieSync(url, hostname) {
  for (const { pattern, name } of COOKIE_SYNC_PATTERNS) {
    if (pattern.test(url)) {
      return { detected: true, type: name, domain: hostname };
    }
  }
  return { detected: false };
}

// ============================================================
// WebRequest - Interceptar requisições
// ============================================================
browser.webRequest.onBeforeRequest.addListener(
  function(details) {
    const tabId = details.tabId;
    if (tabId < 0) return {};

    if (!tabData[tabId]) initTabData(tabId);

    const reqHostname = getHostname(details.url);
    if (!reqHostname) return {};

    const tab = tabData[tabId];

    // Registrar requisição
    const reqInfo = {
      url: details.url,
      hostname: reqHostname,
      type: details.type,
      isThirdParty: false,
      isTracker: false,
      blocked: false,
      timestamp: Date.now()
    };

    // Verificar se é terceira parte
    if (tab.url && isThirdParty(details.url, tab.url)) {
      reqInfo.isThirdParty = true;
      tab.thirdPartyDomains.add(reqHostname);

      // Verificar cookie sync em requisições de terceiros
      const syncResult = detectCookieSync(details.url, reqHostname);
      if (syncResult.detected) {
        tab.cookieSyncDetected = true;
        if (!tab.cookieSyncDetails.find(d => d.domain === reqHostname && d.type === syncResult.type)) {
          tab.cookieSyncDetails.push(syncResult);
        }
      }
    }

    // Verificar se é rastreador conhecido
    if (isKnownTracker(reqHostname)) {
      reqInfo.isTracker = true;
      tab.trackerDomains.add(reqHostname);
    }

    // Verificar lista personalizada
    const inCustomBlock = isInCustomBlocklist(reqHostname);
    const inCustomWhitelist = isInCustomWhitelist(reqHostname);

    // Decisão de bloqueio
    if (!inCustomWhitelist && settings.blockingEnabled) {
      if (inCustomBlock || reqInfo.isTracker) {
        reqInfo.blocked = true;
        tab.blockedDomains.add(reqHostname);
        tab.requests.push(reqInfo);
        updateBadge(tabId);
        return { cancel: true };
      }
    }

    tab.requests.push(reqInfo);
    return {};
  },
  { urls: ["<all_urls>"] },
  ["blocking"]
);

// ============================================================
// WebRequest - Analisar headers de resposta (cookies)
// ============================================================
browser.webRequest.onHeadersReceived.addListener(
  function(details) {
    const tabId = details.tabId;
    if (tabId < 0 || !tabData[tabId]) return;

    const tab = tabData[tabId];
    const reqHostname = getHostname(details.url);
    const isTP = tab.url ? isThirdParty(details.url, tab.url) : false;

    // Analisar Set-Cookie headers
    if (details.responseHeaders) {
      for (const header of details.responseHeaders) {
        if (header.name.toLowerCase() === "set-cookie") {
          const cookieValue = header.value;
          const cookieInfo = parseCookieHeader(cookieValue, reqHostname, isTP);
          tab.cookies.total++;

          if (isTP) {
            tab.cookies.thirdParty.push(cookieInfo);
          } else {
            tab.cookies.firstParty.push(cookieInfo);
          }

          if (cookieInfo.session) {
            tab.cookies.session++;
          } else {
            tab.cookies.persistent++;
          }

          // Detectar supercookies (HSTS, ETag)
          if (cookieInfo.isSupercookie) {
            tab.supercookies.push(cookieInfo);
          }
        }

        // Detectar HSTS como supercookie potencial
        if (header.name.toLowerCase() === "strict-transport-security" && isTP) {
          const existing = tab.supercookies.find(s => s.domain === reqHostname && s.type === "HSTS");
          if (!existing) {
            tab.supercookies.push({
              type: "HSTS Supercookie",
              domain: reqHostname,
              value: header.value,
              isThirdParty: true
            });
          }
        }

        // Detectar ETag como supercookie potencial
        if (header.name.toLowerCase() === "etag" && isTP) {
          const etagValue = header.value;
          // ETags longos podem ser usados como identificadores
          if (etagValue && etagValue.length > 10) {
            const existing = tab.supercookies.find(s => s.domain === reqHostname && s.type === "ETag");
            if (!existing) {
              tab.supercookies.push({
                type: "ETag Supercookie",
                domain: reqHostname,
                value: etagValue.substring(0, 20) + "...",
                isThirdParty: true
              });
            }
          }
        }
      }
    }

    updateBadge(tabId);
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);

// ============================================================
// Parsear header Set-Cookie
// ============================================================
function parseCookieHeader(cookieStr, domain, isThirdParty) {
  const parts = cookieStr.split(";").map(p => p.trim());
  const nameValue = parts[0] || "";
  const nameParts = nameValue.split("=");
  const name = nameParts[0] || "unknown";

  const cookieInfo = {
    name: name,
    domain: domain,
    isThirdParty: isThirdParty,
    session: true,
    secure: false,
    httpOnly: false,
    sameSite: "none",
    expires: null,
    isSupercookie: false,
    raw: cookieStr.substring(0, 100)
  };

  for (const part of parts.slice(1)) {
    const lower = part.toLowerCase();
    if (lower.startsWith("expires=") || lower.startsWith("max-age=")) {
      cookieInfo.session = false;
      cookieInfo.expires = part;
    }
    if (lower === "secure") cookieInfo.secure = true;
    if (lower === "httponly") cookieInfo.httpOnly = true;
    if (lower.startsWith("samesite=")) {
      cookieInfo.sameSite = part.split("=")[1] || "none";
    }
  }

  // Heurística de supercookie: cookie de terceiro, persistente, com nome suspeito
  const superCookieNames = ["uuid", "uid", "guid", "visitor_id", "tracking_id", "_ga", "_fbp", "_ttp", "__utmz"];
  if (isThirdParty && !cookieInfo.session) {
    if (superCookieNames.some(n => name.toLowerCase().includes(n))) {
      cookieInfo.isSupercookie = true;
      cookieInfo.type = "Tracking Supercookie";
    }
  }

  return cookieInfo;
}

// ============================================================
// Atualizar navegação de aba
// ============================================================
browser.webNavigation.onCommitted.addListener(function(details) {
  if (details.frameId !== 0) return;
  const tabId = details.tabId;
  initTabData(tabId);
  tabData[tabId].url = details.url;
  tabData[tabId].hostname = getHostname(details.url);
  updateBadge(tabId);
});

browser.tabs.onActivated.addListener(function(activeInfo) {
  updateBadge(activeInfo.tabId);
});

browser.tabs.onRemoved.addListener(function(tabId) {
  delete tabData[tabId];
});

// ============================================================
// Badge de ícone
// ============================================================
function updateBadge(tabId) {
  if (!tabData[tabId]) return;
  const tab = tabData[tabId];
  const blocked = tab.blockedDomains.size;
  const trackers = tab.trackerDomains.size;
  const total = blocked + trackers;

  if (total > 0) {
    browser.browserAction.setBadgeText({ text: String(total), tabId });
    browser.browserAction.setBadgeBackgroundColor({ color: total > 5 ? "#e74c3c" : "#e67e22", tabId });
  } else {
    browser.browserAction.setBadgeText({ text: "", tabId });
  }
}

// ============================================================
// Calcular pontuação de privacidade
// ============================================================
function calculatePrivacyScore(tab) {
  let score = 100;
  const details = [];

  // Rastreadores detectados
  const trackerCount = tab.trackerDomains.size + tab.blockedDomains.size;
  if (trackerCount > 0) {
    const penalty = Math.min(40, trackerCount * 8);
    score -= penalty;
    details.push({ label: `${trackerCount} rastreador(es) detectado(s)`, penalty: -penalty, icon: "🕵️" });
  }

  // Conexões de terceira parte
  const thirdPartyCount = tab.thirdPartyDomains.size;
  if (thirdPartyCount > 0) {
    const penalty = Math.min(20, thirdPartyCount * 2);
    score -= penalty;
    details.push({ label: `${thirdPartyCount} domínio(s) de terceira parte`, penalty: -penalty, icon: "🌐" });
  }

  // Cookies de terceira parte
  const tpCookies = tab.cookies.thirdParty.length;
  if (tpCookies > 0) {
    const penalty = Math.min(20, tpCookies * 4);
    score -= penalty;
    details.push({ label: `${tpCookies} cookie(s) de terceira parte`, penalty: -penalty, icon: "🍪" });
  }

  // LocalStorage / SessionStorage
  if (tab.localStorageKeys > 0) {
    const penalty = Math.min(10, tab.localStorageKeys);
    score -= penalty;
    details.push({ label: `LocalStorage: ${tab.localStorageKeys} chave(s)`, penalty: -penalty, icon: "💾" });
  }

  // IndexedDB
  if (tab.indexedDBUsed) {
    score -= 5;
    details.push({ label: "IndexedDB utilizado", penalty: -5, icon: "🗄️" });
  }

  // Canvas Fingerprinting
  if (tab.canvasFingerprint) {
    score -= 20;
    details.push({ label: "Canvas Fingerprinting detectado", penalty: -20, icon: "🖼️" });
  }

  // Supercookies
  if (tab.supercookies.length > 0) {
    const penalty = Math.min(15, tab.supercookies.length * 5);
    score -= penalty;
    details.push({ label: `${tab.supercookies.length} supercookie(s) detectado(s)`, penalty: -penalty, icon: "🦠" });
  }

  // Cookie Sync
  if (tab.cookieSyncDetected) {
    score -= 10;
    details.push({ label: "Sincronismo de cookies detectado", penalty: -10, icon: "🔄" });
  }

  // Hook / Hijacking suspeito
  if (tab.hookDetected) {
    score -= 30;
    details.push({ label: "Tentativa de hook/hijacking detectada!", penalty: -30, icon: "⚠️" });
  }

  if (tab.suspiciousScripts.length > 0) {
    const penalty = Math.min(20, tab.suspiciousScripts.length * 10);
    score -= penalty;
    details.push({ label: `${tab.suspiciousScripts.length} script(s) suspeito(s)`, penalty: -penalty, icon: "⚠️" });
  }

  score = Math.max(0, score);
  return { score, details };
}

function getScoreRating(score) {
  if (score >= 80) return { label: "Excelente", color: "#27ae60", grade: "A" };
  if (score >= 60) return { label: "Bom", color: "#2ecc71", grade: "B" };
  if (score >= 40) return { label: "Regular", color: "#f39c12", grade: "C" };
  if (score >= 20) return { label: "Ruim", color: "#e67e22", grade: "D" };
  return { label: "Péssimo", color: "#e74c3c", grade: "F" };
}

// ============================================================
// Comunicação com Popup e Content Script
// ============================================================
browser.runtime.onMessage.addListener(function(message, sender, sendResponse) {
  // Mensagem do content script
  if (message.type === "CANVAS_FINGERPRINT") {
    const tabId = sender.tab ? sender.tab.id : -1;
    if (tabId >= 0 && tabData[tabId]) {
      tabData[tabId].canvasFingerprint = true;
    }
    return;
  }

  if (message.type === "STORAGE_DATA") {
    const tabId = sender.tab ? sender.tab.id : -1;
    if (tabId >= 0 && tabData[tabId]) {
      tabData[tabId].localStorageKeys = message.localStorageKeys || 0;
      tabData[tabId].sessionStorageKeys = message.sessionStorageKeys || 0;
      tabData[tabId].indexedDBUsed = message.indexedDBUsed || false;
      tabData[tabId].storageDetails = message.storageDetails || [];
    }
    return;
  }

  if (message.type === "HOOK_DETECTED") {
    const tabId = sender.tab ? sender.tab.id : -1;
    if (tabId >= 0 && tabData[tabId]) {
      tabData[tabId].hookDetected = true;
      tabData[tabId].suspiciousScripts.push(message.detail);
    }
    return;
  }

  // Mensagem do popup solicitando dados
  if (message.type === "GET_TAB_DATA") {
    browser.tabs.query({ active: true, currentWindow: true }).then(tabs => {
      if (tabs.length === 0) {
        sendResponse({ error: "Nenhuma aba ativa" });
        return;
      }
      const tabId = tabs[0].id;
      if (!tabData[tabId]) initTabData(tabId);

      const tab = tabData[tabId];
      const { score, details } = calculatePrivacyScore(tab);
      const rating = getScoreRating(score);

      sendResponse({
        tabId,
        url: tab.url,
        hostname: tab.hostname,
        thirdPartyDomains: Array.from(tab.thirdPartyDomains),
        trackerDomains: Array.from(tab.trackerDomains),
        blockedDomains: Array.from(tab.blockedDomains),
        requests: tab.requests.slice(-50), // últimas 50 requisições
        cookies: {
          firstParty: tab.cookies.firstParty,
          thirdParty: tab.cookies.thirdParty,
          session: tab.cookies.session,
          persistent: tab.cookies.persistent,
          total: tab.cookies.total
        },
        supercookies: tab.supercookies,
        canvasFingerprint: tab.canvasFingerprint,
        localStorageKeys: tab.localStorageKeys,
        sessionStorageKeys: tab.sessionStorageKeys,
        indexedDBUsed: tab.indexedDBUsed,
        storageDetails: tab.storageDetails || [],
        hookDetected: tab.hookDetected,
        suspiciousScripts: tab.suspiciousScripts,
        cookieSyncDetected: tab.cookieSyncDetected,
        cookieSyncDetails: tab.cookieSyncDetails,
        privacyScore: score,
        scoreRating: rating,
        scoreDetails: details,
        blockingEnabled: settings.blockingEnabled
      });
    });
    return true; // async
  }

  // Atualizar configurações
  if (message.type === "UPDATE_SETTINGS") {
    settings = { ...settings, ...message.settings };
    browser.storage.local.set({ settings });
    sendResponse({ ok: true });
    return;
  }

  // Obter configurações
  if (message.type === "GET_SETTINGS") {
    sendResponse({ settings });
    return true;
  }
});
