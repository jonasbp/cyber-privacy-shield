/**
 * Privacy Shield - Content Script
 * Responsável por:
 * - Injetar detector de fingerprinting no contexto da página
 * - Detectar uso de localStorage/sessionStorage/IndexedDB
 * - Detectar tentativas de hook e hijacking
 * - Monitorar iframes suspeitos
 * - Detectar scripts de rastreamento inline
 */

(function() {
  "use strict";

  // ============================================================
  // 1. Injetar script no contexto da página para detectar fingerprinting
  // ============================================================
  function injectFingerprintDetector() {
    try {
      const script = document.createElement("script");
      script.src = browser.runtime.getURL("content/injected.js");
      script.onload = function() { this.remove(); };
      (document.head || document.documentElement).appendChild(script);
    } catch (e) {
      // Fallback: injetar como texto inline
      try {
        const req = new XMLHttpRequest();
        req.open("GET", browser.runtime.getURL("content/injected.js"), false);
        req.send();
        const script = document.createElement("script");
        script.textContent = req.responseText;
        (document.head || document.documentElement).appendChild(script);
        script.remove();
      } catch (e2) {
        console.warn("[Privacy Shield] Não foi possível injetar detector:", e2);
      }
    }
  }

  // Executar imediatamente (document_start)
  injectFingerprintDetector();

  // ============================================================
  // 2. Receber mensagens do script injetado (contexto da página)
  // ============================================================
  window.addEventListener("message", function(event) {
    if (event.source !== window) return;
    if (!event.data || !event.data.__privacyShield) return;

    const { type, detail } = event.data;

    if (type === "CANVAS_FINGERPRINT") {
      browser.runtime.sendMessage({ type: "CANVAS_FINGERPRINT", detail });
    }
  });

  // ============================================================
  // 3. Detectar storage ao carregar página
  // ============================================================
  function analyzeStorage() {
    const storageDetails = [];
    let localStorageKeys = 0;
    let sessionStorageKeys = 0;
    let indexedDBUsed = false;

    // LocalStorage
    try {
      localStorageKeys = localStorage.length;
      if (localStorageKeys > 0) {
        for (let i = 0; i < Math.min(localStorageKeys, 20); i++) {
          const key = localStorage.key(i);
          const value = localStorage.getItem(key);
          storageDetails.push({
            type: "localStorage",
            key: key,
            valuePreview: value ? value.substring(0, 50) : "(vazio)",
            size: value ? value.length : 0
          });
        }
      }
    } catch (e) {}

    // SessionStorage
    try {
      sessionStorageKeys = sessionStorage.length;
      if (sessionStorageKeys > 0) {
        for (let i = 0; i < Math.min(sessionStorageKeys, 20); i++) {
          const key = sessionStorage.key(i);
          const value = sessionStorage.getItem(key);
          storageDetails.push({
            type: "sessionStorage",
            key: key,
            valuePreview: value ? value.substring(0, 50) : "(vazio)",
            size: value ? value.length : 0
          });
        }
      }
    } catch (e) {}

    // IndexedDB - verificar se tem databases abertas
    try {
      if (window.indexedDB) {
        indexedDB.databases().then(dbs => {
          if (dbs && dbs.length > 0) {
            indexedDBUsed = true;
            dbs.forEach(db => {
              storageDetails.push({
                type: "IndexedDB",
                key: db.name,
                valuePreview: `Versão: ${db.version}`,
                size: 0
              });
            });
            browser.runtime.sendMessage({
              type: "STORAGE_DATA",
              localStorageKeys,
              sessionStorageKeys,
              indexedDBUsed: true,
              storageDetails
            });
          }
        }).catch(() => {});
      }
    } catch (e) {}

    browser.runtime.sendMessage({
      type: "STORAGE_DATA",
      localStorageKeys,
      sessionStorageKeys,
      indexedDBUsed,
      storageDetails
    });
  }

  // Analisar storage após carregamento
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", analyzeStorage);
  } else {
    analyzeStorage();
  }

  // Também analisar após carregamento completo (scripts podem ter adicionado dados)
  window.addEventListener("load", function() {
    setTimeout(analyzeStorage, 1000);
  });

  // ============================================================
  // 4. Detectar tentativas de hook e hijacking (BeEF, etc.)
  // ============================================================
  function detectHookAttempts() {
    // Verificar iframes suspeitos (BeEF usa iframes ocultos)
    const iframes = document.querySelectorAll("iframe");
    iframes.forEach(iframe => {
      const src = iframe.src || iframe.getAttribute("src") || "";
      const style = window.getComputedStyle(iframe);
      const isHidden = style.display === "none" || style.visibility === "hidden" ||
                       style.opacity === "0" || iframe.width === "0" || iframe.height === "0";

      if (isHidden && src && src.startsWith("http")) {
        browser.runtime.sendMessage({
          type: "HOOK_DETECTED",
          detail: {
            method: "Iframe oculto detectado",
            url: src,
            description: "Iframe invisível pode ser usado para rastreamento ou hook"
          }
        });
      }
    });

    // Verificar scripts com padrões conhecidos de BeEF/hook
    const scripts = document.querySelectorAll("script[src]");
    const hookPatterns = [
      /beef/i,
      /hook\.js/i,
      /xsshook/i,
      /browser\.?exploit/i,
      /zombie\.js/i,
      /metasploit/i
    ];

    scripts.forEach(script => {
      const src = script.src || "";
      for (const pattern of hookPatterns) {
        if (pattern.test(src)) {
          browser.runtime.sendMessage({
            type: "HOOK_DETECTED",
            detail: {
              method: "Script de hook detectado",
              url: src,
              description: `Script suspeito: ${src.substring(0, 100)}`
            }
          });
          break;
        }
      }
    });

    // Verificar redirecionamentos suspeitos via meta refresh
    const metaRefresh = document.querySelector("meta[http-equiv='refresh'], meta[http-equiv='Refresh']");
    if (metaRefresh) {
      const content = metaRefresh.getAttribute("content") || "";
      const urlMatch = content.match(/url=(.+)/i);
      if (urlMatch) {
        const redirectUrl = urlMatch[1];
        const currentHost = window.location.hostname;
        try {
          const redirectHost = new URL(redirectUrl).hostname;
          if (redirectHost && redirectHost !== currentHost) {
            browser.runtime.sendMessage({
              type: "HOOK_DETECTED",
              detail: {
                method: "Redirecionamento suspeito (Meta Refresh)",
                url: redirectUrl,
                description: `Redirecionamento para ${redirectHost}`
              }
            });
          }
        } catch (e) {}
      }
    }
  }

  // Executar detecção após DOM estar disponível
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", detectHookAttempts);
  } else {
    detectHookAttempts();
  }

  // Monitorar mudanças no DOM (scripts adicionados dinamicamente)
  const observer = new MutationObserver(function(mutations) {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.tagName === "SCRIPT" && node.src) {
          const hookPatterns = [/beef/i, /hook\.js/i, /xsshook/i];
          for (const pattern of hookPatterns) {
            if (pattern.test(node.src)) {
              browser.runtime.sendMessage({
                type: "HOOK_DETECTED",
                detail: {
                  method: "Script de hook injetado dinamicamente",
                  url: node.src,
                  description: `Script suspeito injetado: ${node.src.substring(0, 100)}`
                }
              });
            }
          }
        }
        if (node.tagName === "IFRAME") {
          const src = node.src || "";
          if (src.startsWith("http")) {
            const style = window.getComputedStyle(node);
            if (style.display === "none" || node.width === "0") {
              browser.runtime.sendMessage({
                type: "HOOK_DETECTED",
                detail: {
                  method: "Iframe oculto injetado dinamicamente",
                  url: src,
                  description: "Iframe invisível adicionado dinamicamente"
                }
              });
            }
          }
        }
      }
    }
  });

  observer.observe(document.documentElement, { childList: true, subtree: true });

})();
