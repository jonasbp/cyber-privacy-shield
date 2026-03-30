/**
 * Privacy Shield - Script injetado no contexto da página
 * Detecta canvas fingerprinting, audio fingerprinting e outras técnicas
 * Este script é injetado no contexto da página (não no contexto da extensão)
 * para poder interceptar chamadas de APIs do browser
 */
(function() {
  "use strict";

  function sendToExtension(type, detail) {
    window.postMessage({ __privacyShield: true, type, detail }, "*");
  }

  // ============================================================
  // Canvas Fingerprinting Detection
  // Intercepta chamadas que extraem dados de canvas para identificação
  // ============================================================
  const canvasProto = HTMLCanvasElement.prototype;
  const origToDataURL = canvasProto.toDataURL;
  const origToBlob = canvasProto.toBlob;

  let canvasFPDetected = false;

  function checkCanvasContent(canvas) {
    // Canvas com dimensões típicas de fingerprinting (não de imagens reais)
    const w = canvas.width;
    const h = canvas.height;
    // Fingerprinters usam canvas pequenos (< 300x100) com texto desenhado
    if (w > 0 && w < 500 && h > 0 && h < 200) {
      return true;
    }
    return false;
  }

  canvasProto.toDataURL = function(type, quality) {
    if (!canvasFPDetected && checkCanvasContent(this)) {
      canvasFPDetected = true;
      sendToExtension("CANVAS_FINGERPRINT", {
        width: this.width,
        height: this.height,
        type: type || "image/png",
        stack: new Error().stack.split("\n").slice(1, 4).join(" | ")
      });
    }
    return origToDataURL.apply(this, arguments);
  };

  canvasProto.toBlob = function(callback, type, quality) {
    if (!canvasFPDetected && checkCanvasContent(this)) {
      canvasFPDetected = true;
      sendToExtension("CANVAS_FINGERPRINT", {
        width: this.width,
        height: this.height,
        type: type || "image/png",
        method: "toBlob"
      });
    }
    return origToBlob.apply(this, arguments);
  };

  const ctx2dProto = CanvasRenderingContext2D.prototype;
  const origGetImageData = ctx2dProto.getImageData;
  let imageDataFPDetected = false;

  ctx2dProto.getImageData = function(sx, sy, sw, sh) {
    if (!imageDataFPDetected) {
      imageDataFPDetected = true;
      sendToExtension("CANVAS_FINGERPRINT", {
        method: "getImageData",
        region: { sx, sy, sw, sh }
      });
    }
    return origGetImageData.apply(this, arguments);
  };

  // ============================================================
  // WebGL Fingerprinting Detection
  // ============================================================
  const origGetParameter = WebGLRenderingContext.prototype.getParameter;
  let webglFPDetected = false;
  const webglFPParams = [37445, 37446, 7936, 7937, 35724]; // VENDOR, RENDERER, etc.

  WebGLRenderingContext.prototype.getParameter = function(param) {
    if (!webglFPDetected && webglFPParams.includes(param)) {
      webglFPDetected = true;
      sendToExtension("CANVAS_FINGERPRINT", {
        method: "WebGL getParameter",
        param: param
      });
    }
    return origGetParameter.apply(this, arguments);
  };

  // ============================================================
  // Audio Fingerprinting Detection
  // ============================================================
  if (window.AudioContext || window.webkitAudioContext) {
    const AudioCtx = window.AudioContext || window.webkitAudioContext;
    const OrigAudioContext = AudioCtx;
    let audioFPDetected = false;

    // Monitorar OscillatorNode + AnalyserNode (padrão de audio fingerprinting)
    const origCreateOscillator = AudioCtx.prototype.createOscillator;
    AudioCtx.prototype.createOscillator = function() {
      if (!audioFPDetected) {
        audioFPDetected = true;
        sendToExtension("CANVAS_FINGERPRINT", {
          method: "AudioContext fingerprint",
          detail: "OscillatorNode criado"
        });
      }
      return origCreateOscillator.apply(this, arguments);
    };
  }

  // ============================================================
  // Font Fingerprinting Detection
  // Detecta enumeração de fontes via measureText
  // ============================================================
  const origMeasureText = CanvasRenderingContext2D.prototype.measureText;
  let fontCheckCount = 0;
  let fontFPDetected = false;

  CanvasRenderingContext2D.prototype.measureText = function(text) {
    fontCheckCount++;
    if (!fontFPDetected && fontCheckCount > 20) {
      fontFPDetected = true;
      sendToExtension("CANVAS_FINGERPRINT", {
        method: "Font fingerprinting",
        detail: `${fontCheckCount} medições de texto detectadas`
      });
    }
    return origMeasureText.apply(this, arguments);
  };

})();
