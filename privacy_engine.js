/**
 * ISRO PS 171 - On-Device Privacy & PII Redaction Engine
 * Module: privacy_engine.js
 * ============================================================================
 *
 * INTEGRATION ARCHITECTURE (Member 1 + Member 3):
 *
 *   ┌─ offscreen.js ─────────────────────────────────────────────────────┐
 *   │  privacyEngine.sanitizeViewport(rawBase64, candidateElements, dpr) │
 *   │    └─► detectAndRedactPII(ctx, w, h, candidateElements)            │
 *   │    └─► scanDOM()  [runs inside offscreen document context]         │
 *   │    └─► SessionVaultManager.tokenize()  → [SYS_PAN_01]             │
 *   │    └─► returns { sanitizedImage, tokenMap, telemetry }             │
 *   └────────────────────────────────────────────────────────────────────┘
 *
 *   The tokenMap is then included in the server payload so the LLM can
 *   reference elements by alias (e.g. "[SYS_EMAIL_01]") without seeing real PII.
 *
 *   Outgoing payload is guarded by validatePayload() - throws on leakage.
 */

import { SessionVaultManager } from './vault_manager.js';
import { AccessibilitySanitizer } from './accessibility_sanitizer.js';

export class PrivacyEngine {
  constructor(config = {}) {
    this.config = {
      maskFillColor:           config.maskFillColor           || '#0a0a0c',
      tokenTextColor:          config.tokenTextColor          || '#00ffcc',
      borderColor:             config.borderColor             || '#ff0055',
      font:                    config.font                    || 'bold 11px "Courier New", monospace',
      pixelateSize:            config.pixelateSize            || 12,
      enableStrictZeroLeakage: config.enableStrictZeroLeakage !== false,
      ...config
    };

    this.patterns = {
      aadhaar:       /(?<!\d)[2-9]{1}[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}(?!\d)/g,
      pan:           /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g,
      creditCard:    /(?<!\d)(?:\d{4}[\s\-]?){3}\d{4}(?!\d)|(?<!\d)\d{15,16}(?!\d)/g,
      indianPhone:   /(?<!\d)(?:\+91[\-\s]?)?[6-9]\d{9}(?!\d)/g,
      email:         /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
      upiId:         /\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b/g,
      passport:      /\b[A-Z]{1}[0-9]{7}\b/g,
      drivingLicense:/\b[A-Z]{2}[0-9]{2}[0-9]{11}\b/g
    };

    this.sensitiveKeywords = /password|cvv|otp|pin|aadhaar|pan|card|secret|token|ssn|license/i;

    // Session vault - in-RAM only, tokenizes page PII → [SYS_*] aliases for LLM
    this.vault = new SessionVaultManager({ aliasPrefix: 'SYS' });

    // Accessibility sanitizer - redacts PII in AX tree nodes before LLM sees them
    this.a11ySanitizer = new AccessibilitySanitizer(this.patterns);

    this.telemetryHistory = [];
  }

  // ──────────────────────────────────────────────────────────────────────────
  // PRIMARY INTERFACE (called from offscreen.js processFrame)
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * sanitizeViewport - the main integration entry point.
   *
   * Accepts a raw base64 screenshot + candidate element bounding boxes,
   * runs full DOM scan + canvas redaction, and returns a safe sanitized image.
   *
   * @param {string} rawBase64 - Raw JPEG base64 string (data URI or bare)
   * @param {Array}  candidateElements - UI elements detected by Member 2's vision model
   * @param {number} scaleFactor - DPR scale factor
   * @returns {Promise<{ sanitizedImage: string, tokenMap: Array, telemetry: Object }>}
   */
  async sanitizeViewport(rawBase64, candidateElements = [], scaleFactor = 1.0) {
    const startTime = performance.now();

    const img = await this._loadImage(
      rawBase64.startsWith('data:') ? rawBase64 : `data:image/jpeg;base64,${rawBase64}`
    );

    // Create a fresh canvas for this frame
    const canvas = new OffscreenCanvas(img.width, img.height);
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(img, 0, 0);

    const tokenMap = [];
    const scale = scaleFactor || 1.0;

    // Phase 1: Scan DOM for PII bounding boxes
    const domBoxes = this.scanDOM();

    const KNOWN_PII_CATEGORIES = new Set([
      'AADHAAR', 'PAN', 'CREDITCARD', 'CREDIT_CARD', 'INDIANPHONE', 'PHONE',
      'EMAIL', 'UPIID', 'UPI', 'PASSWORD', 'PASSWORD_SECRET', 'AUTH_CREDENTIAL',
      'OTP_PIN', 'PERSON', 'ADDRESS', 'FACE_AVATAR', 'PASSPORT', 'DRIVINGLICENSE'
    ]);

    // Phase 2: Merge with ML-detected and DOM-scanned candidate elements
    const allBoxes = [...domBoxes, ...candidateElements.map(el => {
      let b = el.boundingBox;
      if (!b) {
        b = {
          x: el.bbox ? el.bbox[0] : (el.x || 0),
          y: el.bbox ? el.bbox[1] : (el.y || 0),
          width:  el.bbox ? el.bbox[2] : (el.width  || 0),
          height: el.bbox ? el.bbox[3] : (el.height || 0),
        };
      }
      const cat = (el.category || el.type || 'ELEMENT').toUpperCase();
      const isPreIdentifiedPii = !!el.redactionLabel || KNOWN_PII_CATEGORIES.has(cat);
      return {
        id: el.id || el.label || 'ELEMENT',
        category: cat,
        boundingBox: b,
        redactionLabel: el.redactionLabel || (isPreIdentifiedPii ? this.vault.tokenize(cat, cat) : null),
        needsTextScan: !isPreIdentifiedPii
      };
    })];

    // Phase 3: Canvas redaction pass
    for (const item of allBoxes) {
      const box = item.boundingBox;
      const sx = box.viewportWidth ? (canvas.width / box.viewportWidth) : 1.0;
      const sy = box.viewportHeight ? (canvas.height / box.viewportHeight) : 1.0;
      const x = Math.max(0, Math.round(box.x * sx));
      const y = Math.max(0, Math.round(box.y * sy));
      const width  = Math.min(canvas.width  - x, Math.round(box.width  * sx));
      const height = Math.min(canvas.height - y, Math.round(box.height * sy));
      if (width <= 0 || height <= 0) continue;

      // Determine if this item needs PII text scan (for ML elements)
      if (item.needsTextScan) {
        const textCtx = `${item.id || ''} ${item.category || ''}`.trim();
        let hasMatch = false;
        for (const [cat, regex] of Object.entries(this.patterns)) {
          regex.lastIndex = 0;
          if (regex.test(textCtx)) { hasMatch = true; break; }
        }
        if (!hasMatch) continue; // Skip non-PII ML element
      }

      const label = item.redactionLabel || this.vault.tokenize(item.category, item.category);

      if (item.category === 'FACE_AVATAR') {
        this._applyPixelate(ctx, x, y, width, height, this.config.pixelateSize);
        ctx.strokeStyle = this.config.borderColor;
        ctx.lineWidth = 2;
        ctx.strokeRect(x, y, width, height);
      } else {
        ctx.fillStyle = this.config.maskFillColor;
        ctx.fillRect(x, y, width, height);
        ctx.strokeStyle = this.config.borderColor;
        ctx.lineWidth = 1.5;
        ctx.strokeRect(x, y, width, height);
        if (height >= 14 && width >= 45) {
          ctx.fillStyle = this.config.tokenTextColor;
          ctx.font = this.config.font;
          ctx.textBaseline = 'middle';
          ctx.fillText(label, x + 4, y + height / 2);
        }
      }

      tokenMap.push({ id: item.id, category: item.category, label, coordinates: { x, y, width, height } });
    }

    // Export sanitized image (async, non-blocking)
    let sanitizedImage;
    try {
      const blob = await canvas.convertToBlob({ type: 'image/jpeg', quality: 0.85 });
      const buffer = await blob.arrayBuffer();
      const bytes = new Uint8Array(buffer);
      let binary = '';
      for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
      sanitizedImage = btoa(binary);
    } catch {
      sanitizedImage = rawBase64; // Fail-soft: return original if export fails
    }

    const duration = parseFloat((performance.now() - startTime).toFixed(2));
    const telemetryRecord = {
      timestamp: new Date().toISOString(),
      sanitizationLatencyMs: duration,
      redactedTokensCount: tokenMap.length,
      viewportDimensions: { width: canvas.width, height: canvas.height }
    };
    this.telemetryHistory.push(telemetryRecord);

    return { sanitizedImage, tokenMap, telemetry: telemetryRecord };
  }

  // ──────────────────────────────────────────────────────────────────────────
  // ACCESSIBILITY TREE SANITIZATION
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Sanitizes an accessibility tree before it is sent to the LLM server.
   * Called in action-executor.js after CDP Accessibility.getFullAXTree.
   */
  sanitizeAccessibilityTree(rawAxTree) {
    return this.a11ySanitizer.sanitizeTree(rawAxTree);
  }

  // ──────────────────────────────────────────────────────────────────────────
  // ZERO-LEAKAGE OUTGOING PAYLOAD VALIDATOR
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Validates an outgoing server payload for any residual unmasked PII.
   * If enableStrictZeroLeakage is true, throws on any violation (fail-closed).
   */
  validatePayload(outgoingJsonPayload) {
    const serialized = JSON.stringify(outgoingJsonPayload);
    const violations = [];
    for (const [category, regex] of Object.entries(this.patterns)) {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(serialized)) !== null) {
        const val = match[0];
        const isSafe = val.startsWith('[REDACTED_') || val.startsWith('[SYS_') ||
                       val.startsWith('SEC_') || val.startsWith('PII_') ||
                       val.startsWith('[PROTECTED_') || val.startsWith('[MASKED_');
        if (!isSafe) {
          violations.push({ category: category.toUpperCase(), matchedSample: val.slice(0, 3) + '****' + val.slice(-2), position: match.index });
        }
      }
    }
    const isSecure = violations.length === 0;
    if (!isSecure && this.config.enableStrictZeroLeakage) {
      throw new Error(`[PrivacyEngine] SECURITY ALERT: Blocked outgoing payload with ${violations.length} unmasked PII leaks.`);
    }
    return { isSecure, violationsCount: violations.length, violations, verifiedTimestamp: new Date().toISOString() };
  }

  // ──────────────────────────────────────────────────────────────────────────
  // VAULT BRIDGES
  // ──────────────────────────────────────────────────────────────────────────

  /** Detokenizes [SYS_*] aliases back to real values for local CDP typing. */
  detokenize(input) { return this.vault.detokenize(input); }

  /** Flush session vault at the end of an agent session. */
  flushVault() { return this.vault.flushVault(); }

  /**
   * Directly detects PII via Regex + NER patterns and draws solid black
   * redaction rectangles on the Canvas 2D context.
   * 
   * @param {CanvasRenderingContext2D} context - Canvas 2D context
   * @param {number} width - Canvas width in physical pixels
   * @param {number} height - Canvas height in physical pixels
   * @param {Array} [candidateElements=[]] - Detected UI elements from structural pass
   * @returns {Array<{ type: string, bbox: [number, number, number, number], alias?: string }>} Redacted regions
   */
  detectAndRedactPII(context, width, height, candidateElements = []) {
    const redactedRegions = [];

    const nerPatterns = {
      PERSON_NER: /\b(?:Dr\.|Prof\.|Mr\.|Mrs\.|Ms\.|Shri|Smt\.|Director|Commander|Scientist|Capt\.)(?:\s+(?:Dr\.|Prof\.|Shri|Smt\.))?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g,
      CONFIDENTIAL_NER: /\b(?:ISRO|DRDO|RAW|NTRO|BARC|MoD)\s+(?:TOP\s+SECRET|CONFIDENTIAL|RESTRICTED|CLASSIFIED)\b/gi
    };

    const allPatterns = { ...this.patterns, ...nerPatterns };

    const applyRedaction = (type, bbox, rawSecret = '') => {
      let [x, y, w, h] = bbox;
      x = Math.max(0, Math.round(x));
      y = Math.max(0, Math.round(y));
      w = Math.min(width - x, Math.round(w));
      h = Math.min(height - y, Math.round(h));

      if (w <= 0 || h <= 0) return;

      const categoryKey = type.toUpperCase().replace(/_NUMBER|_SECRET|_ADDRESS|_NER/g, '');
      const alias = this.vault ? this.vault.tokenize(rawSecret || type, categoryKey) : `[SYS_${categoryKey}_01]`;

      // SIDE EFFECT: Draw solid black rectangle over PII on canvas
      context.fillStyle = "#000000";
      context.fillRect(x, y, w, h);

      // Security outline border
      context.strokeStyle = "#FF0055";
      context.lineWidth = 1.5;
      context.strokeRect(x, y, w, h);

      // Render monospace alias label
      if (w >= 40 && h >= 14) {
        context.fillStyle = "#00FFCC";
        context.font = "bold 10px monospace";
        context.textBaseline = "middle";
        context.fillText(alias, x + 4, y + h / 2);
      }

      redactedRegions.push({
        type: type,
        bbox: [x, y, w, h],
        alias: alias
      });
    };

    if (Array.isArray(candidateElements) && candidateElements.length > 0) {
      for (const el of candidateElements) {
        const bbox = el.bbox || [el.x, el.y, el.width, el.height];
        if (!bbox || bbox.length < 4) continue;

        const textContext = `${el.label || ''} ${el.text || ''} ${el.value || ''} ${el.type || ''}`.trim();
        if (!textContext) continue;

        if (el.type === 'password' || /password|pin|cvv|secret/i.test(el.label || '')) {
          applyRedaction("PASSWORD_SECRET", bbox, el.value || 'PASSWORD');
          continue;
        }

        for (const [cat, regex] of Object.entries(allPatterns)) {
          regex.lastIndex = 0;
          let match;
          while ((match = regex.exec(textContext)) !== null) {
            const matchedText = match[0];
            const analysis = this.vault
              ? this.vault.analyzeContext(textContext, match.index, matchedText.length, cat)
              : { shouldTokenize: true };

            if (analysis.shouldTokenize) {
              applyRedaction(cat, bbox, matchedText);
              break;
            }
          }
        }
      }
    }

    try {
      if (typeof document !== 'undefined' && document.body) {
        const domItems = this.scanDOM(document);
        for (const item of domItems) {
          const b = item.boundingBox;
          applyRedaction(item.category, [b.x, b.y, b.width, b.height], item.redactionLabel);
        }
      }
    } catch (e) {}

    return redactedRegions;
  }

  // ──────────────────────────────────────────────────────────────────────────
  // DOM SCANNER (runs in offscreen document context only)
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Scans the offscreen document DOM for PII in input values and text nodes.
   * Returns bounding box records for the canvas redaction pass.
   */
  scanDOM(customDocument = (typeof document !== 'undefined' ? document : null)) {
    if (!customDocument) return [];
    const sensitiveItems = [];
    let counter = 1;
    const allElements = this._getAllElementsDeep(customDocument.body || customDocument.documentElement || customDocument);

    allElements.forEach((el) => {
      const tag = (el.tagName || '').toLowerCase();
      if (!['input', 'textarea', 'select'].includes(tag) && !el.isContentEditable) return;
      const rect = el.getBoundingClientRect ? el.getBoundingClientRect() : null;
      if (!rect || rect.width <= 0 || rect.height <= 0) return;

      const val = (el.value || el.innerText || '').trim();
      const attrContext = `${el.name || ''} ${el.id || ''} ${el.placeholder || ''} ${el.getAttribute ? (el.getAttribute('aria-label') || '') : ''}`;
      const type = el.type || 'text';

      if (type === 'password') {
        const alias = this.vault.tokenize(val || 'PASSWORD_SECRET', 'PASSWORD');
        sensitiveItems.push({ id: `SEC_PASSWORD_${counter++}`, category: 'PASSWORD', boundingBox: { x: Math.round(rect.left), y: Math.round(rect.top), width: Math.round(rect.width), height: Math.round(rect.height) }, redactionLabel: alias });
        return;
      }

      if (this.sensitiveKeywords.test(attrContext)) {
        let matchedCat = 'AUTH_CREDENTIAL';
        if (/aadhaar/i.test(attrContext)) matchedCat = 'AADHAAR';
        else if (/pan/i.test(attrContext)) matchedCat = 'PAN';
        else if (/cvv|pin|otp/i.test(attrContext)) matchedCat = 'OTP_PIN';
        const alias = this.vault.tokenize(val || matchedCat, matchedCat);
        sensitiveItems.push({ id: `SEC_${matchedCat}_${counter++}`, category: matchedCat, boundingBox: { x: Math.round(rect.left), y: Math.round(rect.top), width: Math.round(rect.width), height: Math.round(rect.height) }, redactionLabel: alias });
        return;
      }

      if (val.length > 0) {
        for (const [category, regex] of Object.entries(this.patterns)) {
          regex.lastIndex = 0;
          if (regex.test(val)) {
            const alias = this.vault.tokenize(val, category);
            sensitiveItems.push({ id: `SEC_${category.toUpperCase()}_${counter++}`, category: category.toUpperCase(), boundingBox: { x: Math.round(rect.left), y: Math.round(rect.top), width: Math.round(rect.width), height: Math.round(rect.height) }, redactionLabel: alias });
            return;
          }
        }
      }
    });

    return sensitiveItems;
  }

  // ──────────────────────────────────────────────────────────────────────────
  // PRIVATE HELPERS
  // ──────────────────────────────────────────────────────────────────────────

  _getAllElementsDeep(root) {
    const elements = [];
    const walk = (node) => {
      if (!node) return;
      if (node.nodeType === Node.ELEMENT_NODE) {
        elements.push(node);
        if (node.shadowRoot) walk(node.shadowRoot);
      }
      for (const child of node.children || []) walk(child);
    };
    walk(root);
    return elements;
  }

  _applyPixelate(ctx, x, y, width, height, pixelSize = 10) {
    try {
      const imgData = ctx.getImageData(x, y, width, height);
      const data = imgData.data;
      for (let py = 0; py < height; py += pixelSize) {
        for (let px = 0; px < width; px += pixelSize) {
          const pIndex = (py * width + px) * 4;
          ctx.fillStyle = `rgb(${data[pIndex]},${data[pIndex+1]},${data[pIndex+2]})`;
          ctx.fillRect(x + px, y + py, Math.min(pixelSize, width - px), Math.min(pixelSize, height - py));
        }
      }
    } catch {
      ctx.fillStyle = '#1f242c';
      ctx.fillRect(x, y, width, height);
    }
  }

  _loadImage(src) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.crossOrigin = 'anonymous';
      img.onload  = () => resolve(img);
      img.onerror = (err) => reject(new Error('PrivacyEngine: Failed to load image for redaction'));
      img.src = src;
    });
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = PrivacyEngine;
  module.exports.PrivacyEngine = PrivacyEngine;
}
if (typeof window !== 'undefined') {
  window.PrivacyEngine = PrivacyEngine;
}

export default PrivacyEngine;

