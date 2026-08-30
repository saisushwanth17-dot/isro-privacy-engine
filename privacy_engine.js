/**
 * ISRO PS 171 - On-Device Privacy & PII Redaction Engine
 * Module: privacy_engine.js (Shadow DOM & Dynamic Search Support)
 */

class PrivacyEngine {
  constructor(config = {}) {
    this.config = {
      maskFillColor: config.maskFillColor || '#0a0a0c',
      tokenTextColor: config.tokenTextColor || '#00ffcc',
      borderColor: config.borderColor || '#ff0055',
      font: config.font || 'bold 11px "Courier New", monospace',
      pixelateSize: config.pixelateSize || 12,
      enableStrictZeroLeakage: config.enableStrictZeroLeakage !== false,
      ...config
    };

    this.patterns = {
      aadhaar: /(?<!\d)[2-9]{1}[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}(?!\d)/g,
      pan: /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g,
      creditCard: /(?<!\d)(?:\d{4}[\s\-]?){3}\d{4}(?!\d)|(?<!\d)\d{15,16}(?!\d)/g,
      indianPhone: /(?<!\d)(?:\+91[\-\s]?)?[6-9]\d{9}(?!\d)/g,
      email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
      upiId: /\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b/g,
      passport: /\b[A-Z]{1}[0-9]{7}\b/g,
      drivingLicense: /\b[A-Z]{2}[0-9]{2}[0-9]{11}\b/g
    };

    this.sensitiveKeywords = /password|cvv|otp|pin|aadhaar|pan|card|secret|token|ssn|license/i;

    const A11yClass = (typeof AccessibilitySanitizer !== 'undefined') ? AccessibilitySanitizer : (typeof require !== 'undefined' ? require('./accessibility_sanitizer.js') : null);
    this.a11ySanitizer = A11yClass ? new A11yClass(this.patterns) : null;

    // Vault Manager: Bidirectional Format-Preserving Tokenizer & Detokenizer
    const VaultClass = (typeof VaultManager !== 'undefined') ? VaultManager : (typeof require !== 'undefined' ? require('./vault_manager.js') : null);
    this.vault = VaultClass ? new VaultClass({ aliasPrefix: 'SYS' }) : null;

    this.telemetryHistory = [];
  }

  /**
   * Detokenizes a synthetic alias or command string using the secure vault
   * e.g. "Type [SYS_PAN_01] into box" -> "Type ABCDE1234F into box"
   */
  detokenize(input) {
    return this.vault ? this.vault.detokenize(input) : input;
  }

  /**
   * Flushes and securely wipes the in-memory Vault
   */
  flushVault() {
    return this.vault ? this.vault.flushVault() : { status: 'NO_VAULT' };
  }

  /**
   * Recursively finds all elements across open Shadow Roots
   */
  _getAllElementsDeep(root = document) {
    const elements = [];
    const walk = (node) => {
      if (!node) return;
      if (node.nodeType === Node.ELEMENT_NODE) {
        elements.push(node);
        if (node.shadowRoot) {
          walk(node.shadowRoot);
        }
      }
      for (const child of node.children || []) {
        walk(child);
      }
    };
    walk(root);
    return elements;
  }

  scanDOM(customDocument = (typeof document !== 'undefined' ? document : null)) {
    if (!customDocument) return [];
    const sensitiveItems = [];
    let counter = 1;

    // 1. Scan across standard DOM AND Shadow DOM (YouTube, Polymer, React components)
    const allElements = this._getAllElementsDeep(customDocument.body || customDocument.documentElement || customDocument);

    allElements.forEach((el) => {
      const tag = (el.tagName || '').toLowerCase();

      // A. Check Inputs, Textareas, Search boxes
      if (tag === 'input' || tag === 'textarea' || tag === 'select' || el.isContentEditable) {
        const rect = el.getBoundingClientRect();
        if (rect.width <= 0 || rect.height <= 0 || rect.bottom <= 0 || rect.right <= 0) return;

        const val = (el.value || el.innerText || '').trim();
        const placeholder = el.placeholder || '';
        const nameAttr = el.name || '';
        const idAttr = el.id || '';
        const ariaLabel = el.getAttribute('aria-label') || '';
        const type = el.type || 'text';

        // Password input
        if (type === 'password') {
          const alias = this.vault ? this.vault.tokenize(val || 'PASSWORD_SECRET', 'PASSWORD') : `[SYS_PASSWORD_${counter}]`;
          sensitiveItems.push({
            id: `SEC_PASSWORD_${counter++}`,
            type: 'INPUT_FIELD',
            category: 'PASSWORD',
            boundingBox: { x: Math.round(rect.left), y: Math.round(rect.top), width: Math.round(rect.width), height: Math.round(rect.height) },
            redactionLabel: alias
          });
          return;
        }

        // Sensitive attribute keywords
        const attrContext = `${nameAttr} ${idAttr} ${placeholder} ${ariaLabel}`;
        if (this.sensitiveKeywords.test(attrContext)) {
          let matchedCat = 'AUTH_CREDENTIAL';
          if (/aadhaar/i.test(attrContext)) matchedCat = 'AADHAAR';
          else if (/pan/i.test(attrContext)) matchedCat = 'PAN';
          else if (/cvv|pin|otp/i.test(attrContext)) matchedCat = 'OTP_PIN';

          const alias = this.vault ? this.vault.tokenize(val || matchedCat, matchedCat) : `[SYS_${matchedCat}_${counter}]`;
          sensitiveItems.push({
            id: `SEC_${matchedCat}_${counter++}`,
            type: 'INPUT_FIELD',
            category: matchedCat,
            boundingBox: { x: Math.round(rect.left), y: Math.round(rect.top), width: Math.round(rect.width), height: Math.round(rect.height) },
            redactionLabel: alias
          });
          return;
        }

        // Check if dynamic user typed text (e.g. Email in search) matches ANY PII regex!
        if (val.length > 0) {
          for (const [category, regex] of Object.entries(this.patterns)) {
            regex.lastIndex = 0;
            if (regex.test(val)) {
              const alias = this.vault ? this.vault.tokenize(val, category) : `[SYS_${category.toUpperCase()}_${counter}]`;
              sensitiveItems.push({
                id: `SEC_${category.toUpperCase()}_${counter++}`,
                type: 'INPUT_FIELD',
                category: category.toUpperCase(),
                boundingBox: { x: Math.round(rect.left), y: Math.round(rect.top), width: Math.round(rect.width), height: Math.round(rect.height) },
                redactionLabel: alias
              });
              return;
            }
          }
        }
      }

      // B. Check Profile Avatars & Images
      if (tag === 'img' || el.getAttribute('role') === 'img' || /avatar|profile|user-photo/i.test(el.className)) {
        const isAvatar = /avatar|profile|user|photo|badge/i.test((el.className || '') + ' ' + (el.id || '') + ' ' + (el.src || ''));
        if (isAvatar) {
          const rect = el.getBoundingClientRect();
          if (rect.width > 20 && rect.height > 20) {
            sensitiveItems.push({
              id: `FACE_AVATAR_${counter++}`,
              type: 'MEDIA_PII',
              category: 'FACE_AVATAR',
              boundingBox: { x: Math.round(rect.left), y: Math.round(rect.top), width: Math.round(rect.width), height: Math.round(rect.height) },
              redactionLabel: `[REDACTED_AVATAR_#${counter - 1}]`
            });
          }
        }
      }
    });

    // 2. Scan Text Nodes via TreeWalker
    try {
      const walker = customDocument.createTreeWalker(
        customDocument.body || customDocument.documentElement,
        NodeFilter.SHOW_TEXT,
        {
          acceptNode: (node) => {
            if (!node.nodeValue || node.nodeValue.trim().length === 0) return NodeFilter.FILTER_REJECT;
            const parent = node.parentElement;
            if (!parent) return NodeFilter.FILTER_REJECT;
            const tag = parent.tagName.toLowerCase();
            if (['script', 'style', 'noscript', 'svg'].includes(tag)) return NodeFilter.FILTER_REJECT;
            return NodeFilter.FILTER_ACCEPT;
          }
        }
      );

      let currentNode;
      while ((currentNode = walker.nextNode())) {
        const text = currentNode.nodeValue;
        const parent = currentNode.parentElement;
        if (!parent) continue;

        for (const [category, regex] of Object.entries(this.patterns)) {
          regex.lastIndex = 0;
          let match;
          while ((match = regex.exec(text)) !== null) {
            const matchedStr = match[0];
            const alias = this.vault ? this.vault.tokenize(matchedStr, category) : `[SYS_${category.toUpperCase()}_${counter}]`;
            try {
              const range = customDocument.createRange();
              range.setStart(currentNode, match.index);
              range.setEnd(currentNode, match.index + matchedStr.length);
              const rect = range.getBoundingClientRect();
              if (rect.width > 0 && rect.height > 0) {
                sensitiveItems.push({
                  id: `PII_${category.toUpperCase()}_${counter++}`,
                  type: 'TEXT_PII',
                  category: category.toUpperCase(),
                  boundingBox: {
                    x: Math.round(rect.left),
                    y: Math.round(rect.top),
                    width: Math.round(rect.width),
                    height: Math.round(rect.height)
                  },
                  redactionLabel: alias
                });
              }
            } catch (err) {
              const pRect = parent.getBoundingClientRect();
              sensitiveItems.push({
                id: `PII_${category.toUpperCase()}_${counter++}`,
                type: 'TEXT_PII',
                category: category.toUpperCase(),
                boundingBox: {
                  x: Math.round(pRect.left),
                  y: Math.round(pRect.top),
                  width: Math.round(pRect.width),
                  height: Math.round(pRect.height)
                },
                redactionLabel: alias
              });
            }
          }
        }
      }
    } catch (e) {}

    return sensitiveItems;
  }

  async sanitizeViewport(rawScreenshot, customMlBoxes = [], scaleFactor = 1.0) {
    const startTime = performance.now();
    const domBoxes = this.scanDOM();
    const allBoxes = [...domBoxes, ...customMlBoxes];

    const img = await this._loadImage(rawScreenshot);
    const canvas = document.createElement('canvas');
    canvas.width = img.naturalWidth || img.width;
    canvas.height = img.naturalHeight || img.height;
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(img, 0, 0);

    const tokenMap = [];
    const scale = scaleFactor || 1.0;

    for (const item of allBoxes) {
      const box = item.boundingBox;
      const x = Math.max(0, Math.round(box.x * scale));
      const y = Math.max(0, Math.round(box.y * scale));
      const width = Math.min(canvas.width - x, Math.round(box.width * scale));
      const height = Math.min(canvas.height - y, Math.round(box.height * scale));

      if (width <= 0 || height <= 0) continue;

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
          const label = item.redactionLabel || `[REDACTED]`;
          ctx.fillText(label, x + 4, y + height / 2);
        }
      }

      tokenMap.push({
        id: item.id,
        category: item.category,
        label: item.redactionLabel,
        coordinates: { x, y, width, height }
      });
    }

    const sanitizedBase64 = canvas.toDataURL('image/webp', 0.85);
    const duration = parseFloat((performance.now() - startTime).toFixed(2));
    const telemetryRecord = {
      timestamp: new Date().toISOString(),
      sanitizationLatencyMs: duration,
      redactedTokensCount: tokenMap.length,
      viewportDimensions: { width: canvas.width, height: canvas.height }
    };
    this.telemetryHistory.push(telemetryRecord);

    return {
      sanitizedImage: sanitizedBase64,
      tokenMap: tokenMap,
      telemetry: telemetryRecord
    };
  }

  sanitizeAccessibilityTree(rawAccessibilityTree) {
    if (!this.a11ySanitizer) {
      const A11yClass = (typeof AccessibilitySanitizer !== 'undefined') ? AccessibilitySanitizer : (typeof require !== 'undefined' ? require('./accessibility_sanitizer.js') : null);
      this.a11ySanitizer = new A11yClass(this.patterns);
    }
    return this.a11ySanitizer.sanitizeTree(rawAccessibilityTree);
  }

  validatePayload(outgoingJsonPayload) {
    const serialized = JSON.stringify(outgoingJsonPayload);
    const violations = [];

    for (const [category, regex] of Object.entries(this.patterns)) {
      regex.lastIndex = 0;
      let match;
      while ((match = regex.exec(serialized)) !== null) {
        const val = match[0];
        if (!val.startsWith('[REDACTED_') && !val.startsWith('[SYS_') && !val.startsWith('SEC_') && !val.startsWith('PII_') && !val.startsWith('[PROTECTED_') && !val.startsWith('[MASKED_')) {
          violations.push({
            category: category.toUpperCase(),
            matchedSample: val.slice(0, 3) + '****' + val.slice(-2),
            position: match.index
          });
        }
      }
    }

    const isSecure = violations.length === 0;
    if (!isSecure && this.config.enableStrictZeroLeakage) {
      throw new Error(`[PrivacyEngine] Security Alert: Blocked outgoing payload with ${violations.length} unmasked PII leaks.`);
    }
    return {
      isSecure: isSecure,
      violationsCount: violations.length,
      violations: violations,
      verifiedTimestamp: new Date().toISOString()
    };
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
    } catch (e) {
      ctx.fillStyle = '#1f242c';
      ctx.fillRect(x, y, width, height);
    }
  }

  _loadImage(src) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.crossOrigin = 'anonymous';
      img.onload = () => resolve(img);
      img.onerror = (err) => reject(new Error('Failed to load image: ' + err));
      img.src = typeof src === 'string' ? src : src.src;
    });
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = PrivacyEngine;
}
if (typeof window !== 'undefined') {
  window.PrivacyEngine = PrivacyEngine;
}
