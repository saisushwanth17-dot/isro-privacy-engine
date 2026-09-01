/**
 * ISRO PS 171 - On-Device Privacy & PII Redaction Engine
 * Module: accessibility_sanitizer.js
 */

class AccessibilitySanitizer {
  constructor(patterns) {
    this.patterns = patterns || {
      aadhaar: /(?<!\d)[2-9]{1}[0-9]{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}(?!\d)/g,
      pan: /\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b/g,
      creditCard: /(?<!\d)(?:\d{4}[\s\-]?){3}\d{4}(?!\d)|(?<!\d)\d{15,16}(?!\d)/g,
      indianPhone: /(?<!\d)(?:\+91[\-\s]?)?[6-9]\d{9}(?!\d)/g,
      email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
      upiId: /\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b/g
    };
  }

  sanitizeTree(axTree) {
    if (!axTree) return null;
    let counter = 1;

    const sanitizeNode = (node) => {
      if (!node) return null;
      const cleanNode = { ...node };

      const isProtected = 
        cleanNode.role === 'password' ||
        cleanNode.role === 'securefield' ||
        (cleanNode.name && /password|cvv|otp|pin|aadhaar|pan/i.test(cleanNode.name)) ||
        (cleanNode.description && /password|cvv|otp|pin/i.test(cleanNode.description));

      if (isProtected) {
        cleanNode.name = `[REDACTED_SECURE_FIELD_#${counter++}]`;
        cleanNode.value = '[PROTECTED_SECRET]';
        cleanNode.description = '[MASKED_CREDENTIAL]';
      } else {
        if (typeof cleanNode.name === 'string') {
          cleanNode.name = this._maskPIIString(cleanNode.name);
        }
        if (typeof cleanNode.value === 'string') {
          cleanNode.value = this._maskPIIString(cleanNode.value);
        }
        if (typeof cleanNode.description === 'string') {
          cleanNode.description = this._maskPIIString(cleanNode.description);
        }
      }

      if (Array.isArray(cleanNode.children)) {
        cleanNode.children = cleanNode.children.map(child => sanitizeNode(child));
      }

      return cleanNode;
    };

    return sanitizeNode(axTree);
  }

  _maskPIIString(str) {
    if (!str || typeof str !== 'string') return str;
    let sanitized = str;
    for (const [category, regex] of Object.entries(this.patterns)) {
      regex.lastIndex = 0;
      sanitized = sanitized.replace(regex, () => `[REDACTED_${category.toUpperCase()}]`);
    }
    return sanitized;
  }
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = AccessibilitySanitizer;
}
if (typeof window !== 'undefined') {
  window.AccessibilitySanitizer = AccessibilitySanitizer;
}

export { AccessibilitySanitizer };
export default AccessibilitySanitizer;
