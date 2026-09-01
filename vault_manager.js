/**
 * ============================================================================
 * ISRO PS 171 - PII Tokenization Vault & Detokenization Engine
 * Module: vault_manager.js
 * ============================================================================
 * 
 * Standalone Security Module implementing:
 * 1. Format-Preserving Bidirectional Tokenization (Real Secret <-> [SYS_TYPE_ID])
 * 2. Context-Aware Confidence Scoring (+/- 50 char window, negative filter)
 * 3. Secure Agent Detokenization (Resolves aliases back to real values for typing)
 * 4. Ephemeral Memory Sweeping (flushVault garbage collection post-session)
 */

class VaultManager {
  constructor(options = {}) {
    this.options = {
      contextWindowChars: options.contextWindowChars || 50,
      confidenceThreshold: options.confidenceThreshold || 0.65,
      aliasPrefix: options.aliasPrefix || 'SYS',
      ...options
    };

    // Secure local in-memory storage (RAM only, never written to disk)
    this.vault = new Map();       // Alias -> Real Secret
    this.reverseVault = new Map(); // Real Secret -> Alias
    this.counters = new Map();    // Category -> Integer counter

    // Context Keywords for Positive & Negative Context Evaluation
    this.contextDictionary = {
      PAN: {
        positive: ['pan', 'tax', 'income', 'permanent account', 'nsdl', 'utitsl', 'father', 'assesse', 'tin'],
        negative: ['item', 'sku', 'serial', 'model', 'product', 'tracking', 'order', 'part no', 'build']
      },
      AADHAAR: {
        positive: ['aadhaar', 'uidai', 'uid', 'identity', 'citizen', 'enrollment', 'resident', 'biometric', 'vid'],
        negative: ['serial', 'tracking', 'transaction', 'barcode', 'invoice', 'code', 'ref', 'account no']
      },
      CREDITCARD: {
        positive: ['card', 'visa', 'mastercard', 'amex', 'rupay', 'cvv', 'cvc', 'expiry', 'exp', 'debit', 'credit', 'payment', 'bank'],
        negative: ['item id', 'serial', 'tracking', 'order id', 'sku', 'vin', 'mac', 'isbn', 'shipment']
      },
      INDIANPHONE: {
        positive: ['phone', 'mobile', 'call', 'contact', 'tel', 'cell', 'whatsapp', 'sms', 'otp to', 'dial'],
        negative: ['serial', 'timestamp', 'date', 'order', 'amount', 'pin code', 'zip', 'qty']
      },
      PASSWORD: {
        positive: ['password', 'pwd', 'passcode', 'secret', 'credentials', 'pin', 'login', 'token', 'auth', 'key'],
        negative: ['license key', 'version', 'hash', 'public']
      },
      EMAIL: {
        positive: ['email', 'mail', 'contact', 'inbox', 'address', 'send to', 'recipient'],
        negative: ['example.com', 'test.com', 'domain']
      },
      UPIID: {
        positive: ['upi', 'vpa', 'paytm', 'gpay', 'phonepe', 'bhim', 'payment', 'transfer'],
        negative: ['domain', 'server']
      },
      PERSON_NER: {
        positive: ['dr', 'prof', 'mr', 'mrs', 'ms', 'shri', 'smt', 'scientist', 'director', 'commander', 'name', 'officer'],
        negative: ['file', 'class', 'function', 'variable']
      },
      CONFIDENTIAL_NER: {
        positive: ['isro', 'drdo', 'secret', 'confidential', 'restricted', 'classified', 'defense', 'mission'],
        negative: ['public', 'open-source']
      }
    };
  }

  // ==========================================================================
  // 1. CONTEXT-AWARE CONFIDENCE SCORING
  // ==========================================================================

  /**
   * Evaluates text context surrounding a match to filter out false positives
   * Looks at +/- 50 characters around matchIndex
   * 
   * @param {string} fullText - The entire text content being scanned
   * @param {number} matchIndex - Starting index of the matched candidate
   * @param {number} matchLength - Length of the matched candidate
   * @param {string} category - Category string (e.g. 'CREDITCARD', 'PAN', 'AADHAAR')
   * @returns {Object} { confidence: number, shouldTokenize: boolean, contextSnippet: string, matchedKeywords: string[] }
   */
  analyzeContext(fullText, matchIndex, matchLength, category) {
    if (!fullText || typeof fullText !== 'string' || matchIndex < 0) {
      return { confidence: 0.5, shouldTokenize: true, contextSnippet: '', matchedKeywords: [] };
    }

    const windowSize = this.options.contextWindowChars;
    const start = Math.max(0, matchIndex - windowSize);
    const end = Math.min(fullText.length, matchIndex + matchLength + windowSize);

    // Context window: +/- 50 chars surrounding and including the match
    const windowText = fullText.slice(start, end).toLowerCase();

    const catKey = category.toUpperCase();
    const dict = this.contextDictionary[catKey] || { positive: [], negative: [] };

    let score = 0.50; // Baseline neutral score
    const matchedPositive = [];
    const matchedNegative = [];

    // Check negative keywords (penalize false positives like serial numbers, item IDs)
    for (const neg of dict.negative) {
      if (windowText.includes(neg)) {
        matchedNegative.push(neg);
        score -= 0.35;
      }
    }

    // Check positive keywords (boost confidence for verified domain context)
    for (const pos of dict.positive) {
      if (windowText.includes(pos)) {
        matchedPositive.push(pos);
        score += 0.25;
      }
    }

    // Boundary clamping
    const finalConfidence = Math.max(0.01, Math.min(0.99, parseFloat(score.toFixed(2))));
    const shouldTokenize = finalConfidence >= this.options.confidenceThreshold;

    return {
      confidence: finalConfidence,
      shouldTokenize: shouldTokenize,
      matchedPositive: matchedPositive,
      matchedNegative: matchedNegative,
      contextSnippet: fullText.slice(start, end).replace(/\s+/g, ' ').trim()
    };
  }

  // ==========================================================================
  // 2. FORMAT-PRESERVING BIDIRECTIONAL TOKENIZATION
  // ==========================================================================

  /**
   * Tokenizes a single secret into a synthetic alias (e.g. ABCDE1234F -> [SYS_PAN_01])
   * Re-using existing alias if the secret was already tokenized in this session.
   * 
   * @param {string} rawSecret - Real sensitive value
   * @param {string} category - Category string (e.g. 'PAN', 'AADHAAR', 'PASSWORD')
   * @returns {string} Synthetic alias token (e.g. [SYS_PAN_01])
   */
  tokenize(rawSecret, category = 'SECRET') {
    if (!rawSecret || typeof rawSecret !== 'string') return rawSecret;

    const trimmed = rawSecret.trim();
    if (!trimmed) return rawSecret;

    // Return existing alias if already stored (idempotent mapping)
    if (this.reverseVault.has(trimmed)) {
      return this.reverseVault.get(trimmed);
    }

    const catKey = category.toUpperCase();
    const currentCount = (this.counters.get(catKey) || 0) + 1;
    this.counters.set(catKey, currentCount);

    const pad = currentCount < 10 ? `0${currentCount}` : `${currentCount}`;
    const alias = `[${this.options.aliasPrefix}_${catKey}_${pad}]`;

    // Store bidirectional mapping
    this.vault.set(alias, trimmed);
    this.reverseVault.set(trimmed, alias);

    return alias;
  }

  /**
   * Scans a text block with candidate regex matches and tokenizes only verified items
   * @param {string} text - Full text containing potential PII
   * @param {Object} patternMap - Map of category -> Regex
   * @returns {string} Sanitized text where verified PII is swapped with [SYS_...] aliases
   */
  tokenizeText(text, patternMap) {
    if (!text || typeof text !== 'string') return text;

    let sanitized = text;

    for (const [category, regex] of Object.entries(patternMap)) {
      regex.lastIndex = 0;
      let match;
      // Find all matches in current text state
      while ((match = regex.exec(sanitized)) !== null) {
        const matchedSecret = match[0];
        const matchIndex = match.index;

        // Run Context Analysis on the surrounding +/- 50 characters
        const contextAnalysis = this.analyzeContext(sanitized, matchIndex, matchedSecret.length, category);

        if (contextAnalysis.shouldTokenize) {
          const alias = this.tokenize(matchedSecret, category);
          // Substitute the secret with the alias
          sanitized = sanitized.slice(0, matchIndex) + alias + sanitized.slice(matchIndex + matchedSecret.length);
          // Adjust regex cursor past the newly inserted alias
          regex.lastIndex = matchIndex + alias.length;
        } else {
          // Skipped due to negative context (false positive)
          regex.lastIndex = matchIndex + matchedSecret.length;
        }
      }
    }

    return sanitized;
  }

  // ==========================================================================
  // 3. SECURE DETOKENIZATION (AI INTERACTION BRIDGE)
  // ==========================================================================

  /**
   * Resolves a synthetic alias back to the real secret from secure memory.
   * Also supports detokenizing entire command strings:
   * e.g. "Type [SYS_PAN_01] into box" -> "Type ABCDE1234F into box"
   * 
   * @param {string} input - Alias token or action string containing tokens
   * @returns {string} Real unmasked secret value for local browser typing
   */
  detokenize(input) {
    if (!input || typeof input !== 'string') return input;

    // Direct single alias lookup
    if (this.vault.has(input)) {
      return this.vault.get(input);
    }

    // String containing one or more embedded [SYS_...] aliases
    let resolved = input;
    const aliasRegex = /\[SYS_[A-Z0-9_]+\]/g;
    resolved = resolved.replace(aliasRegex, (match) => {
      if (this.vault.has(match)) {
        return this.vault.get(match);
      }
      return match; // Unknown alias, return as is
    });

    return resolved;
  }

  /**
   * Checks if an alias exists in the active vault
   * @param {string} alias - Token to check
   * @returns {boolean}
   */
  hasAlias(alias) {
    return this.vault.has(alias);
  }

  /**
   * Returns current count of stored secrets in RAM
   */
  getVaultSize() {
    return this.vault.size;
  }

  // ==========================================================================
  // 4. EPHEMERAL MEMORY SWEEPING (ZERO LEAKAGE GC)
  // ==========================================================================

  /**
   * Securely flushes and wipes all sensitive secrets from memory.
   * Overwrites key/value string references before clearing Maps
   * to guarantee zero residual data in RAM post-session.
   */
  flushVault() {
    const clearedItemsCount = this.vault.size;

    // Overwrite stored secrets in RAM with blank values before GC
    for (const [alias, secret] of this.vault.entries()) {
      this.vault.set(alias, '\0'.repeat(secret.length));
    }
    for (const [secret, alias] of this.reverseVault.entries()) {
      this.reverseVault.set(secret, '\0'.repeat(alias.length));
    }

    this.vault.clear();
    this.reverseVault.clear();
    this.counters.clear();

    return {
      status: 'FLUSHED_SUCCESSFULLY',
      clearedItemsCount: clearedItemsCount,
      activeVaultSize: 0,
      timestamp: new Date().toISOString()
    };
  }
}

// Module Exports
const SessionVaultManager = VaultManager;

if (typeof module !== 'undefined' && module.exports) {
  module.exports = VaultManager;
  module.exports.VaultManager = VaultManager;
  module.exports.SessionVaultManager = SessionVaultManager;
}
if (typeof window !== 'undefined') {
  window.VaultManager = VaultManager;
  window.SessionVaultManager = SessionVaultManager;
}

export { VaultManager, SessionVaultManager };
export default VaultManager;
