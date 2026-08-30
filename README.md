# ISRO PS 171 — Privacy Preserving & PII Redaction Engine (Member 3)

> **Component:** Client-Side Privacy Engine & PII Tokenization Vault  
> **Supports:** Chrome Extension Manifest V3 / WebGPU / WASM / Offline Agent Loop  
> **Coverage:** ISRO Evaluation Metric 2 (20% PII Recall), Metric 3 (20% Redaction Quality), Metric 5 (15% Low Latency)

---

## 📦 Package Contents

```
├── vault_manager.js          # PII Tokenization Vault (Format-Preserving Alias + Context Analyzer + Detokenizer)
├── privacy_engine.js         # Core Engine (DOM Scanner + Canvas Masker + Security Gate + Vault Bridge)
├── accessibility_sanitizer.js# Semantic Accessibility Tree Sanitizer
├── accessibility_walker.js   # Semantic A11y Tree Builder from Light & Shadow DOM
├── privacy_engine.d.ts       # Complete TypeScript Definitions & Type Safety
├── manifest.json             # Manifest V3 configuration for Chrome / Edge
├── background.js             # Background service worker for tab capture
├── content.js                # Content script bridge (Shadow DOM + dynamic input scanner)
├── popup.html / popup.js     # Live DevTools Inspector UI
├── popup.css                 # Cyber-security Dark Theme
├── verify_all.js             # Automated test suite (100% passing)
└── .gitignore                # Git ignore configuration
```

---

## 🏛️ Architecture: The Bidirectional PII Vault (`VaultManager`)

Instead of one-way redaction, the **PII Tokenization Vault** intercepts sensitive text, swaps it with mathematically generated synthetic aliases before reaching the AI model, and securely detokenizes it back when the AI agent interacts with the browser.

```
       USER BROWSER                                          AI AGENT (LLM)
┌─────────────────────────┐                            ┌─────────────────────────┐
│ Real PAN: "ABCDE1234F"  │───[ tokenize() ]──────────►│ Sees: "[SYS_PAN_01]"    │
│                         │                            │ (Zero PII Exposed)      │
│                         │                            │                         │
│ Browser Input Typed:    │◄──[ detokenize() ]─────────│ Action:                 │
│ "ABCDE1234F"            │   "Type [SYS_PAN_01]"      │ "Type [SYS_PAN_01]"     │
└─────────────────────────┘                            └─────────────────────────┘
```

---

## 🚀 How Member 1 & Core Agent Connects to `VaultManager`

### 1. Format-Preserving Tokenization (`tokenize`)
```javascript
import { VaultManager } from './vault_manager.js';
const vault = new VaultManager();

// Real secret -> Format-preserving alias
const alias = vault.tokenize('ABCDE1234F', 'PAN');
console.log(alias); // => "[SYS_PAN_01]"

// Re-using the same secret yields the same alias (idempotent):
console.log(vault.tokenize('ABCDE1234F', 'PAN')); // => "[SYS_PAN_01]"
```

---

### 2. Context-Aware Confidence Scoring (`analyzeContext`)
Regex alone produces false positives (e.g., a 16-digit order ID is not a credit card). `analyzeContext()` inspects a window of $\pm 50$ characters around the match:

```javascript
const text = "Payment details: Visa Credit Card 4532891234567890 Expiry 12/28 CVV 123";
const matchIndex = text.indexOf("4532891234567890");

const analysis = vault.analyzeContext(text, matchIndex, 16, 'CREDITCARD');
console.log(analysis);
// {
//   confidence: 0.99,
//   shouldTokenize: true,
//   matchedPositive: ['visa', 'card', 'credit', 'expiry', 'cvv'],
//   contextSnippet: "...Visa Credit Card 4532891234567890 Expiry 12/28 CVV..."
// }

// False positive example (ignored!):
const itemText = "Warehouse item ID 4532891234567890 in shipment";
const itemAnalysis = vault.analyzeContext(itemText, itemText.indexOf("4532891234567890"), 16, 'CREDITCARD');
console.log(itemAnalysis.shouldTokenize); // => false (Negative keyword "item id" detected)
```

---

### 3. Secure Detokenization (`detokenize`)
When the AI agent decides to fill a form:
```javascript
// AI output action:
const aiCommand = 'Type [SYS_PAN_01] into the PAN field';

// Detokenize restores the real secret in local RAM only:
const executableText = vault.detokenize(aiCommand);
console.log(executableText);
// => "Type ABCDE1234F into the PAN field"

// Core agent safely dispatches typing into the browser DOM!
```

---

### 4. Ephemeral Memory Sweeping (`flushVault`)
The moment an agent session completes:
```javascript
const result = vault.flushVault();
console.log(result);
// {
//   status: 'FLUSHED_SUCCESSFULLY',
//   clearedItemsCount: 3,
//   activeVaultSize: 0
// }
// Stored strings in RAM are overwritten and cleared — zero residual data leakage!
```

---

## 🧪 Verification & Automated Testing
Run the comprehensive verification suite anytime:
```bash
node verify_all.js
```
Output:
```
================================================================
   ISRO PS 171 - MEMBER 3 PRIVACY ENGINE VERIFICATION SUITE    
================================================================
[TEST 1] Testing PII Pattern Precision & Recall... (Passed)
[TEST 2] Testing Zero-Leakage Outgoing Payload Validator... (Passed)
[TEST 3] Testing Accessibility Tree Sanitizer... (Passed)
[TEST 4] Testing VaultManager Format-Preserving Tokenization... (Passed)
[TEST 5] Testing Context-Aware Confidence Scoring (+/- 50 chars)... (Passed)
[TEST 6] Testing Secure Agent Detokenization... (Passed)
[TEST 7] Testing Ephemeral Memory Sweeping (flushVault)... (Passed)
================================================================
  VERIFICATION RESULTS: ALL TESTS PASSED (100% SUCCESS)
================================================================
```
