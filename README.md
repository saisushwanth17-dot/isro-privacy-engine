# ISRO PS 171 — Privacy Preserving & Redaction Engine (Member 3)

> **Component:** Client-Side Privacy Engine & On-Device Sanitization  
> **Supports:** Chrome Extension Manifest V3 / WebGPU / WASM  
> **Coverage:** ISRO Evaluation Metric 2 (20% PII Recall) & Metric 3 (20% Redaction Quality)

---

## 📦 Package Contents

```
├── privacy_engine.js         # Core Engine (DOM & Shadow DOM Scanner + Canvas Masker + Security Gate)
├── accessibility_sanitizer.js# On-device semantic Accessibility Tree Sanitizer
├── accessibility_walker.js   # Lightweight A11y Tree Builder from DOM & Shadow Roots
├── privacy_engine.d.ts       # Full TypeScript Definitions & Interface Types
├── manifest.json             # Manifest V3 configuration for Chrome / Edge
├── background.js             # Background service worker for tab capture
├── content.js                # Content script injected into active tabs
├── popup.html / popup.js     # Live DevTools Inspector & Visualizer UI
├── popup.css                 # Cyber-security dark theme styling
└── .gitignore                # Git ignore configuration
```

---

## 🔌 How Member 1 (ML / WebGPU Lead) Connects Their Vision Model

Member 1's local Vision Model (e.g. YOLO-UI / MobileViT / ONNX Web) outputs bounding boxes for detected UI elements or visual PII from raw pixels.

To sanitize the frame with **both** DOM PII and Member 1's ML detections:

```typescript
import { PrivacyEngine } from './privacy_engine.js';

const privacyEngine = new PrivacyEngine({
  enableStrictZeroLeakage: true // Blocks unmasked PII strings from escaping
});

// 1. Member 1 passes detected visual bounding boxes:
const customMlBoxes = [
  {
    id: 'ML_DETECTED_FACE_1',
    category: 'FACE_AVATAR',
    boundingBox: { x: 120, y: 80, width: 64, height: 64 },
    redactionLabel: '[REDACTED_FACE_#1]'
  }
];

// 2. Run on-device sanitization in one line:
const { sanitizedImage, tokenMap, telemetry } = await privacyEngine.sanitizeViewport(
  rawScreenshotBase64,  // Captured viewport image (PNG/WebP/Base64)
  customMlBoxes,        // ML bounding boxes from Member 1
  window.devicePixelRatio || 1
);

console.log(`Sanitized in ${telemetry.sanitizationLatencyMs}ms. Masked items: ${tokenMap.length}`);
// Output: sanitizedImage (Base64 WebP with zero sensitive pixels)
```

---

## 🛡️ How Member 4 (Backend LLM Lead) Validates Zero Leakage

Before sending the JSON payload to the remote server / LLM:

```javascript
try {
  // Scans the payload for unmasked Aadhaar, PAN, passwords, phones, or cards
  privacyEngine.validatePayload(outgoingJsonPayload);

  // Safe to transmit over network:
  await sendToBackend(outgoingJsonPayload);
} catch (error) {
  console.error("Payload blocked locally to prevent privacy leak:", error.message);
}
```
