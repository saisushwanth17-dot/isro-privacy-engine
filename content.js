/**
 * ISRO PS 171 - Chrome Extension Content Script
 * Module: content.js (Shadow DOM & Active Element Scanner)
 */

const privacyEngine = new PrivacyEngine();
const a11yWalker = new AccessibilityWalker();

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'EXTRACT_PAGE_DATA') {
    try {
      // 1. Scan DOM & Shadow DOM PII (including live search bars)
      const sensitiveItems = privacyEngine.scanDOM(document);

      // 2. Build complete Accessibility Tree (including Shadow Roots)
      const rawAxTree = a11yWalker.buildTree(document.body);

      // 3. Sanitize Accessibility Tree on-device
      const sanitizedAxTree = privacyEngine.sanitizeAccessibilityTree(rawAxTree);

      sendResponse({
        success: true,
        sensitiveItems: sensitiveItems,
        sanitizedAxTree: sanitizedAxTree,
        pageTitle: document.title,
        devicePixelRatio: window.devicePixelRatio || 1
      });
    } catch (err) {
      console.error('Content script extraction error:', err);
      sendResponse({ success: false, error: err.message });
    }
    return true;
  }

  if (request.action === 'EXECUTE_ACTION') {
    const { actionType, coordinate, text } = request.payload;
    try {
      if (actionType === 'CLICK') {
        const target = document.elementFromPoint(coordinate[0], coordinate[1]);
        if (target) {
          target.click();
          target.focus();
        }
      } else if (actionType === 'TYPE') {
        const target = document.elementFromPoint(coordinate[0], coordinate[1]);
        if (target) {
          target.value = text;
          target.dispatchEvent(new Event('input', { bubbles: true }));
          target.dispatchEvent(new Event('change', { bubbles: true }));
        }
      }
      sendResponse({ success: true });
    } catch (err) {
      sendResponse({ success: false, error: err.message });
    }
    return true;
  }
});
