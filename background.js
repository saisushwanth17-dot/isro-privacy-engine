/**
 * ISRO PS 171 - Background Service Worker
 * Module: background.js
 */

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'CAPTURE_VISIBLE_TAB') {
    chrome.tabs.captureVisibleTab(null, { format: 'png' }, (dataUrl) => {
      if (chrome.runtime.lastError) {
        sendResponse({ success: false, error: chrome.runtime.lastError.message });
      } else {
        sendResponse({ success: true, screenshotUrl: dataUrl });
      }
    });
    return true; // Keep message channel open for async response
  }
});
