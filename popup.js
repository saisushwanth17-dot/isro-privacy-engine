/**
 * ISRO PS 171 - Extension Popup Logic
 * Module: popup.js (With Auto Script Injection Fallback)
 */

const engine = new PrivacyEngine();

document.addEventListener('DOMContentLoaded', () => {
  // Tab Switching
  document.querySelectorAll('.tab-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById(btn.dataset.tab).classList.add('active');
    });
  });

  const btnCapture = document.getElementById('btnCapture');
  btnCapture.addEventListener('click', async () => {
    btnCapture.disabled = true;
    btnCapture.innerText = '⏳ Sanitizing On-Device...';

    try {
      // 1. Get Active Tab
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab) throw new Error('No active browser tab found.');

      // Check if it's a restricted Chrome internal page
      if (tab.url.startsWith('chrome://') || tab.url.startsWith('edge://') || tab.url.startsWith('chrome-extension://')) {
        throw new Error('Extensions cannot run on internal browser settings pages. Please open a website (like YouTube, Google, or the ISRO portal).');
      }

      // 2. Capture Viewport via Background Service Worker
      const bgResponse = await chrome.runtime.sendMessage({ action: 'CAPTURE_VISIBLE_TAB' });
      if (!bgResponse || !bgResponse.success) {
        throw new Error(bgResponse ? bgResponse.error : 'Failed to capture screenshot');
      }

      // 3. Extract DOM PII & A11y Tree with Auto-Injection Fallback
      let contentResponse;
      try {
        contentResponse = await chrome.tabs.sendMessage(tab.id, { action: 'EXTRACT_PAGE_DATA' });
      } catch (connectionErr) {
        // If content script was not yet injected (e.g. tab opened before extension reload), inject it automatically!
        console.log('Injecting content scripts into tab on the fly...');
        await chrome.scripting.executeScript({
          target: { tabId: tab.id },
          files: [
            'accessibility_sanitizer.js',
            'accessibility_walker.js',
            'privacy_engine.js',
            'content.js'
          ]
        });
        // Retry message
        contentResponse = await chrome.tabs.sendMessage(tab.id, { action: 'EXTRACT_PAGE_DATA' });
      }

      if (!contentResponse || !contentResponse.success) {
        throw new Error('Content script communication failed. Try refreshing the page.');
      }

      const { sensitiveItems, sanitizedAxTree, devicePixelRatio } = contentResponse;

      // 4. Sanitize Viewport Canvas on Client
      const sanitizationResult = await engine.sanitizeViewport(
        bgResponse.screenshotUrl,
        sensitiveItems,
        devicePixelRatio || 1
      );

      // 5. Construct Outgoing Payload
      const outgoingPayload = {
        session_id: 'isro-session-' + Math.random().toString(36).substring(2, 10),
        timestamp: new Date().toISOString(),
        page_title: contentResponse.pageTitle,
        sanitized_visual_tokens: sanitizationResult.tokenMap,
        sanitized_accessibility_tree: sanitizedAxTree
      };

      // 6. Validate Payload Zero-Leakage
      const validation = engine.validatePayload(outgoingPayload);

      // 7. Update UI
      document.getElementById('txtLatency').innerText = sanitizationResult.telemetry.sanitizationLatencyMs + ' ms';
      document.getElementById('txtPiiCount').innerText = sanitizationResult.tokenMap.length;
      
      const txtStatus = document.getElementById('txtStatus');
      if (validation.isSecure) {
        txtStatus.innerText = '0 LEAKS (SECURE)';
        txtStatus.className = 'status-badge';
      } else {
        txtStatus.innerText = `ALERT: ${validation.violationsCount} LEAK(S)`;
        txtStatus.className = 'status-badge status-alert';
      }

      const imgSanitized = document.getElementById('imgSanitized');
      imgSanitized.src = sanitizationResult.sanitizedImage;
      imgSanitized.style.display = 'block';
      document.getElementById('placeholder').style.display = 'none';

      document.getElementById('jsonA11y').innerText = JSON.stringify(sanitizedAxTree, null, 2);
      document.getElementById('jsonPayload').innerText = JSON.stringify(outgoingPayload, null, 2);

    } catch (err) {
      alert('Sanitization Notice: ' + err.message);
      console.error(err);
    } finally {
      btnCapture.disabled = false;
      btnCapture.innerText = '🔒 Capture & Sanitize Active Tab';
    }
  });
});
