// Content script to render in-page warning banner if URL is classified as Phishing
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "SHOW_WARNING_BANNER") {
    if (document.getElementById("sentinelphish-warning-banner")) return;

    const banner = document.createElement("div");
    banner.id = "sentinelphish-warning-banner";
    banner.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      background-color: #EF4444;
      color: white;
      font-family: system-ui, -apple-system, sans-serif;
      padding: 12px 16px;
      z-index: 9999999;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 14px;
      font-weight: 600;
    `;

    banner.innerHTML = `
      <div>
        🚨 <strong>SENTINELPHISH SECURITY WARNING:</strong> High risk phishing site detected (Risk Score: ${request.data.risk_score}/100). Do NOT enter passwords or personal data!
      </div>
      <button id="close-sentinel-banner" style="background: rgba(0,0,0,0.2); border: none; color: white; padding: 4px 10px; border-radius: 4px; cursor: pointer;">Dismiss</button>
    `;

    document.body.prepend(banner);

    document.getElementById("close-sentinel-banner").addEventListener("click", () => {
      banner.remove();
    });
  }
});
