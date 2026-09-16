// Background Service Worker for SentinelPhish extension

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url && tab.url.startsWith("http")) {
    fetch("http://localhost:8000/api/v1/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: tab.url })
    })
    .then(res => res.json())
    .then(data => {
      let badgeText = "";
      let badgeColor = "#10B981";

      if (data.verdict === "Phishing") {
        badgeText = "DANGER";
        badgeColor = "#EF4444";
        // Notify content script to display security banner if high risk
        chrome.tabs.sendMessage(tabId, { action: "SHOW_WARNING_BANNER", data: data });
      } else if (data.verdict === "Suspicious") {
        badgeText = "WARN";
        badgeColor = "#F59E0B";
      } else {
        badgeText = "SAFE";
        badgeColor = "#10B981";
      }

      chrome.action.setBadgeText({ tabId: tabId, text: badgeText });
      chrome.action.setBadgeBackgroundColor({ tabId: tabId, color: badgeColor });
    })
    .catch(() => {
      chrome.action.setBadgeText({ tabId: tabId, text: "" });
    });
  }
});
