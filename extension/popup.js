const API_ENDPOINT = "http://localhost:8000/api/v1/check";

document.addEventListener("DOMContentLoaded", () => {
  const currentUrlEl = document.getElementById("current-url");
  const verdictBadgeEl = document.getElementById("verdict-badge");
  const riskScoreEl = document.getElementById("risk-score");
  const explanationEl = document.getElementById("explanation");
  const redFlagsListEl = document.getElementById("red-flags-list");
  const scanBtn = document.getElementById("scan-btn");

  function scanTabUrl() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (!tabs || !tabs[0] || !tabs[0].url) {
        currentUrlEl.textContent = "Unable to read current tab URL.";
        return;
      }

      const activeUrl = tabs[0].url;
      currentUrlEl.textContent = activeUrl;
      verdictBadgeEl.textContent = "Checking...";
      verdictBadgeEl.className = "badge badge-checking";

      fetch(API_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: activeUrl })
      })
      .then(res => res.json())
      .then(data => {
        verdictBadgeEl.textContent = data.verdict;
        verdictBadgeEl.className = `badge badge-${data.verdict.toLowerCase()}`;
        
        riskScoreEl.textContent = data.risk_score;
        explanationEl.textContent = data.explanation || "No anomaly explanation.";

        redFlagsListEl.innerHTML = "";
        if (data.red_flags && data.red_flags.length > 0) {
          data.red_flags.forEach(flagObj => {
            const div = document.createElement("div");
            div.className = "flag-item";
            div.textContent = `• ${flagObj.flag}`;
            redFlagsListEl.appendChild(div);
          });
        } else {
          redFlagsListEl.innerHTML = '<div class="no-flags">No threat indicators found.</div>';
        }
      })
      .catch(err => {
        verdictBadgeEl.textContent = "Error";
        verdictBadgeEl.className = "badge badge-checking";
        explanationEl.textContent = "Gateway offline. Ensure FastAPI backend is running on localhost:8000.";
      });
    });
  }

  scanBtn.addEventListener("click", scanTabUrl);
  scanTabUrl();
});
