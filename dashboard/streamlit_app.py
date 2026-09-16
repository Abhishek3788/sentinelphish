import streamlit as st
import requests
import json
import pandas as pd
import time

API_BASE = "http://localhost:8000/api/v1"

st.set_page_config(
    page_title="SentinelPhish Admin Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark theme styling
st.markdown("""
<style>
    .metric-card {
        background-color: #1E293B;
        padding: 18px;
        border-radius: 10px;
        border: 1px solid #334155;
        text-align: center;
    }
    .verdict-phishing {
        color: #EF4444;
        font-weight: bold;
        font-size: 24px;
    }
    .verdict-suspicious {
        color: #F59E0B;
        font-weight: bold;
        font-size: 24px;
    }
    .verdict-safe {
        color: #10B981;
        font-weight: bold;
        font-size: 24px;
    }
</style>
""", unsafe_allow_html=True)

st.sidebar.title("🛡️ SentinelPhish")
st.sidebar.caption("AI-Powered Phishing Detection Platform")
nav = st.sidebar.radio("Navigation", ["Overview & Telemetry", "Live URL Inspector", "Batch Scanner", "Feedback & Tuning"])


def fetch_stats():
    try:
        res = requests.get(f"{API_BASE}/stats", timeout=3.0)
        if res.status_code == 200:
            return res.json()
    except Exception:
        pass
    return None


if nav == "Overview & Telemetry":
    st.title("📊 System Telemetry & Aggregates")
    st.write("Real-time operational metrics across all 8 detection layers.")
    
    stats = fetch_stats()
    if stats:
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Total Scans", stats["total_scans"])
        c2.metric("Phishing Detected", stats["phishing_detected"])
        c3.metric("Suspicious", stats["suspicious_detected"])
        c4.metric("Safe URLs", stats["safe_detected"])
        c5.metric("Avg Latency", f"{stats['avg_processing_time_ms']} ms")
    else:
        st.info("API Gateway offline or no scan data recorded yet. Start FastAPI backend at http://localhost:8000.")

    st.subheader("Layer Weights Configuration")
    weights_df = pd.DataFrame([
        {"Layer": "Threat Intelligence", "Weight": "30%", "Timeout": "6.0s"},
        {"Layer": "Groq LLM Reasoning", "Weight": "25%", "Timeout": "8.0s"},
        {"Layer": "ML Ensemble (RF+XGB+LGB)", "Weight": "20%", "Timeout": "2.0s"},
        {"Layer": "Visual Similarity & OCR", "Weight": "10%", "Timeout": "12.0s"},
        {"Layer": "Content Analysis", "Weight": "8%", "Timeout": "10.0s"},
        {"Layer": "Domain & Network Intel", "Weight": "5%", "Timeout": "5.0s"},
        {"Layer": "Lexical Analyzer", "Weight": "2%", "Timeout": "1.0s"}
    ])
    st.dataframe(weights_df, use_container_width=True)

elif nav == "Live URL Inspector":
    st.title("🔍 Live Multi-Layer URL Inspector")
    target_url = st.text_input("Enter URL to analyze:", value="http://paypal-secure-verification.xyz/login")
    
    if st.button("Run Inspection", type="primary"):
        with st.spinner("Executing 8 parallel detection layers..."):
            try:
                resp = requests.post(f"{API_BASE}/check", json={"url": target_url}, timeout=15.0)
                if resp.status_code == 200:
                    data = resp.json()
                    
                    st.divider()
                    col1, col2, col3 = st.columns(3)
                    
                    verdict_class = f"verdict-{data['verdict'].lower()}"
                    col1.markdown(f"### Verdict: <span class='{verdict_class}'>{data['verdict']}</span>", unsafe_allow_html=True)
                    col2.metric("Risk Score", f"{data['risk_score']} / 100")
                    col3.metric("Confidence", data["confidence"].upper())
                    
                    st.write(f"**Latency:** {data['processing_time_ms']} ms | **Cached:** {data['cached']}")
                    st.info(f"**AI Security Explanation:** {data['explanation']}")
                    
                    st.subheader("🚩 Detected Red Flags")
                    if data["red_flags"]:
                        for rf in data["red_flags"]:
                            icon = "🔴" if rf["severity"] == "high" else ("🟡" if rf["severity"] == "medium" else "🔵")
                            st.write(f"{icon} **[{rf['severity'].upper()}]** {rf['flag']}")
                    else:
                        st.success("No threat red flags detected.")

                    st.subheader("📈 Layer Risk Scores")
                    st.bar_chart(pd.Series(data["layer_scores"]))

                else:
                    st.error(f"Scan failed: {resp.text}")
            except Exception as e:
                st.error(f"Could not connect to SentinelPhish API gateway: {e}")

elif nav == "Batch Scanner":
    st.title("📦 Batch URL Scanner")
    raw_urls = st.text_area("Paste up to 50 URLs (one per line):", value="https://google.com\nhttp://paypal-security-update.xyz\nhttps://github.com")
    
    if st.button("Run Batch Scan"):
        urls_list = [u.strip() for u in raw_urls.split("\n") if u.strip()]
        with st.spinner(f"Scanning {len(urls_list)} URLs..."):
            try:
                resp = requests.post(f"{API_BASE}/check/batch", json={"urls": urls_list}, timeout=30.0)
                if resp.status_code == 200:
                    batch_res = resp.json()
                    df_res = pd.DataFrame(batch_res)
                    st.dataframe(df_res[["url", "verdict", "risk_score", "confidence", "processing_time_ms"]], use_container_width=True)
                else:
                    st.error(resp.text)
            except Exception as e:
                st.error(f"Batch scan failed: {e}")

elif nav == "Feedback & Tuning":
    st.title("💬 Feedback & Retraining Queue")
    scan_id = st.text_input("Scan UUID:")
    is_correct = st.checkbox("Was the scan verdict accurate?", value=False)
    user_comment = st.text_area("Notes / True classification:")
    
    if st.button("Submit Feedback"):
        try:
            res = requests.post(f"{API_BASE}/feedback", json={"scan_id": scan_id, "is_correct": is_correct, "user_comment": user_comment})
            if res.status_code == 200:
                st.success("Feedback recorded successfully!")
            else:
                st.error(res.text)
        except Exception as e:
            st.error(f"Feedback submission error: {e}")
