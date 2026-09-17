# 🛡️ SentinelPhish — Advanced AI-Powered Phishing URL Detection System

SentinelPhish is an open-source, multi-layer phishing URL detection platform built with Python (FastAPI), Groq LLM (`llama-3.3-70b-versatile`), a soft-voting Machine Learning Ensemble (Random Forest + XGBoost + LightGBM), Playwright content inspection, Streamlit telemetry dashboard, React web client, and Chrome Extension (Manifest V3).

---

## 🌟 Key Features

- **8 Parallel Detection Layers**:
  1. **Lexical**: Entropy, Levenshtein typosquatting, Punycode homographs, suspicious TLDs, IP hostnames.
  2. **Domain/Network Intel**: WHOIS domain age, DNS records (A/MX/TXT/NS), SSL certificate issuer/validity, Certificate Transparency logs (crt.sh), IP reputation (AbuseIPDB / ipapi.co).
  3. **Content Analysis**: Playwright headless browser fetch, cross-domain form action validation, password field detection, JS obfuscation, redirect chain tracking, trafilatura text extraction.
  4. **Threat Intelligence**: Google Safe Browsing, VirusTotal, URLhaus, OpenPhish, PhishTank, urlscan.io with 24h Redis caching.
  5. **Visual Similarity & OCR**: Screenshot perceptual image hashing (pHash/dHash), Tesseract OCR login prompt detection.
  6. **Groq LLM Reasoning**: `llama-3.3-70b-versatile` cybersecurity threat reasoning with JSON schema enforcement.
  7. **ML Ensemble**: Soft-voting Random Forest + XGBoost + LightGBM on 15 URL structural features.
  8. **Behavioral/Temporal**: User-Agent bot-vs-browser cloaking check, shortener target expansion, campaign fingerprinting.

- **Fusion Engine**: Weighted scoring algorithm with strict priority override rules and SHAP explainability.
- **Production REST Gateway**: FastAPI with rate limiting, Redis response caching, batch scanning, feedback logging, and OpenAPI swagger docs.
- **Client Applications**:
  - Streamlit Admin Dashboard (`dashboard/streamlit_app.py`).
  - Chrome Extension Manifest V3 (`extension/`).
  - React + Vite + Tailwind modern Web App (`web/`).

---

## 🚀 Quick Start

### 1. Run with Docker Compose
```bash
docker-compose up --build
```
This launches:
- **FastAPI API Gateway**: `http://localhost:8000/docs`
- **Streamlit Admin Dashboard**: `http://localhost:8501`
- **PostgreSQL Database**: `localhost:5432`
- **Redis Cache**: `localhost:6379`
- **Celery Worker**: Background batch scanning queue

### 2. Local Manual Installation
```bash
# Clone and setup environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
playwright install chromium

# Train local ML ensemble models
python scripts/train_all_models.py

# Initialize database
python scripts/init_db.py

# Run FastAPI Gateway
uvicorn app.main:app --reload --port 8000
```

---

## 🛠️ Configuration & Secrets (`.env`)

Copy `.env.example` to `.env`:
```env
GROQ_API_KEY=your_groq_api_key
GOOGLE_SAFE_BROWSING_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
DATABASE_URL=sqlite+aiosqlite:///./sentinelphish.db
REDIS_URL=redis://localhost:6379/0
ENVIRONMENT=development
```

---

## 🧪 Testing

Run pytest suite:
```bash
pytest --cov=app --cov-report=term-missing
```

---

## 📄 License
MIT License. Open-source for personal and enterprise threat intelligence usage.
