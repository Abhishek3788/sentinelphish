# SentinelPhish Architecture & Technical Blueprint

```
Clients (Chrome Extension / React Web App / REST API)
        │
   FastAPI Gateway (rate limit, Redis lookup, input validation)
        │
   ScanOrchestrator (asyncio.gather, per-layer timeouts, Celery)
        │
   ┌────┴─────────────────────────────────────────────┐
   │  Parallel Detection Layers:                       │
   │  1. Lexical Analysis (<10ms)                    │
   │  2. Domain & Network Intel (1-3s)                │
   │  3. Playwright Content Analysis (2-5s)           │
   │  4. Threat Intel APIs (1-2s)                     │
   │  5. Visual Similarity & OCR (3-5s)                │
   │  6. Groq LLM Reasoning (1-3s)                    │
   │  7. ML Ensemble (RF + XGB + LGBM) (~500ms)       │
   │  8. Behavioral & Temporal (1-2s)                  │
   └────┬─────────────────────────────────────────────┘
        │
   Fusion Engine (weighted scoring + priority override rules)
        │
   Database Persistence (PostgreSQL / SQLite) & Redis Cache (24h)
        │
   JSON Response -> Client Applications (Streamlit / React / Extension)
```

## Layer Weights & Timeout Budget

| Layer | Name | Weight | Timeout |
|---|---|---|---|
| 1 | Lexical Analysis | 2% (0.02) | 1.0s |
| 2 | Domain & Network Intel | 5% (0.05) | 5.0s |
| 3 | Content Analysis | 8% (0.08) | 10.0s |
| 4 | Threat Intelligence | 30% (0.30) | 6.0s |
| 5 | Visual Similarity & OCR | 10% (0.10) | 12.0s |
| 6 | Groq LLM Reasoning | 25% (0.25) | 8.0s |
| 7 | ML Ensemble | 20% (0.20) | 2.0s |
| 8 | Behavioral & Temporal | 0% (Contextual) | 8.0s |

## Priority Override Rules
1. Any threat-intel feed flags URL -> `risk_score = max(score, 95)`
2. AI and ML both report >0.9 confidence phishing -> `risk_score = max(score, 90)`
3. Domain age <7 days AND visual brand match -> `risk_score = max(score, 85)`
4. Only lexical layer suspicious, all others clean -> `risk_score = min(score, 40)`
