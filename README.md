# AI-Powered Security Operations Center (SOC) Analyst

> **Automated Threat Detection, Event Normalization, and Incident Investigation Platform**  
> *A Technically Defensible, End-to-End Cybersecurity System for Academic & Research Demonstrations*

---

## 1. Executive Overview & Problem Statement

Modern Security Operations Centers (SOCs) face an overwhelming volume of security telemetry, leading to alert fatigue, missed threats, and delayed incident response. Traditional SIEM solutions generate thousands of disconnected alerts for a single multi-stage attack.

This project implements a fully working, demonstrable, end-to-end **AI-Powered SOC Analyst Platform** designed to solve alert fatigue through:
1. **Heterogeneous Security Telemetry Normalization** (parsing JSON, CSV, Syslog, Auth, and Firewall logs into a unified Pydantic event model).
2. **Hybrid Threat Detection** combining deterministic rule-based triggers with scikit-learn `IsolationForest` unsupervised machine learning anomaly scoring.
3. **Sliding-Window Alert Correlation** to group redundant alerts into cohesive, multi-vector Security Incidents.
4. **Context-Rich AI SOC Investigation Agent** with dual-mode support (Live LLM provider integration + transparent Rule-Based SOC fallback reasoning).
5. **MITRE ATT&CK Framework Mapping** (T1110, T1046, T1499, T1078, T1041).
6. **Multi-Factor Transparent Risk Scoring (0–100)** with clear, human-explainable contribution factors.
7. **Safe Interactive Attack Simulator** feeding real-time synthetic attack scenarios directly through the production detection pipeline.
8. **Detection Engine Benchmarking** evaluating Precision, Recall, F1 Score, False Positive Rate, and Confusion Matrices across Rule-based, ML-based, and Hybrid detection strategies.

---

## 2. Complete End-to-End System Pipeline Architecture

```text
Synthetic Attack Simulator / Raw Log Telemetry Ingestion (JSON, CSV, Syslog, Auth, Firewall)
                                      ↓
                Log Normalization Engine (Pydantic Schema Validation)
                                      ↓
                       Hybrid Threat Detection Engine
            ┌─────────────────────────┴─────────────────────────┐
            ↓                                                   ↓
 Rule Detection Engine                              ML Anomaly Detector
 (Brute Force, Port Scan, DoS, Privilege)         (scikit-learn Isolation Forest)
            └─────────────────────────┬─────────────────────────┘
                                      ↓
                          Security Alert Generation
                                      ↓
                 Alert Correlator (Sliding Window Grouping)
                                      ↓
                         Correlated Security Incident
                                      ↓
                      Context Enrichment & MITRE Mapping
                   (T1110, T1046, T1499, T1078, T1041, T1204)
                                      ↓
              AI SOC Investigation Agent (Context Payload Builder)
            ┌─────────────────────────┴─────────────────────────┐
            ↓                                                   ↓
     Live LLM Mode                                   Rule-Based SOC Fallback Mode
 (Google Gemini / OpenAI / Groq API)             (Deterministic Threat Signatures)
            └─────────────────────────┬─────────────────────────┘
                                      ↓
                  Multi-Factor Risk Scoring Engine (0-100)
                                      ↓
               SOC Command Center Dashboard & Report Exporter
                    (Markdown, JSON, Printable HTML/PDF)
```

---

## 3. Key Capabilities & System Scope

| Component | Description | Technical Implementation |
|---|---|---|
| **Event Ingestion & Normalizer** | Ingests JSON, CSV, Syslog strings, Auth logs, Firewall logs | Pydantic v2 validation, Regex timestamp & IP extraction |
| **Rule-Based Engine** | Configurable deterministic thresholds for 4 primary attack patterns | Windowed aggregation for Brute Force, Port Scan, DoS, Privilege Anomaly |
| **ML Anomaly Detector** | Unsupervised statistical anomaly detection on feature vectors | `scikit-learn` Isolation Forest (`n_estimators=100`, contamination=0.15) |
| **Alert Correlator** | Groups related alerts sharing IP/user/destination into single incidents | Sliding time-window entity correlation engine |
| **AI Investigation Agent** | Synthesizes context, confirmed evidence, technical narrative, actions | Dual-mode: Live LLM provider API + Rule-Based SOC Fallback |
| **MITRE ATT&CK Mapping** | Maps detected threats to standard MITRE TTPs | T1110 (Brute Force), T1046 (Scan), T1499 (DoS), T1078 (Valid Accounts) |
| **Risk Scoring Engine** | Transparent 0–100 risk score calculation with explicit factor weights | Base Severity (40%), Volume (20%), ML Score (20%), Entity (10%), Evidence (10%) |
| **Attack Simulator** | Safe synthetic attack execution feeding production pipeline | Interactive scenario triggers for Brute Force, Port Scan, DoS, Privilege Anomaly |
| **SOC Command Center** | High-contrast, dark mode SOC command center dashboard | Next.js 14 App Router, TypeScript, Tailwind CSS, Recharts, Lucide Icons |
| **Engine Benchmarking** | Performance comparison of Rule vs ML vs Hybrid detection | Calculates Precision, Recall, F1 Score, FPR, Accuracy & Confusion Matrices |

---

## 4. Technology Stack

### Backend
- **Language & Framework**: Python 3.11, FastAPI
- **Data Validation & Settings**: Pydantic v2, Pydantic-Settings
- **Machine Learning**: `scikit-learn`, `numpy`, `pandas`
- **HTTP & Async API**: `httpx`, `uvicorn`
- **Testing**: `pytest`, `anyio`

### Frontend
- **Framework**: Next.js 14 (App Router), React 19, TypeScript
- **Styling**: Tailwind CSS
- **Data Visualization**: Recharts
- **Icons**: Lucide React

---

## 5. Directory Structure

```text
AI SOC Analyst/
├── backend/
│   ├── app/
│   │   ├── main.py                     # FastAPI routes & application lifecycle
│   │   ├── config.py                   # System configuration & environment settings
│   │   ├── schemas/
│   │   │   ├── events.py               # StandardSecurityEvent & Ingestion schemas
│   │   │   ├── alerts.py               # SecurityAlert & Rule/ML schemas
│   │   │   └── incidents.py            # Incident, MITRE, Risk & AI schemas
│   │   ├── services/
│   │   │   ├── normalizer.py           # Log normalization engine
│   │   │   ├── detection.py            # Rule-based threat detection engine
│   │   │   ├── ml_detector.py          # Isolation Forest ML anomaly detector
│   │   │   ├── correlator.py           # Alert correlation engine
│   │   │   ├── mitre_mapper.py         # MITRE ATT&CK mapping service
│   │   │   ├── risk_scorer.py          # Multi-factor 0-100 risk scorer
│   │   │   ├── ai_agent.py             # AI SOC Analyst agent (LLM + Fallback)
│   │   │   └── report_generator.py     # Markdown, JSON & HTML report generator
│   │   ├── simulator/
│   │   │   └── attack_scenarios.py     # 4 Attack simulation generators
│   │   └── benchmark/
│   │       └── evaluator.py            # Detection benchmark evaluator
│   ├── tests/
│   │   ├── test_normalizer.py          # Pytest unit tests for log normalizer
│   │   ├── test_detection.py           # Pytest unit tests for rule engine
│   │   └── test_api.py                 # Pytest async integration tests for API
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx                # SOC Overview Dashboard
│   │   │   ├── investigation/page.tsx  # Alert Investigation Workspace
│   │   │   ├── simulator/page.tsx      # Interactive Attack Simulator
│   │   │   ├── incidents/page.tsx      # Incident Reports & Exporters
│   │   │   └── benchmark/page.tsx      # Detection Engine Benchmarks
│   │   ├── components/
│   │   │   ├── Sidebar.tsx             # Command center sidebar navigation
│   │   │   ├── Header.tsx              # Ticker, AI mode & telemetry status header
│   │   │   └── SeverityBadge.tsx       # Styled severity badge component
│   │   └── lib/
│   │       └── api.ts                  # Typed API client for FastAPI backend
│   └── package.json
└── README.md
```

---

## 6. Installation & Running Locally

### Step 1: Clone Repository
```bash
git clone https://github.com/your-username/AI-SOC-Analyst.git
cd "AI SOC Analyst"
```

### Step 2: Running Backend (FastAPI)
```bash
cd backend
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
*Backend API will be live at `http://127.0.0.1:8000` with interactive API docs at `http://127.0.0.1:8000/docs`.*

### Step 3: Running Automated Pytest Suite
```bash
cd backend
python -m pytest -v
```

### Step 4: Running Frontend (Next.js)
```bash
cd frontend
npm install
npm run dev
```
*Frontend Command Center will be live at `http://localhost:3000`.*

---

## 7. AI SOC Agent Configuration

The system automatically operates in **dual mode**:

### Mode 1: Live LLM Provider Integration
To enable live LLM integration, set the `LLM_API_KEY` environment variable in `backend/.env` or runtime environment:
```env
LLM_API_KEY=your_gemini_or_openai_api_key
LLM_PROVIDER=google
LLM_MODEL=gemini-1.5-flash
```

### Mode 2: Deterministic Rule-Based SOC Fallback
If no API key is provided or external API calls fail, the system seamlessly uses its local deterministic **Rule-Based SOC Analyst Reasoning** engine. The output explicitly labels itself as:
```text
Mode: Rule-Based SOC Analysis
```

---

## 8. Demonstration Walkthrough

1. **Open SOC Dashboard** (`http://localhost:3000`): View live KPIs, threat breakdown donut chart, severity distribution, and initial correlated incident feed.
2. **Launch Attack Simulation** (`http://localhost:3000/simulator`): Click **Run Attack Simulation** on any of the 4 cards (e.g., Brute Force). Observe the 5-stage pipeline progress indicator.
3. **Investigate Incident** (`http://localhost:3000/investigation`): Click **Investigate Generated Incident**. Review executive summary, confirmed evidence badges, technical attack narrative, recommended response checklist, MITRE ATT&CK cards, 0–100 risk score factor breakdown, and correlated raw telemetry table.
4. **Export Incident Report** (`http://localhost:3000/incidents`): Export report in Markdown (`.md`), JSON (`.json`), or open printable HTML view.
5. **View Benchmark Metrics** (`http://localhost:3000/benchmark`): Compare F1 score, Precision, Recall, and Confusion Matrices across Rule-based, ML-based, and Hybrid detection strategies.

---

## 9. Academic Integrity Disclaimer & Limitations

> **Academic Disclaimer**: This project is developed as a B.Tech Computer Science & Engineering minor project prototype / educational security platform. It demonstrates automated threat detection and incident investigation concepts.

### Documented Limitations:
- Evaluation uses controlled synthetic security scenarios.
- Unsupervised Isolation Forest model requires continuous baseline telemetry updates for drift adaptation.
- Responses generated by the AI SOC Agent are advisory; human SOC analyst approval is required prior to applying mitigation actions.
