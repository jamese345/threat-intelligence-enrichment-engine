# 🔎 Threat Intelligence Enrichment Engine

A Python-based **Threat Intelligence Enrichment Engine** designed to help SOC analysts investigate suspicious alerts by extracting Indicators of Compromise (IOCs), enriching them with threat intelligence, adding global threat context, and producing actionable SOC recommendations.

The project is part of my journey toward becoming an **AI SOC Analyst**, combining cybersecurity, Python, automation, threat intelligence, and intelligent security analysis.

---

## 🎯 Project Goal

SOC analysts often receive alerts containing indicators such as:

- IP addresses
- Domains
- URLs
- File hashes

The challenge is turning these raw indicators into useful security context quickly.

This project automates that process by:

1. Extracting IOCs from security alerts
2. Normalizing and deduplicating indicators
3. Enriching indicators using threat intelligence
4. Adding global threat-environment context
5. Assessing IOC risk and confidence
6. Generating SOC analyst recommendations
7. Producing structured investigation reports

---

## 🏗️ Architecture

```text
                         SOC Alert
                            │
                            ▼
                 ┌─────────────────────┐
                 │    IOC Extraction   │
                 │ IP / Domain / URL   │
                 │       / Hash        │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Normalization &     │
                 │ Deduplication       │
                 └──────────┬──────────┘
                            │
              ┌─────────────┴─────────────┐
              ▼                           ▼
     ┌──────────────────┐        ┌──────────────────┐
     │ Threat           │        │ Global Threat    │
     │ Intelligence     │        │ Context          │
     │                  │        │                  │
     │ AlienVault OTX   │        │ ICHI             │
     └────────┬─────────┘        └────────┬─────────┘
              │                           │
              └─────────────┬─────────────┘
                            ▼
                 ┌─────────────────────┐
                 │ IOC Risk Analysis    │
                 │ & Confidence         │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ SOC Analyst         │
                 │ Assessment          │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Recommendation      │
                 │ ESCALATE /          │
                 │ INVESTIGATE /       │
                 │ MONITOR / REVIEW    │
                 └──────────┬──────────┘
                            │
                            ▼
                 ┌─────────────────────┐
                 │ Automated Reports   │
                 │ JSON / CSV / TXT    │
                 └─────────────────────┘
```

---

## 🚀 Key Features

### IOC Extraction

Automatically identifies:

- IPv4 addresses
- Domains
- URLs
- MD5 hashes
- SHA1 hashes
- SHA256 hashes

### IOC Normalization

Indicators are normalized before enrichment to reduce duplicate lookups.

Examples include:

- Domain case normalization
- Removing unnecessary `www.` prefixes
- URL normalization
- Hash normalization
- Duplicate removal

### Threat Intelligence Enrichment

The engine integrates with **AlienVault OTX** to retrieve threat intelligence associated with discovered indicators.

The enrichment process considers information such as:

- Threat intelligence pulse count
- Reputation
- Indicator type
- API availability
- Enrichment status

### Global Threat Context

The engine also incorporates the **Internet Cyber Health Index (ICHI)** as an external global threat-environment signal.

This provides additional context about the broader internet threat environment.

Importantly, global threat context is treated as an **urgency/context signal**, not as proof that an individual IOC is malicious.

### IOC Risk Analysis

Indicators are classified into:

- 🔴 HIGH
- 🟠 MEDIUM
- 🟢 LOW
- ⚪ UNKNOWN

The engine also calculates confidence based on available threat intelligence.

### SOC Recommendations

The engine produces analyst-oriented recommendations:

- `ESCALATE`
- `INVESTIGATE`
- `MONITOR`
- `REVIEW`

### Automated Reporting

Investigation results are automatically exported as:

```text
reports/
├── enrichment_results.json
├── enrichment_results.csv
└── enrichment_report.txt
```

---

## 📊 Example SOC Assessment

Example output:

```text
============================================================
THREAT INTELLIGENCE ENRICHMENT ENGINE
============================================================

IOC Count: 2

SOC Analyst Assessment:
  Overall Risk: MEDIUM
  Confidence: MEDIUM
  Recommended Action: MONITOR
  High-Risk IOCs: 0
  Medium-Risk IOCs: 1
  Low-Risk IOCs: 0
  Unknown-Risk IOCs: 1

  Summary:
  Alert assessed as MEDIUM risk with MEDIUM confidence.
  0 high-risk, 1 medium-risk, 0 low-risk, and
  1 unknown-risk indicators were identified.
  Recommended action: MONITOR.
```

---

## 🧪 Testing

The project includes an automated test suite covering:

- IOC extraction
- IOC normalization
- IOC deduplication
- Threat intelligence enrichment
- API failures
- Invalid JSON responses
- Unexpected API responses
- Timeout handling
- Unsupported indicators
- Global threat context failures
- Risk classification
- Confidence scoring
- SOC recommendations
- Analyst workflow
- Report generation
- Empty alerts
- End-to-end pipeline

Run the tests with:

```bash
python -m unittest discover -s tests -v
```

---

## 📁 Project Structure

```text
threat-intelligence-enrichment-engine/
│
├── data/
│
├── reports/
│   ├── enrichment_results.json
│   ├── enrichment_results.csv
│   └── enrichment_report.txt
│
├── src/
│   ├── __init__.py
│   ├── analyst_workflow.py
│   ├── enrichment.py
│   ├── extract_iocs.py
│   ├── generate_report.py
│   ├── global_threat_context.py
│   ├── normalize_iocs.py
│   ├── risk_context.py
│   └── threat_intelligence.py
│
├── tests/
│   ├── __init__.py
│   ├── test_analyst_workflow.py
│   ├── test_enrichment.py
│   ├── test_generate_report.py
│   ├── test_global_threat_context.py
│   ├── test_ioc_extraction.py
│   ├── test_normalize_iocs.py
│   └── test_threat_intelligence.py
│
├── .env.example
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
└── main.py
```

---

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/jamese345/threat-intelligence-enrichment-engine.git
cd threat-intelligence-enrichment-engine
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

### 3. Activate the environment

Windows:

```bash
.venv\Scripts\activate
```

### 4. Install dependencies

```bash
python -m pip install -r requirements.txt
```

### 5. Configure environment variables

Copy:

```text
.env.example
```

to:

```text
.env
```

Then add your AlienVault OTX API key:

```env
OTX_API_KEY=your_api_key_here
```

Never commit `.env` or expose API keys publicly.

### 6. Run the engine

```bash
python main.py
```

Reports will be generated in:

```text
reports/
```

---

## 🔐 Security Considerations

This project is designed for defensive cybersecurity research, SOC automation, and threat intelligence analysis.

API credentials are loaded through environment variables and should never be committed to source control.

The project also distinguishes between:

**Known malicious evidence**

and

**Insufficient intelligence / unknown**

An indicator that cannot be confirmed as malicious is not automatically considered safe.

---

## 🛠️ Technologies Used

- Python
- Pandas
- Requests
- python-dotenv
- Regular Expressions
- unittest
- AlienVault OTX
- ICHI
- JSON
- CSV

---

## 📈 Project Status

**Status: Completed — v1.0.0**

Implemented:

- [x] IOC extraction
- [x] IOC normalization
- [x] IOC deduplication
- [x] Threat intelligence enrichment
- [x] Global threat context
- [x] IOC risk analysis
- [x] Confidence scoring
- [x] SOC recommendations
- [x] Analyst workflow
- [x] Automated reporting
- [x] Reliability hardening
- [x] Automated tests

---

## 🔮 Future Improvements

Potential future enhancements include:

- [ ] Additional threat intelligence providers
- [ ] MISP integration
- [ ] MITRE ATT&CK technique mapping
- [ ] IOC caching
- [ ] Threat intelligence correlation
- [ ] Web-based analyst dashboard
- [ ] SIEM integration
- [ ] LLM-assisted investigation
- [ ] Automated investigation summaries

These improvements will contribute toward the larger goal of building a complete **AI SOC Analyst platform**.

---

## 🧠 What I Learned

This project strengthened my practical understanding of:

- Threat intelligence APIs
- IOC extraction and normalization
- API error handling
- Security automation
- Risk scoring
- Analyst decision workflows
- External threat context
- Automated reporting
- Python testing
- Building resilient security tooling

The project also reinforced an important SOC principle:

> **Threat intelligence provides context; analyst decisions require correlation.**

---

## 👨‍💻 Author

**Brian Owala**

Cybersecurity Analyst focused on combining **Cybersecurity + Python + AI**.

Currently building practical AI SOC projects with the long-term goal of becoming an **AI SOC Analyst**.

---

## 📚 Part of My AI SOC Journey

This project is **Project 4** in my AI SOC Analyst portfolio roadmap:

```text
01. 🛡️ SOC Log Analyzer
        ↓
02. 🚨 Automated Alert Triage Engine
        ↓
03. 🧠 ML-Based Anomaly Detector
        ↓
04. 🔎 Threat Intelligence Enrichment Engine
        ↓
05. 📚 Cybersecurity RAG Assistant
        ↓
06. 🤖 AI SOC Investigation Agent
        ↓
07. 🏆 Full AI SOC Analyst Platform
```

---

## 📄 License

This project is licensed under the MIT License.