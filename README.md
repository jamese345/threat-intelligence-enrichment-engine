# 🔎 Threat Intelligence Enrichment Engine

A Python-based **Threat Intelligence Enrichment Engine** designed to help SOC analysts investigate suspicious alerts by extracting Indicators of Compromise (IOCs), enriching them with threat intelligence, adding global threat context, mapping alert behavior to **MITRE ATT&CK**, and producing actionable SOC recommendations.

This project is part of my journey toward becoming an **AI SOC Analyst**, combining cybersecurity, Python, automation, threat intelligence, and intelligent security analysis.

---

## 🎯 Project Goal

SOC analysts often receive alerts containing indicators such as:

- IP addresses
- Domains
- URLs
- File hashes

The challenge is turning these raw indicators and alert behaviors into useful security context quickly.

This project automates that process by:

1. Extracting IOCs from security alerts
2. Normalizing and deduplicating indicators
3. Enriching indicators using threat intelligence
4. Adding global threat-environment context
5. Assessing IOC risk and confidence
6. Mapping suspicious behavior to MITRE ATT&CK
7. Generating SOC analyst recommendations
8. Producing structured investigation reports

The goal is to move from:

> **Raw security alert → actionable SOC intelligence**

---

# 🏗️ Architecture

```text
                              SOC ALERT
                                  │
                                  ▼
                       ┌─────────────────────┐
                       │   IOC Extraction    │
                       │                     │
                       │ IP / Domain / URL   │
                       │      / Hash         │
                       └──────────┬──────────┘
                                  │
                                  ▼
                       ┌─────────────────────┐
                       │ Normalization &     │
                       │ Deduplication       │
                       └──────────┬──────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
          ┌──────────────────┐        ┌──────────────────┐
          │ Threat           │        │ Global Threat    │
          │ Intelligence     │        │ Context          │
          │                  │        │                  │
          │ AlienVault OTX   │        │ ICHI             │
          └────────┬─────────┘        └────────┬─────────┘
                   │                           │
                   └─────────────┬─────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │    IOC Risk Analysis   │
                    │    & Confidence        │
                    └────────────┬───────────┘
                                 │
                                 │
               ┌─────────────────┴─────────────────┐
               │                                   │
               ▼                                   ▼
     ┌────────────────────┐             ┌────────────────────┐
     │ MITRE ATT&CK       │             │ SOC Analyst        │
     │ Behavioral Mapping │             │ Assessment         │
     └─────────┬──────────┘             └──────────┬─────────┘
               │                                   │
               └─────────────────┬─────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │ SOC Recommendations    │
                    │                        │
                    │ ESCALATE               │
                    │ INVESTIGATE            │
                    │ MONITOR                │
                    │ REVIEW                 │
                    └────────────┬───────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │ Automated SOC Reports  │
                    │                        │
                    │ JSON / CSV / MITRE CSV │
                    │ TXT                    │
                    └────────────────────────┘
```

---

# 🚀 Key Features

## 🔍 IOC Extraction

Automatically identifies common Indicators of Compromise:

- IPv4 addresses
- Domains
- URLs
- MD5 hashes
- SHA1 hashes
- SHA256 hashes

---

## 🧹 IOC Normalization

Indicators are normalized before enrichment to reduce duplicate lookups and improve consistency.

Examples include:

- Domain normalization
- Removing unnecessary `www.` prefixes
- URL normalization
- Hash normalization
- Duplicate removal

---

## 🌐 Threat Intelligence Enrichment

The engine integrates with **AlienVault OTX** to retrieve threat intelligence associated with discovered indicators.

The enrichment process considers information such as:

- Threat intelligence pulse count
- Reputation
- Indicator type
- API availability
- Enrichment status
- API failures and unexpected responses

The engine is designed to continue operating safely when external intelligence is unavailable.

---

## 🌍 Global Threat Context

The engine incorporates the **Internet Cyber Health Index (ICHI)** as an external global threat-environment signal.

This provides additional context about the broader internet threat environment.

Importantly:

> **Global threat context is treated as an urgency/context signal, not proof that an individual IOC is malicious.**

This distinction helps prevent global threat conditions from being incorrectly interpreted as direct IOC evidence.

---

# 🎯 IOC Risk Analysis

Indicators are classified into:

- 🔴 **HIGH**
- 🟠 **MEDIUM**
- 🟢 **LOW**
- ⚪ **UNKNOWN**

The engine also calculates confidence based on the available intelligence.

For example:

```text
IOC Risk: MEDIUM
Confidence: MEDIUM
Pulse Count: 20
Recommendation: INVESTIGATE
```

An IOC with insufficient evidence is not automatically classified as safe.

---

# 🧠 MITRE ATT&CK Behavioral Mapping

The engine analyzes alert text and maps recognized behaviors to **MITRE ATT&CK Enterprise techniques**.

Current mappings include:

| Technique | Name |
|---|---|
| T1110 | Brute Force |
| T1078 | Valid Accounts |
| T1059 | Command and Scripting Interpreter |
| T1087 | Account Discovery |
| T1003 | OS Credential Dumping |

The system records:

- Technique ID
- Technique name
- Tactics
- Matched behavioral keywords
- MITRE ATT&CK description

MITRE ATT&CK is treated as **behavioral evidence associated with the alert**, rather than being incorrectly attached to individual IOC reputation records.

---

# 🧑‍💻 SOC Analyst Assessment

After enrichment, the engine produces an analyst-oriented assessment containing:

- Overall risk
- Highest IOC risk
- High-risk IOC count
- Medium-risk IOC count
- Low-risk IOC count
- Unknown-risk IOC count
- Overall confidence
- Recommended action
- Analyst summary
- MITRE ATT&CK findings

Possible recommendations include:

```text
ESCALATE
INVESTIGATE
MONITOR
REVIEW
```

This creates a simple SOC decision workflow:

```text
Threat Intelligence
        +
Global Context
        +
Behavioral Evidence
        ↓
Risk Assessment
        ↓
SOC Recommendation
```

---

# 📊 Example Investigation

A realistic test alert contained multiple suspicious behaviors:

```text
Multiple failed login attempts detected against the admin account.
The attacker appears to be using a compromised account.
PowerShell command execution was also detected after authentication.
Possible credential dumping activity targeting LSASS was observed.
The attacker performed account discovery to enumerate users.
```

The engine identified **5 MITRE ATT&CK techniques**:

```text
T1110  Brute Force
T1078  Valid Accounts
T1059  Command and Scripting Interpreter
T1087  Account Discovery
T1003  OS Credential Dumping
```

The resulting global threat context was:

```text
Threat Score: 71.82
Threat Level: HIGH
Urgency Modifier: HIGH
Context Status: success
```

The SOC assessment was:

```text
Overall Risk: MEDIUM
Confidence: MEDIUM
Recommended Action: INVESTIGATE

High-Risk IOCs: 0
Medium-Risk IOCs: 1
Low-Risk IOCs: 0
Unknown-Risk IOCs: 1
```

Example IOC results:

```text
185.10.10.25
    Risk: UNKNOWN
    Confidence: LOW
    Recommendation: REVIEW

malicious-example.com
    Risk: MEDIUM
    Confidence: MEDIUM
    Pulse Count: 20
    Recommendation: INVESTIGATE
```

This demonstrates how the engine combines **IOC intelligence + global context + behavioral analysis** rather than relying on a single signal.

---

# 📄 Automated Reporting

The engine produces four report formats:

```text
reports/
├── enrichment_results.json
├── enrichment_results.csv
├── mitre_attack.csv
└── enrichment_report.txt
```

### `enrichment_results.json`

Complete machine-readable investigation results containing:

- IOC enrichment
- Risk analysis
- Global threat context
- Analyst assessment
- MITRE ATT&CK analysis

### `enrichment_results.csv`

Contains **IOC-level intelligence**, including:

- Indicator
- Indicator type
- Threat intelligence source
- Pulse count
- Reputation
- IOC risk
- Confidence
- Global threat level
- Global threat score
- Urgency modifier
- SOC recommendation

### `mitre_attack.csv`

Contains **alert-level behavioral analysis**:

- Technique ID
- Technique name
- Tactics
- Matched keywords
- MITRE description

MITRE data is intentionally separated from the IOC CSV because MITRE techniques describe **alert behavior**, not individual IOC reputation.

### `enrichment_report.txt`

A concise SOC analyst-friendly report combining:

- Overall assessment
- Global threat context
- MITRE ATT&CK findings
- IOC enrichment results
- Risk reasons
- Recommendations

---

# 🧪 Testing

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
- MITRE ATT&CK mapping
- Report generation
- Empty alerts
- End-to-end pipeline

Run the tests with:

```bash
python -m unittest discover -s tests -v
```

### Final Test Result

```text
Ran 70 tests in 26.872s

OK
```

✅ **70 tests passed with zero failures.**

---

# 📁 Project Structure

```text
threat-intelligence-enrichment-engine/
│
├── data/
│   └── enterprise-attack.json
│
├── reports/
│   ├── enrichment_results.json
│   ├── enrichment_results.csv
│   ├── mitre_attack.csv
│   └── enrichment_report.txt
│
├── src/
│   ├── __init__.py
│   ├── analyst_workflow.py
│   ├── enrichment.py
│   ├── extract_iocs.py
│   ├── generate_report.py
│   ├── global_threat_context.py
│   ├── mitre_attack.py
│   ├── normalize_iocs.py
│   ├── risk_context.py
│   └── threat_intelligence.py
│
├── tests/
│   ├── __init__.py
│   ├── test_analyst_workflow.py
│   ├── test_end_to_end.py
│   ├── test_enrichment.py
│   ├── test_generate_report.py
│   ├── test_global_threat_context.py
│   ├── test_ioc_extraction.py
│   ├── test_mitre_attack.py
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

# ⚙️ Installation

## 1. Clone the repository

```bash
git clone https://github.com/jamese345/threat-intelligence-enrichment-engine.git
cd threat-intelligence-enrichment-engine
```

## 2. Create a virtual environment

```bash
python -m venv .venv
```

## 3. Activate the environment

### Windows

```bash
.venv\Scripts\activate
```

## 4. Install dependencies

```bash
python -m pip install -r requirements.txt
```

## 5. Configure environment variables

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

**Never commit `.env` or expose API keys publicly.**

## 6. Run the engine

```bash
python main.py
```

Reports will be generated inside:

```text
reports/
```

---

# 🔐 Security Considerations

This project is designed for defensive cybersecurity research, SOC automation, and threat intelligence analysis.

API credentials are loaded through environment variables and should never be committed to source control.

The engine also distinguishes between:

**Known malicious evidence**

and

**Insufficient intelligence / unknown**

An indicator that cannot be confirmed as malicious is **not automatically considered safe**.

This is an important principle when building automated security decision systems.

---

# 🛠️ Technologies Used

- Python
- Requests
- python-dotenv
- Regular Expressions
- unittest
- AlienVault OTX
- ICHI
- MITRE ATT&CK
- `mitreattack-python`
- JSON
- CSV

---

# 📈 Project Status

## ✅ Completed — v1.0.0

Implemented:

- [x] IOC extraction
- [x] IOC normalization
- [x] IOC deduplication
- [x] Threat intelligence enrichment
- [x] API error handling
- [x] Global threat context
- [x] IOC risk analysis
- [x] Confidence scoring
- [x] SOC recommendations
- [x] Analyst workflow
- [x] MITRE ATT&CK behavioral mapping
- [x] Alert-level MITRE reporting
- [x] IOC-level reporting
- [x] JSON reporting
- [x] CSV reporting
- [x] TXT SOC reporting
- [x] Reliability hardening
- [x] Automated testing
- [x] End-to-end validation

### Test Status

```text
70 tests
70 passed
0 failures
```

---

# 🔮 Future Improvements

Potential future enhancements include:

- [ ] Additional threat intelligence providers
- [ ] MISP integration
- [ ] IOC caching
- [ ] Threat intelligence correlation
- [ ] Web-based analyst dashboard
- [ ] SIEM integration
- [ ] LLM-assisted investigation
- [ ] Automated investigation summaries
- [ ] Expanded MITRE ATT&CK behavioral coverage
- [ ] Correlation between multiple alerts
- [ ] Historical IOC tracking

These improvements will contribute toward the larger goal of building a complete **AI SOC Analyst platform**.

---

# 🧠 What I Learned

This project strengthened my practical understanding of:

- Threat intelligence APIs
- IOC extraction and normalization
- API reliability and error handling
- Security automation
- Risk scoring
- Confidence scoring
- SOC analyst decision workflows
- MITRE ATT&CK behavioral mapping
- External threat context
- Automated reporting
- Python testing
- Building resilient security tooling

The project reinforced an important SOC principle:

> **Threat intelligence provides context; analyst decisions require correlation.**

---

# 👨‍💻 Author

**Brian Owala**

Cybersecurity Analyst focused on combining:

**Cybersecurity + Python + AI**

Currently building practical AI SOC projects with the long-term goal of becoming an **AI SOC Analyst**.

---

# 📚 Part of My AI SOC Journey

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

The long-term goal is to combine these capabilities into an intelligent SOC platform capable of:

```text
Detection
   ↓
Alert Triage
   ↓
Anomaly Detection
   ↓
Threat Intelligence
   ↓
Behavioral Analysis
   ↓
Investigation
   ↓
Response
```

---

# 📄 License

This project is licensed under the **MIT License**.