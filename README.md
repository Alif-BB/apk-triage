# 🔍 APK Triage Tool

> Static analysis · Google Threat Intelligence · Campaign Clustering  
> Built for **PDRM · BNM · CyberSecurity Malaysia** investigators tackling Malaysian mobile banking fraud (Macau scams, fake banking apps, SMS stealers).

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Project Structure](#project-structure)
4. [Prerequisites](#prerequisites)
5. [Installation](#installation)
6. [Configuration](#configuration)
7. [Running the App](#running-the-app)
8. [Usage Guide](#usage-guide)
   - [Triage Page](#triage-page)
   - [Campaign Clustering Page](#campaign-clustering-page)
9. [Case Package Contents](#case-package-contents)
10. [How Campaign Clustering Works](#how-campaign-clustering-works)
11. [Risk Scoring](#risk-scoring)
12. [IoC Extraction & False Positive Filtering](#ioc-extraction--false-positive-filtering)
13. [Database Schema](#database-schema)
14. [Testing](#testing)
15. [Submission Contacts](#submission-contacts)
16. [Limitations & Roadmap](#limitations--roadmap)
17. [Disclaimer](#disclaimer)

---

## Overview

APK Triage is a forensic analysis tool that enables law enforcement and financial institution security teams to rapidly assess suspicious Android APKs distributed as part of Malaysian financial scams.

A single APK upload produces:
- A **risk score** based on dangerous permissions, C2 indicators, and VirusTotal reputation
- A **court-ready case package** (digitally signed PDF, JSON evidence, BNMLINK template, chain-of-custody log)
- Automatic **campaign clustering** — linking APKs that share the same Telegram bot or IP address to identify coordinated syndicate operations

All analysis is performed **locally**. The only data sent externally is the APK's SHA-256 hash (and hardcoded IPs/URLs) to VirusTotal — the APK binary itself never leaves your machine.

---

## Features

### 🔍 Feature 1 — APK Triage & Automated Case Package
| Capability | Detail |
|---|---|
| Static analysis | Permissions, receivers, services, activities, hardcoded strings |
| Risk scoring | Weighted scoring across permissions, SMS receivers, Telegram C2, hardcoded IPs |
| GTI enrichment | VirusTotal hash + IP + URL reputation via `vt-py` |
| AI verdict | Gemini-powered 3-paragraph plain-English summary for non-technical investigators |
| Evidence integrity | MD5, SHA-1, SHA-256 computed and embedded in all exports |
| Signed PDF report | ReportLab + pyhanko digital signature (court-admissible) |
| JSON evidence file | Structured machine-readable evidence for SIEM / case management |
| BNMLINK template | Pre-filled incident report for BNMLINK / Cyber999 / PDRM CCID submission |
| Chain of custody | Timestamped CSV log of every action taken on the evidence |
| One-click ZIP | All of the above bundled into a single case package download |

### 🕸️ Feature 2 — Campaign Clustering
| Capability | Detail |
|---|---|
| Auto-save | Every APK analysis is automatically saved to a local SQLite database |
| C2 fingerprinting | Extracts Telegram bot tokens and hardcoded IPs as campaign pivot indicators |
| Auto-clustering | APKs sharing an identical C2 indicator are automatically grouped into a campaign |
| Campaign table | Filterable list of campaigns with member APK drilldown |
| Network graph | Interactive vis.js graph — APK nodes linked to C2 nodes, coloured by risk level |
| Timeline | All scans newest-first with score progress bar |
| Analyst actions | Rename campaigns, delete stale scans |

---

## Project Structure

```
apk-triage/
│
├── dashboard.py                  ← Home / landing page (Streamlit entry point)
│
├── pages/
│   ├── 1_🔍_Triage.py           ← APK upload, analysis, case package export
│   └── 2_🕸️_Campaigns.py        ← Campaign clustering UI
│
├── core/
│   ├── __init__.py
│   ├── analyser.py               ← APK parsing, hashing, IoC extraction, risk scoring
│   ├── gti.py                    ← VirusTotal / GTI API calls
│   ├── ai.py                     ← Gemini AI verdict generation
│   ├── pdf_report.py             ← ReportLab PDF + pyhanko digital signing
│   └── case_package.py           ← JSON evidence, BNMLINK template, CoC CSV, ZIP bundler
│
├── campaign/
│   ├── __init__.py
│   ├── db.py                     ← SQLite schema + connection helpers
│   ├── store.py                  ← Save scan results, auto-cluster by C2
│   └── cluster.py                ← Query logic for campaigns, graph, timeline
│
├── data/
│   └── campaign.db               ← SQLite database (auto-created, gitignored)
│
├── .streamlit/
│   └── secrets.toml              ← API keys (gitignored — never commit this)
│
├── test_campaign.py              ← Unit tests for campaign logic
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Prerequisites

| Requirement | Version |
|---|---|
| Python | 3.10 or higher |
| Operating System | Linux recommended (Kali, Ubuntu) — tested on Kali Linux in VMware |
| VirusTotal API key | Free tier (500 req/day) — https://virustotal.com |
| Google Gemini API key | Optional — enables AI verdicts |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/youruser/apk-triage.git
cd apk-triage

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

### `requirements.txt`

```
streamlit
androguard
vt-py
google-generativeai
loguru
reportlab
pyhanko
pyhanko-certvalidator
cryptography
pandas
```

---

## Configuration

Create the Streamlit secrets file — this is already listed in `.gitignore` so it will never be committed:

```bash
mkdir -p .streamlit
nano .streamlit/secrets.toml
```

Add your API keys:

```toml
# .streamlit/secrets.toml

# VirusTotal / Google Threat Intelligence
# Get a free key at: https://www.virustotal.com/gui/join-us
VT_API_KEY = "your_virustotal_api_key_here"

# Google Gemini (optional — enables AI verdicts)
# Get a key at: https://aistudio.google.com/app/apikey
GEMINI_API_KEY = "your_gemini_api_key_here"
```

If `secrets.toml` is not present or a key is missing:
- **VT_API_KEY** — the tool falls back to a password input field in the sidebar
- **GEMINI_API_KEY** — AI verdict section is hidden with a notice to contact admin

---

## Running the App

```bash
# Activate venv first if not already active
source venv/bin/activate

# Launch the app
streamlit run dashboard.py
```

The app opens at `http://localhost:8501` in your browser. Use the sidebar to navigate between pages.

---

## Usage Guide

### Triage Page

1. **Fill in analyst details** in the sidebar — name, badge number, unit/organisation, case reference number, and document classification. These are embedded in all exported files for chain-of-custody purposes.

2. **Upload an APK** using the file uploader. Supported: `.apk` files only.

3. The tool runs automatically in sequence:
   - Static analysis (permissions, IoCs, risk scoring)
   - GTI enrichment via VirusTotal (if API key is configured)
   - AI verdict via Gemini (if API key is configured)
   - Auto-save to the campaign database

4. Review the results — risk gauge, evidence integrity hashes, GTI detections, permissions, IoCs, and app components.

5. **Download the Case Package** (ZIP) for a complete court-ready evidence bundle, or download individual files (PDF, JSON, incident report, CoC log).

> ⚠️ If no analyst name is entered, a warning is shown. All exported files will show "Not specified" in the analyst field.

---

### Campaign Clustering Page

Navigate to **🕸️ Campaigns** in the sidebar after analysing at least one APK.

**Header stats** show total APKs in the database, number of campaigns detected, critical-risk APKs, unique Telegram C2s, and unique IP-based C2s.

**Campaigns tab:**
- Filter by C2 type (All / Telegram / IP)
- Each campaign shows its pivot indicator, first/last seen dates, and APK count
- Expand a campaign to see all linked APKs in a table
- Rename a campaign to reflect intelligence findings (e.g. "Operation Maybank Ghost")
- Delete individual scans from the database

**Network Graph tab:**
- APK nodes (circles) coloured by risk level: 🔴 CRITICAL · 🟠 HIGH · 🟡 MEDIUM · 🟢 LOW
- C2 nodes (diamonds) coloured by type: 🔵 Telegram · 🟣 IP · 🟢 URL
- APKs connected to the same C2 node belong to the same campaign
- Hover over any node for details (package name, risk score, SHA-256, analyst)
- Drag, zoom, and pan to explore the graph

**Timeline tab:**
- All scans ordered newest-first
- Score shown as a visual progress bar
- GTI detection count and threat label visible at a glance

---

## Case Package Contents

Each downloaded `.zip` contains:

| File | Purpose |
|---|---|
| `triage_report_*_signed.pdf` | Court-ready forensic report with embedded digital signature. Verifiable in Adobe Acrobat. |
| `evidence_*.json` | Structured machine-readable evidence. Suitable for SIEM ingestion, case management systems, or inter-agency sharing. |
| `incident_report_template_*.txt` | Pre-filled incident report for submission to BNMLINK, Cyber999, or PDRM CCID. Fill in victim details before sending. |
| `chain_of_custody_*.csv` | Timestamped log of every action taken on the evidence (received → hashed → analysed → GTI queried → report generated). |
| `README.txt` | Submission contacts and file guide. |

> The PDF is signed with a self-signed certificate generated on first run and stored at `~/.apktriage_signer.p12`. For formal court submission, replace this with an agency-issued PKI certificate.

---

## How Campaign Clustering Works

Campaign clustering is based on **exact C2 indicator matching** across APKs.

### Step 1 — IoC Extraction
Androguard reads every string constant embedded in the APK's DEX bytecode. Four regex patterns are applied:

| Pattern | Matches |
|---|---|
| `TELEGRAM_PATTERN` | Telegram bot tokens (`bot<id>:<token>`) and `t.me/` links |
| `IP_PATTERN` | IPv4 addresses — filtered against a comprehensive exclusion list |
| `URL_PATTERN` | HTTP/HTTPS URLs — filtered against Android/SDK namespace noise |
| `KEYWORD_PATTERN` | Malaysian bank names, TAC, OTP, transaction |

### Step 2 — Normalisation & Storage
Each IoC is stored as a separate row in the `c2_indicators` table, linked to the APK scan by `scan_id`.

### Step 3 — Auto-Clustering
For each extracted IoC, the tool checks whether a campaign already exists for that exact value:
- **Yes** → `apk_count + 1`, `last_seen` updated
- **No** → new campaign row created with an auto-generated name

Two APKs are considered part of the same campaign when they share an **identical `ioc_value`** — for example, the same Telegram bot token or the same hardcoded IP address.

### Campaign Pivot Types
| Type | Signal strength | Rationale |
|---|---|---|
| Telegram token | 🔴 Very strong | Unique per bot, directly operator-controlled, almost never a false positive |
| IP address | 🟠 Strong | Hardcoded C2 server IPs after private/loopback/multicast exclusion |
| URL | Not used as pivot | Too noisy — URLs still shown in triage report for analyst review |

---

## Risk Scoring

| Score | Level | Meaning |
|---|---|---|
| 0 | CLEAN | No suspicious indicators |
| 1–29 | LOW | Minor indicators, likely benign |
| 30–59 | MEDIUM | Multiple indicators, manual review recommended |
| 60–89 | HIGH | Strong malicious indicators |
| 90+ | CRITICAL | Confirmed malware pattern — matches Malaysian financial scam profile |

### Score Contributors

| Indicator | Points |
|---|---|
| `RECEIVE_SMS` permission | +50 |
| `BIND_ACCESSIBILITY_SERVICE` permission | +30 |
| `READ_SMS` permission | +25 |
| `SYSTEM_ALERT_WINDOW` permission | +25 |
| SMS-related broadcast receiver | +25 |
| `SEND_SMS` permission | +20 |
| `REQUEST_INSTALL_PACKAGES` permission | +20 |
| Per hardcoded IP address | +20 |
| `READ_CONTACTS` permission | +15 |
| `RECORD_AUDIO` permission | +15 |
| `PROCESS_OUTGOING_CALLS` permission | +15 |
| `READ_CALL_LOG` permission | +15 |
| BOOT receiver | +15 |
| `CAMERA` permission | +10 |
| Banking keywords (TAC/OTP/bank names) | +10 |
| Per Telegram C2 indicator | +40 |
| GTI: >20 AV engines flagged | +50 |
| GTI: 6–20 AV engines flagged | +30 |
| GTI: 1–5 AV engines flagged | +15 |
| GTI: confirmed malicious IP | +20 each |
| GTI: confirmed malicious URL | +10 each |

---

## IoC Extraction & False Positive Filtering

### IP Addresses — Excluded ranges
The following are automatically excluded from IoC extraction and campaign clustering:

- Loopback: `127.0.0.0/8`
- Unspecified: `0.x.x.x`
- Broadcast: `255.x.x.x`
- Private RFC1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- Link-local: `169.254.0.0/16`
- Multicast: `224.0.0.0/4`
- Android emulator: `10.0.2.2`, `10.0.2.15`, `10.0.3.2`
- Google Public DNS: `8.8.8.8`, `8.8.4.4`
- Cloudflare DNS: `1.1.1.1`, `1.0.0.1`
- RFC5737 documentation: `192.0.2.x`, `198.51.100.x`, `203.0.113.x`
- Version-like strings: `1.0.0.0`, `0.0.0.1`
- Malformed addresses

### URLs — Excluded prefixes
Namespace URIs and SDK reference strings are filtered out, including:
`schemas.android.com`, `www.w3.org`, `developer.android.com`, `firebase.google.com`, `play.google.com`, `graph.facebook.com`, `maven.apache.org`, and others.

URLs remain visible in the triage report for analyst review but are **not used as campaign clustering pivots**.

---

## Database Schema

SQLite database located at `data/campaign.db` (auto-created on first run).

```sql
-- One row per analysed APK
CREATE TABLE apk_scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    package       TEXT    NOT NULL,
    version       TEXT,
    sha256        TEXT    NOT NULL UNIQUE,  -- duplicate prevention
    md5           TEXT,
    sha1          TEXT,
    risk_score    INTEGER NOT NULL DEFAULT 0,
    risk_level    TEXT    NOT NULL DEFAULT 'UNKNOWN',
    min_sdk       TEXT,
    target_sdk    TEXT,
    analyst_name  TEXT,
    analyst_org   TEXT,
    case_number   TEXT,
    gti_malicious INTEGER DEFAULT 0,
    gti_total     INTEGER DEFAULT 0,
    gti_threat    TEXT,
    ai_verdict    TEXT,
    scanned_at    TEXT    NOT NULL,
    keywords      TEXT,   -- JSON array
    permissions   TEXT    -- JSON array (dangerous only)
);

-- Normalised C2 indicators (one row per IoC per APK)
CREATE TABLE c2_indicators (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    INTEGER NOT NULL REFERENCES apk_scans(id) ON DELETE CASCADE,
    ioc_type   TEXT    NOT NULL,  -- 'telegram' | 'ip'
    ioc_value  TEXT    NOT NULL,
    UNIQUE(scan_id, ioc_type, ioc_value)
);

-- Campaign groups (one row per unique C2 value)
CREATE TABLE campaigns (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,  -- auto-generated or analyst-renamed
    pivot_type  TEXT    NOT NULL,  -- 'telegram' | 'ip'
    pivot_value TEXT    NOT NULL,  -- the shared C2 value
    first_seen  TEXT    NOT NULL,
    last_seen   TEXT    NOT NULL,
    apk_count   INTEGER NOT NULL DEFAULT 1,
    UNIQUE(pivot_type, pivot_value)
);
```

Query the database directly:
```bash
sqlite3 data/campaign.db
```
```sql
-- Overview
SELECT 'APK scans',   COUNT(*) FROM apk_scans
UNION ALL
SELECT 'C2 indicators', COUNT(*) FROM c2_indicators
UNION ALL
SELECT 'Campaigns',   COUNT(*) FROM campaigns;

-- All campaigns with member count
SELECT name, pivot_type, pivot_value, apk_count, first_seen, last_seen
FROM campaigns ORDER BY apk_count DESC;

-- APKs in a specific campaign
SELECT s.package, s.risk_level, s.sha256, s.scanned_at
FROM apk_scans s
JOIN c2_indicators c ON c.scan_id = s.id
WHERE c.ioc_value = 't.me/yourbotname';
```

---

## Testing

### Unit Tests

```bash
source venv/bin/activate
python test_campaign.py
```

Runs 10 automated tests covering: basic save, duplicate SHA-256 prevention, campaign auto-creation, multi-APK grouping, campaign member queries, IP-based clustering, stats accuracy, network graph node/edge counts, campaign rename, and scan deletion with cascade.

### Manual Test Scenarios

| Scenario | Steps | Expected |
|---|---|---|
| First APK | Upload any APK | Green "Saved to campaign database (Scan #1)" toast |
| Duplicate | Upload same APK again | Blue "Already in database" info message |
| Campaign grouping | Upload 2 APKs sharing a Telegram token | Campaign shows `apk_count = 2` |
| Network graph | 3+ APKs in DB | APK nodes and C2 nodes visible, connected by edges |
| Clean APK | Upload APK with no IoCs | Saved to timeline, no new campaign created |

### Data Integrity Check

```bash
sqlite3 data/campaign.db << 'SQL'
.headers on
.mode column
-- Check for orphaned indicators
SELECT 'Orphaned indicators:', COUNT(*)
FROM c2_indicators c
LEFT JOIN apk_scans s ON s.id = c.scan_id
WHERE s.id IS NULL;
SQL
```

### Recommended Test APK Families

For campaign clustering tests, use samples from these malware families (download from MalwareBazaar):

| Family | C2 type | Why useful |
|---|---|---|
| SpyNote / SpyMax | Hardcoded IP | One operator → same VPS → multiple APKs |
| Tria Stealer | Telegram bot token | Confirmed Malaysia/Brunei campaign, reused bot tokens |
| TrAd / Macau Scam variants | Telegram bot | SMS stealers impersonating MY government/bank apps |
| Cerberus / Alien | Hardcoded IP | Commercial C2 panel shared across APK builds |

> ⚠️ Handle all malware samples inside a sandboxed VM only (Kali Linux / VMware recommended). Never run or extract samples on your host machine.

---

## Submission Contacts

| Agency | Contact | Purpose |
|---|---|---|
| **BNMLINK** (Bank Negara Malaysia) | bnmlink@bnm.gov.my · 1-300-88-5465 | Financial fraud reports |
| **Cyber999** (CyberSecurity Malaysia) | cyber999@cybersecurity.my · 1-300-88-2999 | Malware sample submission |
| **PDRM CCID** | ccid.rmp.gov.my | Police reports — cybercrime |
| **MyCERT** | mycert@cybersecurity.my | C2 IP/domain takedown requests |
| **Telegram** | https://telegram.org/support | Bot token abuse reports |

---

## Limitations & Roadmap

### Current Limitations

- **Exact-match clustering only** — two APKs from the same syndicate that rotated their C2 infrastructure will not be linked. Fuzzy matching or ASN correlation is not yet implemented.
- **Static analysis only** — dynamic behaviour (runtime C2 connections, payload decryption) is not observed. For dynamic analysis, submit samples to Tria.ge or Any.run.
- **Self-signed PDF certificate** — the digital signature is cryptographically valid but not issued by a trusted CA. For formal court submission, replace `~/.apktriage_signer.p12` with an agency-issued certificate.
- **URL clustering disabled** — URLs are extracted and shown in reports but not used as campaign pivots due to high false-positive rates from Android SDK namespace strings.
- **No obfuscation handling** — APKs that encrypt their C2 strings at runtime will evade string-based extraction.

### Potential Feature 3 — Fuzzy Campaign Linking
- ASN/WHOIS correlation for IP-based campaigns (same subnet = same operator)
- Telegram username cross-referencing
- Code similarity scoring between APK variants
- ML-based clustering on permission + IoC fingerprints

---

## Disclaimer

This tool is intended for **authorised law enforcement, financial institution security teams, and cybersecurity researchers** investigating Malaysian mobile banking fraud. All APK samples analysed should be obtained legally and handled in accordance with applicable Malaysian law (Computer Crimes Act 1997, Communications and Multimedia Act 1998).

The authors are not responsible for misuse of this tool or the information it produces. APK hash data is submitted to VirusTotal during analysis — do not analyse APKs containing sensitive or classified information without reviewing VirusTotal's privacy policy.

> Built with ❤️ for Malaysia's cybersecurity community.
