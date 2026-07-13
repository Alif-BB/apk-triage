# 🔍 A-Analyzer: APK Triage & Threat Intelligence Tool

> Static analysis · Google Threat Intelligence (VirusTotal) · Campaign Clustering  
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
8. [Database Engine & Dynamic Routing](#database-engine--dynamic-routing)
9. [Database Migration Guide](#database-migration-guide)
10. [Database Schema](#database-schema)
11. [Usage Guide](#usage-guide)
12. [Case Package Contents](#case-package-contents)
13. [How Campaign Clustering Works](#how-campaign-clustering-works)
14. [Risk Scoring](#risk-scoring)
15. [IoC Extraction & False Positive Filtering](#ioc-extraction--false-positive-filtering)
16. [Deployment & Developer Workflow](#deployment--developer-workflow)
17. [Testing & Verification](#testing--verification)
18. [Submission Contacts](#submission-contacts)
19. [Limitations & Roadmap](#limitations--roadmap)
20. [Disclaimer](#disclaimer)

---

## Overview

A-Analyzer is a forensic triage and threat intelligence tool that enables law enforcement and financial institution security teams to rapidly assess suspicious Android APKs distributed as part of Malaysian financial scams.

A single APK upload produces:
- A weighted **risk score** based on dangerous permissions, SMS broadcast receivers, hardcoded C2 infrastructure, and VirusTotal reputation.
- A **court-ready case package** (including a digitally signed PDF, structured JSON evidence, pre-filled BNMLINK template, and a chronological chain-of-custody log).
- Automatic **campaign clustering** — dynamically linking separate APKs that share identical C2 infrastructure (such as Telegram bot tokens or hardcoded IP addresses) to identify coordinated syndicate operations.

All decompilation and static parsing are performed **locally** on your analysis workstation. The only data sent externally is the APK's SHA-256 hash (to check VirusTotal reputation) and AI prompt queries if Gemini enrichment is active. The raw APK binary itself never leaves your machine.

---

## Features

### 🔍 Feature 1 — APK Triage & Automated Case Package
| Capability | Detail |
|---|---|
| **Static analysis** | Extracts permissions, intent receivers, background services, activities, and embedded string constants. |
| **Risk scoring** | Applies weighted risk scores across suspicious permissions, accessibility bindings, SMS stealers, and C2 indicators. |
| **GTI enrichment** | Queries VirusTotal hash, IP, and URL reputations on-demand using the asynchronous `vt-py` SDK. |
| **AI verdict** | Synthesizes Gemini AI-driven 3-paragraph executive summaries for non-technical prosecutors and investigators. |
| **Evidence integrity** | Computes MD5, SHA-1, and SHA-256 hashes, embedding them in all exported materials to preserve evidentiary value. |
| **Signed PDF report** | Formats professional PDF briefs with ReportLab and adds verifiable digital signatures using `pyhanko`. |
| **JSON evidence file** | Exposes structured machine-readable analysis data for SIEM ingestion and case management. |
| **BNMLINK template** | Pre-fills incident response templates for Bank Negara Malaysia (BNMLINK), MyCERT, or PDRM CCID. |
| **Chain of custody** | Compiles a timestamped chronological CSV log recording every action taken on the evidence files. |
| **One-click ZIP** | Bundles the complete court-ready case package into a single, structured archive for download. |

### 🕸️ Feature 2 — Campaign Clustering
| Capability | Detail |
|---|---|
| **Seamless auto-save** | Automatically logs every APK analysis record to the database upon upload. |
| **C2 fingerprinting** | Parses DEX bytecode strings to isolate Telegram bot tokens, t.me URLs, and hardcoded IPv4 addresses. |
| **Auto-clustering** | Dynamically groups separate APKs sharing identical C2 pivot points under unique campaign designations. |
| **Interactive network graph**| Renders a premium, dynamic web-graph mapping APKs (coloured by risk) to their shared C2 nodes. |
| **Intelligence timeline** | Displays a historical ledger of analyzed files ordered newest-first with visual score progress meters. |
| **Analyst actions** | Permits manual renaming of campaign clusters (e.g. "Operation Maybank Ghost") and pruning stale entries. |

---

## Project Structure

```
apk-triage/
│
├── dashboard.py                  ← Home / landing page (Streamlit entry point)
│
├── DEVELOPMENT_WORKFLOW.md       ← Step-by-step developer guide for update deployments
├── README.md                     ← This main documentation file
├── app_icon.svg                  ← Standalone vector logo asset
│
├── .streamlit/
│   ├── config.toml               ← Streamlit styling and server configuration
│   └── secrets.toml              ← Local API keys & DB configuration (gitignored)
│
├── pages/
│   ├── 1_🔍_Triage.py           ← Forensic APK upload, analysis, and case ZIP packaging
│   └── 2_🕸️_Campaigns.py        ← Campaign clustering, dynamic timeline, and network graph
│
├── core/
│   ├── __init__.py
│   ├── analyser.py               ← APK parsing, decompilation, IoC extraction, and risk math
│   ├── gti.py                    ← VirusTotal / GTI API integration
│   ├── ai.py                     ← Gemini AI text synthesis helper
│   ├── pdf_report.py             ← ReportLab layout compiler + pyhanko cryptographic signer
│   └── case_package.py           ← Structured JSON, pre-filled submission files, and ZIP packager
│
├── campaign/
│   ├── __init__.py
│   ├── db.py                     ← Dual SQLite/Postgres DB driver with custom compatibility wrappers
│   ├── store.py                  ← Analysis database insert/update logic and campaign grouping
│   └── cluster.py                ← Graph modeling, campaign statistics, and chronological timelines
│
├── data/
│   └── campaign.db               ← Local SQLite database (fallback; auto-created, gitignored)
│
├── scripts/
│   └── migrate_data.py           ← Offline-to-Cloud (SQLite to Supabase Postgres) migration script
│
├── utils/
│   ├── __init__.py
│   └── styles.py                 ← Premium UI components, brand colors, custom metrics, and fonts
│
├── decode.py                     ← Helper utility to XOR-decode obfuscated APK strings
├── requirements.txt              ← Python packaging dependencies
└── venv/                         ← Local Python virtual environment
```

---

## Prerequisites

| Requirement | Recommended Version |
|---|---|
| **Python** | `3.10` or higher |
| **Operating System** | macOS or Linux (tested on Kali Linux / Ubuntu) |
| **VirusTotal API Key** | Free tier (500 queries/day) — register at [virustotal.com](https://virustotal.com) |
| **Google Gemini API Key** | Optional — generates executive AI summaries at [aistudio.google.com](https://aistudio.google.com) |

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/youruser/apk-triage.git
cd apk-triage

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install core and driver dependencies
pip install -r requirements.txt
```

---

## Configuration

Create the local Streamlit secrets file (already added to `.gitignore` so it will never be committed to Git):

```bash
mkdir -p .streamlit
nano .streamlit/secrets.toml
```

Populate the secrets file with your API keys and optional database connection credentials:

```toml
# .streamlit/secrets.toml

# VirusTotal / Google Threat Intelligence
VT_API_KEY = "your_virustotal_api_key_here"

# Google Gemini (Optional — enables AI summaries)
GEMINI_API_KEY = "your_gemini_api_key_here"

# Supabase PostgreSQL (Optional — activates Cloud Shared Database)
# Use the Connection Pooler URL (Port 6543) for best IPv4/IPv6 compatibility
SUPABASE_DB_URL = "postgresql://postgres.yourref:yourpassword@aws-0-ap-southeast-1.pooler.supabase.com:6543/postgres"
```

If `secrets.toml` is not present or keys are missing:
* **`VT_API_KEY`**: The application will show a sidebar password text-input field where analysts can paste their API keys temporarily.
* **`GEMINI_API_KEY`**: The executive summary section will display a helpful administrative configuration notice.
* **`SUPABASE_DB_URL`**: The database transparently switches to the local SQLite database at `data/campaign.db`.

---

## Running the App

```bash
# Activate your virtual environment first
source venv/bin/activate

# Launch the Streamlit server
streamlit run dashboard.py
```

The application opens automatically at `http://localhost:8501` in your browser.

---

## Database Engine & Dynamic Routing

A-Analyzer is equipped with a **Dual-Driver Database Architecture** built into `campaign/db.py`:

```mermaid
graph TD
    A[Streamlit App Startup] --> B{SUPABASE_DB_URL configured?}
    B -->|Yes - Cloud / Production| C[Connect to Supabase PostgreSQL]
    B -->|No - Local / Offline| D[Connect to Local SQLite campaign.db]
    C --> E[PostgresCursorWrapper handles ? and SQLite syntax]
    D --> F[Standard sqlite3 library handles queries]
```

### 1. Connection Pooler Configuration (IPv4 Port 6543)
Direct connections to Supabase PostgreSQL instances (`db.[ref].supabase.co` on port `5432`) are IPv6-only by default. In local networks or ISP configurations without active IPv6 routing, direct connections throw `nodename nor servname provided, or not known`.
* **Solution**: Always use Supabase's **Connection Pooler** URL on port **`6543`**. This pooler operates perfectly over IPv4 networks.

### 2. Automatic Password Sanitization
Database passwords with special characters (such as `#`, `@`, or `:`) throw driver parsing errors in standard libpq/psycopg2.
* **Solution**: The application implements `sanitize_db_url(url)` to isolate the credentials segment and safely URL-encode password components automatically behind the scenes.

### 3. Syntax Adapters
To keep application-level queries database-agnostic, `campaign/db.py` implements transparent cursor and connection wrappers (`PostgresConnectionWrapper`, `PostgresCursorWrapper`):
* Translates parameters dynamically (`?` parameters are swapped to `%s`).
* Adapts transaction conflicts (`INSERT OR IGNORE` matches are updated to PostgreSQL's `ON CONFLICT DO NOTHING`).
* Directs SQLite `.lastrowid` access queries to Postgres-native `SELECT LASTVAL()` sequences.
* Guarantees identical dictionary row access with `psycopg2.extras.DictCursor`.

---

## Database Migration Guide

If you have been analyzing APKs locally using the SQLite backend and wish to push your history, campaigns, and indicators into your shared cloud Supabase PostgreSQL server, use the integrated migration utility:

```bash
# 1. Activate environment
source venv/bin/activate

# 2. Set your destination database URL in .streamlit/secrets.toml
# 3. Run the migration script
python scripts/migrate_data.py
```

The script will:
1. Verify connection credentials and establish conduits with both engines.
2. Initialize tables on the remote PostgreSQL backend if they don't exist yet.
3. Migrate `apk_scans`, `c2_indicators`, and `campaigns` records while handling duplicates automatically.
4. Align PostgreSQL's primary key index sequences with `setval(pg_get_serial_sequence(), ...)` to prevent future insertion collisions.

---

## Database Schema

The database relies on three main normalized tables:

### 1. `apk_scans`
Stores core metadata and risk scores for each analyzed file.

| Column | Type (SQLite) | Type (PostgreSQL) | Description |
|---|---|---|---|
| **`id`** | `INTEGER PRIMARY KEY` | `SERIAL PRIMARY KEY` | Unique ID for each scan. |
| **`package`** | `TEXT NOT NULL` | `TEXT NOT NULL` | Android app package ID. |
| **`version`** | `TEXT` | `TEXT` | App version string. |
| **`sha256`** | `TEXT NOT NULL UNIQUE`| `TEXT NOT NULL UNIQUE` | File SHA-256 (prevents duplicates). |
| **`md5`** | `TEXT` | `TEXT` | File MD5 hash. |
| **`sha1`** | `TEXT` | `TEXT` | File SHA-1 hash. |
| **`risk_score`**| `INTEGER NOT NULL` | `INTEGER NOT NULL` | Final calculated risk level (0-100). |
| **`risk_level`**| `TEXT NOT NULL` | `TEXT NOT NULL` | Human-readable score band label. |
| **`analyst_name`**| `TEXT` | `TEXT` | Forensic analyst's identity. |
| **`gti_malicious`**| `INTEGER DEFAULT 0`| `INTEGER DEFAULT 0` | VirusTotal malicious flags. |
| **`gti_threat`**| `TEXT` | `TEXT` | Detected family or threat category. |
| **`ai_verdict`**| `TEXT` | `TEXT` | Gemini summary text block. |
| **`scanned_at`**| `TEXT NOT NULL` | `TEXT NOT NULL` | ISO timestamp of the analysis. |
| **`permissions`**| `TEXT` | `TEXT` | JSON-encoded array of dangerous permissions. |

### 2. `c2_indicators`
Normalized table tracking extracted command-and-control indicators linked to scans.

| Column | Type | Description |
|---|---|---|
| **`id`** | `INTEGER` / `SERIAL` | Primary Key. |
| **`scan_id`** | `INTEGER REFERENCES apk_scans(id)` | Cascading foreign key link. |
| **`ioc_type`** | `TEXT NOT NULL` | `telegram` or `ip`. |
| **`ioc_value`**| `TEXT NOT NULL` | Shared target string (IP or Bot Token). |

### 3. `campaigns`
Consolidated campaign clusters.

| Column | Type | Description |
|---|---|---|
| **`id`** | `INTEGER` / `SERIAL` | Primary Key. |
| **`name`** | `TEXT NOT NULL` | Auto-generated ID or analyst-updated designation. |
| **`pivot_type`**| `TEXT NOT NULL` | Indicator type defining the campaign (`telegram` or `ip`). |
| **`pivot_value`**| `TEXT NOT NULL` | The literal C2 string that links the members together. |
| **`apk_count`** | `INTEGER DEFAULT 1` | Total number of APKs clustered under this campaign. |

---

## Usage Guide

### Triage Page (🔍 Triage)
1. **Analyst Profile**: Fill in your analyst parameters (name, badge number, case reference) in the sidebar. This metadata is permanently stamped into the final case packages and PDF briefs.
2. **Decompile APK**: Drag and drop a suspicious `.apk` package into the uploader. 
3. **Automated Run-through**: The engine instantly parses the package locally, calculates risk math, checks VirusTotal reputation asynchronously, queries the Gemini model for an executive briefing, and logs the analysis to the shared database.
4. **Acquire Court Evidence**: Download individual files or select the **Case Package (ZIP)** option. This bundles the signed PDF report, structured JSON, pre-populated escalation forms, and chain-of-custody audit logs in seconds.

### Campaign Page (🕸️ Campaigns)
1. **Shared Dashboard**: Review general repository stats: total analyzed APKs, identified syndicates, critical targets, and unique C2 resources.
2. **Campaign Explorer**: Filter active threats by indicator type, review first/last-seen timestamps, drill down into campaign tables, rename campaigns, and prune database noise.
3. **Interactive Graph**: Navigate a premiumVis.js network topology. Explore spatial nodes representing physical files and their underlying connections to servers or bot infrastructure.

---

## Case Package Contents

The downloaded `.zip` case package contains standard forensically structured files:

| File | Type | Purpose |
|---|---|---|
| **`triage_report_*_signed.pdf`** | Cryptographic PDF | Verifiable forensic brief signed digitally using a local `.p12` PKI certificate file. |
| **`evidence_*.json`** | Structured JSON | Machine-readable metadata dump suitable for SIEM, MISP, or case management ingestion. |
| **`incident_report_template_*.txt`**| Pre-filled TXT | Pre-formatted incident briefing. Simply input victim specifics and escalate directly to BNMLINK/PDRM. |
| **`chain_of_custody_*.csv`** | Audit CSV | Non-repudiation log containing timestamps, action steps, and matching hashes (MD5, SHA-1, SHA-256). |
| **`README.txt`** | Text Guide | File inventory and official contact directory. |

---

## How Campaign Clustering Works

```
[ APK Upload ]
      │
      ▼
[ DEX String Parse ]
      │
      ├─── Extract Telegram Bot Token (bot<id>:<token>)  ──►  🟢 Telegram Pivot
      └─── Extract Hardcoded IPv4 Address (Excluding IPs)  ──►  🔵 IP Pivot
      │
      ▼
[ Database Query ]
      │
      ├─── Pivot Value Matches Existing Campaign?
      │          ├─── Yes ──► Link Scan to Campaign, Increment APK Count, Update last_seen
      │          └─── No  ──► Generate New Campaign Name, Initialize Cluster Record
```

* **Telegram Bot Tokens**: Classed as **🔴 Very Strong** signals. They are uniquely assigned, operator-controlled, and constitute explicit evidence of syndicate coordination.
* **IP Addresses**: Classed as **🟠 Strong** signals. They are mapped to active command-and-control nodes after removing common developer domains, CDNs, local loops, and public nameservers.
* **URLs**: Classed as review indicators only. They are extracted and presented in reports but excluded from automated grouping logic to prevent false-positives from standard Android SDK namespaces.

---

## Risk Scoring

Risk scores range from **0** (Clean) to **100** (Critical) across weighted parameters:

| Category | Indicator / Capability | Weight |
|---|---|---|
| **Permissions** | `RECEIVE_SMS` (Intercept messages) | **+50** |
| | `BIND_ACCESSIBILITY_SERVICE` (UI Stealer/Keylogging) | **+30** |
| | `READ_SMS` (Read existing inbox) | **+25** |
| | `SYSTEM_ALERT_WINDOW` (Overlay injection) | **+25** |
| | `SEND_SMS` (Siloed TAC/OTP exfiltration) | **+20** |
| | `REQUEST_INSTALL_PACKAGES` (Sideload payload updates) | **+20** |
| **DEX / Strings**| Hardcoded IP Address (Not excluded) | **+20** each |
| | SMS Receiver Component (Custom receiver logic) | **+25** |
| | Telegram C2 bot token / API string | **+40** |
| | Malaysian Banking keywords (TAC, OTP, Bank Names) | **+10** |
| **GTI / VT** | > 20 Antivirus engines flag hash as malicious | **+50** |
| | 6 - 20 Antivirus engines flag hash as malicious | **+30** |
| | 1 - 5 Antivirus engines flag hash as malicious | **+15** |
| | Malicious IP reputation match | **+20** each |
| | Malicious URL reputation match | **+10** each |

---

## IoC Extraction & False Positive Filtering

To avoid false associations on common development domains and local networks, string parsers apply strict CIDR exclusions and namespace rules:

* **Excluded IP Ranges**: Loopback (`127.0.0.0/8`), Private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), Link-local (`169.254.0.0/16`), multicast, emulator addresses (`10.0.2.2`), and public nameservers (`8.8.8.8`, `1.1.1.1`).
* **Excluded URLs**: Common Android SDK references such as `schemas.android.com`, `www.w3.org`, `developer.android.com`, `firebase.google.com`, `play.google.com`, and `graph.facebook.com`.

---

## Deployment & Developer Workflow

A-Analyzer is set up with complete continuous deployment to Streamlit Community Cloud. For detailed, step-by-step instructions on switching branches, local debugging, merging updates safely, pushing code, and synchronizing secrets, consult the **[DEVELOPMENT_WORKFLOW.md](file:///Users/mohdalifridzuanahmad/Documents/imp_docs/Projects/A-Analyzer/apk-triage/DEVELOPMENT_WORKFLOW.md)** document located in the project root.

---

## Testing & Verification

### 1. Manual Verification Tests

Ensure database mechanics, routing, and UI rendering are working seamlessly with these test scenarios:

| Action | Target Step | Expected Result |
|---|---|---|
| **Analyze New APK** | Upload any standard APK | Display green confirmation notice: `"Saved to campaign database"`. |
| **Verify Duplicate** | Upload the identical APK again | Display blue notification: `"Already in database — showing cached analysis"`. |
| **Test Campaign Grouping**| Upload two distinct APKs sharing a Telegram bot token | Verify the campaign table records `apk_count = 2` for that shared token. |
| **Explore Network Graph**| Open the Campaigns tab and navigate to the Network Graph | Verify circular APK nodes link to diamond-shaped C2 nodes with correct edges. |

### 2. Live Database Connectivity Check
To confirm that your local environment connects safely to your remote Supabase instance or local SQLite file before starting Streamlit, execute this quick connectivity command in your virtual environment:

```bash
python -c "from campaign.db import get_connection, get_connection_url; conn=get_connection(); print('[+] Active connection:', type(conn).__name__); print('[+] Configured URL:', get_connection_url() is not None)"
```

---

## Submission Contacts

For escalating confirmed scam infrastructure and malicious APK cases:

| Target | Organization | Purpose / Link |
|---|---|---|
| **BNMLINK** | Bank Negara Malaysia | Financial fraud reports: `bnmlink@bnm.gov.my` / 1-300-88-5465 |
| **Cyber999**| CyberSecurity Malaysia | Incident escalation & takedowns: `cyber999@cybersecurity.my` |
| **PDRM CCID**| Commercial Crime Investigation Dept | Cybercrime reports: [ccid.rmp.gov.my](https://ccid.rmp.gov.my) |
| **MyCERT** | Malaysia Computer Emergency Response | C2 IP/domain takedown requests: `mycert@cybersecurity.my` |
| **Telegram**| Telegram Abuse Team | Bot token abuse reports: [telegram.org/support](https://telegram.org/support) |

---

## Limitations & Roadmap

* **Obfuscation**: Highly packed APKs or those utilizing runtime string-encryption will evade standard static extraction.
* **Dynamic Indicators**: Out-of-band C2 addresses resolved dynamically are not tracked. For advanced behavioral analysis, execute samples in interactive sandboxes (Tria.ge or Any.run).
* **Fuzzy campaign linkages**: Implementing ASN/WHOIS IP clustering (linking IPs belonging to the same hosting network subnet as a single campaign group) is planned for future updates.

---

## Disclaimer

This software is designed exclusively for **authorized security analysts, financial threat intelligence units, and law enforcement agencies** investigating mobile-based financial scams. All analyzed samples must be acquired and managed in absolute compliance with applicable local cybersecurity legislation, including the Malaysian Computer Crimes Act 1997.

---
> Developed with ❤️ for Malaysia's threat intelligence community.
