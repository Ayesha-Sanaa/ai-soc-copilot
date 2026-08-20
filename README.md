# AI SOC Copilot — Discovery + Lateral Movement Detection & Triage

An end-to-end SOC automation lab: a real attack chain is simulated, detected in Splunk through a
multi-signal correlation search, and triaged automatically by an LLM — with no manual analyst
step in between.

---

## Project Overview

This simulates a Discovery + Lateral Movement attack (recon commands followed by PsExec-style
remote execution), detects it in Splunk using a correlation search that requires multiple signals
to agree, and routes the alert to an LLM for automated triage — severity, MITRE ATT&CK mapping,
confidence, false-positive likelihood, and recommended response steps. The triage result is
written back into Splunk and shown on a dashboard.

The goal wasn't to build the biggest possible lab — it was to build one clean, defensible,
end-to-end pipeline that actually fires, end to end, without me pressing a manual trigger.

---

## Problem Statement

SOC analysts spend a large share of their time doing first-pass triage on alerts: reading raw
logs, mapping them to ATT&CK techniques, judging severity, and deciding what to do next. Most of
that first pass follows a repeatable pattern. This project automates that first pass for one
well-defined attack chain, so a human analyst starts their investigation with context already
prepared instead of a blank alert.

---

## Objectives

- Simulate a realistic, reproducible lateral movement attack chain
- Detect it using correlation logic (multiple weak signals), not a single IOC match
- Automatically triage the alert with an LLM and return structured, usable output
- Close the loop by feeding that output back into the SIEM for visibility
- Keep the whole thing lightweight enough to run on a single machine with limited RAM

---

## Key Features

- Multi-signal Splunk correlation search (not a single-event match)
- Scheduled Splunk Alert that fires a webhook with zero manual intervention
- FastAPI receiver that calls an LLM and returns strict structured JSON
- Mock mode — the whole pipeline can be tested and demoed without any API key or cost
- Triage results written back into Splunk via HTTP Event Collector (HEC)
- A Splunk dashboard showing severity, confidence, MITRE mapping, and analyst-ready summaries

---

## Architecture

```
Kali Linux (Impacket PsExec)
        │  discovery commands + remote service execution
        ▼
Windows Target (Sysmon + Security/System Event Logs)
        │
        ▼
Splunk Universal Forwarder
        │
        ▼
Splunk Enterprise
        │  multi-signal correlation search (5-min window)
        ▼
Scheduled Alert  ──────────────►  Webhook (HTTP POST)
                                        │
                                        ▼
                              FastAPI Receiver (main.py)
                                        │
                                        ▼
                              LLM (Gemini API / Mock Mode)
                                        │
                    ┌───────────────────┴───────────────────┐
                    ▼                                        ▼
        JSON response (severity, MITRE,          Splunk HEC (soc_copilot_triage
        confidence, actions)                      sourcetype)
                                                              │
                                                              ▼
                                                   Splunk Dashboard
```

---

## Technology Stack

| Layer | Tool |
|---|---|
| Attack simulation | Kali Linux, Impacket (`psexec.py`) |
| Telemetry | Sysmon, Windows Security/System Event Logs |
| Log shipping | Splunk Universal Forwarder |
| SIEM / detection | Splunk Enterprise (correlation search, scheduled alert) |
| Automation backend | Python, FastAPI |
| AI triage | Gemini API (`gemini-3.6-flash`) — with an offline mock mode |
| Output ingestion | Splunk HTTP Event Collector (HEC) |
| Visualization | Splunk Dashboard Studio |

FastAPI was chosen over Flask for native async support and typed request/response models.
Splunk's own HEC + Dashboard were used for output instead of standing up a separate dashboard
tool, specifically to avoid extra RAM overhead on the lab machine.

---

## Data Flow

1. Attacker runs discovery commands and a remote service execution against the Windows target.
2. Sysmon logs process creation (`whoami`, `net.exe`, `hostname`); Windows Security/System logs
   capture the logon, privilege assignment, and service install.
3. The Universal Forwarder ships `Security`, `System`, and `Sysmon/Operational` logs to Splunk.
4. A scheduled correlation search runs every 5 minutes, bucketing events into 5-minute windows and
   checking whether at least 3 of 4 expected signals appear on the same host in the same window.
5. If the condition is met, Splunk fires a webhook to the FastAPI receiver with the match details.
6. FastAPI builds a prompt from the alert and calls the LLM, which returns structured JSON.
7. FastAPI sends that JSON back into Splunk via HEC, into a dedicated sourcetype.
8. The Splunk dashboard queries that sourcetype and displays it as a table.

---

## Attack Scenario

**Chosen chain: Discovery + Lateral Movement** — deliberately picked over a Credential Access or
Persistence chain so that all three labs in the portfolio cover different MITRE techniques with
zero overlap.

```bash
impacket-psexec -service-name PSEXESVC -remote-binary-name PSEXESVC \
    pentest:'P@ssw0rd123!'@192.168.56.1
```

Once a shell is obtained (as `NT AUTHORITY\SYSTEM`), a small, realistic set of recon commands is
run — not an exhaustive list, just what a real operator would actually type:

```
whoami
hostname
ipconfig /all
net user
net localgroup administrators
```

**PsExec shell obtained:**
<img width="1436" height="840" alt="kali1" src="https://github.com/user-attachments/assets/04e06869-fa41-4df7-a3d3-2a590aa8497a" />

**Discovery commands executed on target:**
<img width="1372" height="870" alt="kalipxsec" src="https://github.com/user-attachments/assets/4844c140-b177-454f-a53f-d5901a40377d" />

<img width="1365" height="896" alt="kali2" src="https://github.com/user-attachments/assets/0fb3ab03-2b55-448a-8581-d5f35b885fcc" />

<img width="1178" height="935" alt="kali3" src="https://github.com/user-attachments/assets/b91d7f44-4bc0-45b0-9303-0451e998f4ad" />

Clean session exit — Impacket automatically removes the temporary service and binary.

A known Windows behavior had to be handled here: local (non-built-in-Administrator) accounts get a
filtered token over the network by default, which blocks ADMIN$/C$ write access. This was resolved
by setting `LocalAccountTokenFilterPolicy=1` in the registry on the target — itself a MITRE
T1112-relevant artifact worth noting.

---

## Log Collection

Three log sources feed the correlation search:

| Source | Event IDs used | What it captures |
|---|---|---|
| Sysmon | 1 (Process Create) | `whoami`, `net.exe`, `hostname` execution |
| Windows Security | 4624, 4672 | Network logon (Type 3), special privilege assignment |
| Windows System | 7045 | New service installed (`PSEXESVC`) |

Sysmon was already configured (SwiftOnSecurity-based) with `whoami`, `net.exe`, `psexec.exe`, and
`psexesvc.exe` already present in its `NetworkConnect` include list, so no config changes were
needed there. Windows Security auditing had to be explicitly enabled, since it isn't on by
default:

```powershell
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
auditpol /set /subcategory:"Special Logon" /success:enable
```

The Universal Forwarder's `inputs.conf` had to be extended to forward `Security` and `System`
channels — out of the box it was only shipping the Sysmon channel:

```ini
[WinEventLog://Microsoft-Windows-Sysmon/Operational]
disabled = false
index = main

[WinEventLog://Security]
disabled = false
index = main

[WinEventLog://System]
disabled = false
index = main
```

**Sysmon telemetry confirmed in Splunk:**

<img width="1568" height="739" alt="splunk1" src="https://github.com/user-attachments/assets/421f0e65-bbb0-405a-96cb-e1a6df914e4d" />

**Security events (4624/4672) confirmed:**

<img width="1568" height="778" alt="splunk2" src="https://github.com/user-attachments/assets/e9948f3b-c639-4158-aea2-caac36d7496b" />

**System event 7045 (service install) confirmed:**

<img width="1568" height="774" alt="splunk3" src="https://github.com/user-attachments/assets/c2d2267a-dc91-48fd-ae79-3c8402878437" />

---

## Detection Logic

The search deliberately avoids matching on a single indicator like the `PSEXESVC.exe` filename.
Real detection engineering means correlating weak signals into a strong one:

```spl
index=main (sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
    (Image="*whoami*" OR Image="*net.exe*" OR Image="*hostname*"))
    OR (sourcetype="WinEventLog:Security" (EventCode=4624 OR EventCode=4672))
    OR (sourcetype="WinEventLog:System" EventCode=7045 Service_Name="PSEXESVC")
| eval signal=case(
    sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational", "Discovery Command",
    EventCode=4624, "Network Logon",
    EventCode=4672, "Special Privileges",
    EventCode=7045, "Service Installed"
  )
| bin _time span=5m
| stats dc(signal) as signal_count values(signal) as signals
      earliest(_time) as first_seen latest(_time) as last_seen by ComputerName, _time
| where signal_count >= 3
```

This search does something useful beyond simple detection: it distinguishes a **failed** PsExec
attempt (3 signals — logon, privileges, service install, but no discovery telemetry because the
shell never returned) from a **successful** one (all 4 signals, including the discovery commands
that only fire once an attacker actually has a working shell).

**Correlation search results — note the partial (3-signal) vs. complete (4-signal) rows:**

<img width="1568" height="757" alt="splunk4" src="https://github.com/user-attachments/assets/50b04349-0005-4433-ae08-ea716e6071f3" />

---

## Alert Workflow

The correlation search is saved as a Splunk **Scheduled Alert**:

- **Schedule:** cron `*/5 * * * *` (every 5 minutes)
- **Trigger condition:** Number of Results > 0
- **Trigger:** For each result (so multiple hosts alert independently)
- **Action:** Webhook → `http://127.0.0.1:8001/splunk-alert`

**Alert configuration:**

<img width="1012" height="810" alt="alert1" src="https://github.com/user-attachments/assets/c832dd6f-690a-4e17-82bc-a16429ff715a" />

**Webhook action attached:**

<img width="973" height="807" alt="alert2" src="https://github.com/user-attachments/assets/0db11103-dd4a-4392-8929-a3747f48eb1b" />

**Webhook URL configured:**

<img width="896" height="788" alt="alert3" src="https://github.com/user-attachments/assets/e527fbee-2649-45d3-a8d8-374829746431" />

**Alert saved and enabled:**

<img width="1417" height="601" alt="alert4" src="https://github.com/user-attachments/assets/4cfa8e14-f7ef-4c0f-a5ee-d7b318cad6f0" />

A second attack run was performed specifically to confirm the alert fires **on its own**, on
schedule, without manually re-running the test script:

<img width="1372" height="870" alt="kalinow" src="https://github.com/user-attachments/assets/0fd5b4dc-777d-43e0-8de2-2f2a7fb2d66e" />

Few minutes later, Splunk's scheduler fired the webhook by itself:

<img width="1333" height="896" alt="uvi1" src="https://github.com/user-attachments/assets/9e035f22-d0ed-4a9b-ba67-14d408a2c7f0" />



---

## AI Triage Workflow

The FastAPI receiver (`main.py`) exposes a single endpoint, `POST /splunk-alert`. On each call it:

1. Parses the Splunk alert payload (host, signal count, matched signals, timestamps)
2. Builds a prompt and sends it to the LLM with a strict system prompt requiring JSON-only output
3. Parses and validates the response
4. Returns it to the caller, forwards it to Splunk HEC, and optionally to Slack

**System prompt (condensed):** the model is told it's a Tier-1 SOC triage assistant and must
return only a JSON object with `summary`, `mitre`, `severity`, `confidence`,
`false_positive_probability`, `why`, and `recommended_actions` — no markdown, no preamble.

**Live triage result in the terminal, generated automatically by the scheduled alert:**

<img width="1333" height="896" alt="uvi2" src="https://github.com/user-attachments/assets/68dd9545-6448-4f1a-bf31-08b6f43af0a6" />

Sample output for the full 4-signal (successful) attack chain:

```json
{
  "summary": "Host DESKTOP-HGL0NFV exhibited a correlated attack chain featuring discovery command execution, a network logon, service creation, and special privilege assignment within the same timeframe.",
  "mitre": ["T1087", "T1082", "T1021.002", "T1543.003", "T1078"],
  "severity": "High",
  "confidence": 0.85,
  "false_positive_probability": "Low",
  "why": "The simultaneous observation of 4 distinct signals — network logon, service installation (indicative of PsExec), privilege assignment, and recon commands — strongly indicates active lateral movement rather than benign activity.",
  "recommended_actions": [
    "Isolate host DESKTOP-HGL0NFV from the network to prevent further lateral movement.",
    "Investigate Security Event ID 4624 to identify the source IP address and account used.",
    "Inspect System Event ID 7045 to determine the service name and image path of the installed service.",
    "Review process creation logs around the alert timestamp to analyze executed discovery commands."
  ]
}
```

**Mock mode:** because LLM APIs are usage-based and not always free to test against, the receiver
supports `MOCK_MODE=true`, which returns a realistic, severity-scaled response based on the actual
signal count — with zero API calls. This let the entire pipeline be validated end-to-end before an
API key was even involved, and makes the project runnable by anyone cloning the repo without
needing to pay for anything.

---

## AI Output Ingestion (HEC)

Rather than the triage result being a dead end printed to a terminal, it's written back into
Splunk using the HTTP Event Collector, under a dedicated sourcetype (`soc_copilot_triage`):

```python
requests.post(
    SPLUNK_HEC_URL,
    headers={"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"},
    json={"sourcetype": "soc_copilot_triage", "index": SPLUNK_HEC_INDEX, "event": {...}},
)
```

This closes the loop: Splunk detects → LLM triages → Splunk stores and displays the triage. An
analyst never has to leave Splunk to see the AI's assessment.

**Triage data landing back in Splunk via HEC:**

<img width="1568" height="732" alt="dash1" src="https://github.com/user-attachments/assets/726f34f9-5949-429c-8a87-0969dabb875d" />

**Structured table view of ingested triage results:**

<img width="1568" height="659" alt="dash2" src="https://github.com/user-attachments/assets/97ee33dd-e076-40ea-9693-da668285886b" />

---

## Splunk Dashboard

A Splunk Dashboard Studio panel queries the `soc_copilot_triage` sourcetype and presents each
triaged alert as a row: timestamp, host, severity, confidence, MITRE techniques, and false-positive
likelihood.

<img width="784" height="770" alt="dashtab" src="https://github.com/user-attachments/assets/e3877f5f-e67f-4727-b631-89d612ea7fda" />


One real snag worth documenting: Splunk indexes JSON array fields (like `mitre`) as multivalue
fields named `field{}`, not `field` — `mvjoin(mitre, ", ")` silently returned nothing until the
field was referenced correctly as `mvjoin('mitre{}', ", ")`. Worth knowing before hitting the same
wall.

**Dashboard, first version (MITRE column not yet rendering):**



<img width="1568" height="703" alt="mitrenahi" src="https://github.com/user-attachments/assets/7d30029b-5313-4d0b-9858-5229b48b050f" />

**Final dashboard, with MITRE mapping correctly displayed:**

<img width="1568" height="721" alt="mitre" src="https://github.com/user-attachments/assets/f97d8225-d827-41ec-9ba9-c9664c14d67b" />

---

## Installation

**Prerequisites:** Splunk Enterprise with Universal Forwarder configured, Sysmon on the Windows
target, Python 3.10+, and Impacket on the attacking machine (Kali ships with it).

The four source files (`main.py`, `requirements.txt`, `.env.example`, `test_alert.py`) are in
[`SOURCE_FILES.md`](./SOURCE_FILES.md). Create each one locally with that content, then:

```bash
pip install -r requirements.txt
cp .env.example .env
```

## Configuration

Edit `.env`:

```dotenv
GEMINI_API_KEY=your_gemini_api_key_here      # console: aistudio.google.com
GEMINI_MODEL=gemini-3.6-flash
MOCK_MODE=false                              # set true to run without any API key


SPLUNK_HEC_URL=https://127.0.0.1:8088/services/collector
SPLUNK_HEC_TOKEN=your_hec_token_here
SPLUNK_HEC_INDEX=main
```


## Usage

```bash
uvicorn main:app --reload --port 8001
```

Configure a Splunk alert on the correlation search above with a Webhook action pointing to
`http://127.0.0.1:8001/splunk-alert`. To test without touching Splunk at all:

```bash
python test_alert.py
```

## Sample Investigation

Given a triggered alert reporting 4 signals on `DESKTOP-HGL0NFV` within a 5-minute window, the
pipeline returns (see full JSON above): **Severity: High, Confidence: 0.85, False Positive
Probability: Low**, mapped to T1087 (Account Discovery), T1082 (System Information Discovery),
T1021.002 (SMB/Windows Admin Shares), T1543.003 (Windows Service creation), and T1078 (Valid
Accounts) — with concrete next steps for the analyst, generated without any human triage step.

## Results

- End-to-end pipeline confirmed firing autonomously on a real scheduled Splunk alert (no manual
  trigger), twice, across two separate attack runs
- Correlation logic correctly distinguished a partial/failed PsExec attempt from a complete one
- Full round trip (attack → detection → AI triage → back into Splunk → dashboard) verified with
  screenshots at every stage

## Limitations

- Lab-scale: single host, single attack chain, no domain environment
- Correlation search uses a fixed 5-minute window, not adaptive baselining
- Confidence and severity scores come from the LLM's judgment, not a calibrated statistical model
- No authentication on the FastAPI webhook endpoint — acceptable for a local lab, not for
  production
- Splunk's `main` index is shared between raw logs and AI output; a dedicated index would be
  cleaner at scale

## Future Improvements

- Add authentication/signing to the webhook endpoint
- Move the correlation search from a fixed window to adaptive/statistical baselining
- Add a second correlation rule for a different technique to test cross-chain false positives
- Replace the mock-mode fallback with a small local model for fully offline operation

## Skills Demonstrated

Detection engineering (multi-signal correlation, not single-IOC matching) · Splunk administration
(forwarder config, audit policy, HEC, scheduled alerts, dashboards) · Python/FastAPI backend
development · LLM prompt engineering for structured, schema-constrained output · MITRE ATT&CK
mapping · Windows internals (token filtering, event auditing) · attack simulation with Impacket ·
end-to-end pipeline debugging across five different tools

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Sysmon documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [Impacket](https://github.com/fortra/impacket)
- [Splunk HTTP Event Collector](https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector)
- [FastAPI](https://fastapi.tiangolo.com/)
