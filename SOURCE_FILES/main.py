import os
import json
import logging
from datetime import datetime

from fastapi import FastAPI, Request
from pydantic import BaseModel
from dotenv import load_dotenv
import google.generativeai as genai
import requests

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("soc-copilot")

app = FastAPI(title="AI SOC Copilot - Alert Triage")

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

MOCK_MODE = os.getenv("MOCK_MODE", "false").lower() == "true"

SPLUNK_HEC_URL = os.getenv("SPLUNK_HEC_URL")
SPLUNK_HEC_TOKEN = os.getenv("SPLUNK_HEC_TOKEN")
SPLUNK_HEC_INDEX = os.getenv("SPLUNK_HEC_INDEX", "main")

if GEMINI_API_KEY and not MOCK_MODE:
    genai.configure(api_key=GEMINI_API_KEY)
    gemini_model = genai.GenerativeModel(GEMINI_MODEL)
else:
    gemini_model = None


class TriageResult(BaseModel):
    summary: str
    mitre: list[str]
    severity: str
    confidence: float
    false_positive_probability: str
    why: str
    recommended_actions: list[str]


def mock_triage_response(alert_payload: dict) -> dict:
    result = alert_payload.get("result", alert_payload)
    signal_count = int(result.get("signal_count", 0) or 0)
    signals = str(result.get("signals", ""))
    host = result.get("ComputerName", "unknown-host")

    if signal_count >= 4:
        severity, confidence, fp_prob = "High", 0.91, "Low"
        why = (
            f"All four correlated signals fired on {host} within a "
            f"5-minute window, indicating a high-confidence lateral movement chain."
        )
    elif signal_count == 3:
        severity, confidence, fp_prob = "Medium", 0.65, "Medium"
        why = (
            f"Three of four expected signals fired on {host}, indicating "
            f"a possible partial or failed lateral movement attempt."
        )
    else:
        severity, confidence, fp_prob = "Low", 0.3, "High"
        why = (
            f"Only {signal_count} signal(s) were observed on {host}, "
            f"which is insufficient for a confident determination."
        )

    return {
        "summary": (
            f"[MOCK] Correlated activity on {host}: {signal_count} signal(s) matched "
            f"({signals.replace(chr(10), ', ')})."
        ),
        "mitre": ["T1087", "T1021.002", "T1569.002"],
        "severity": severity,
        "confidence": confidence,
        "false_positive_probability": fp_prob,
        "why": why,
        "recommended_actions": [
            f"Isolate host {host} from the network pending investigation",
            "Review PSEXESVC.exe hash and parent process for legitimacy",
            "Check the source IP of the network logon against known admin workstations",
            "Reset credentials for the account used in the logon event",
        ],
    }


def build_user_prompt(alert_payload: dict) -> str:
    result = alert_payload.get("result", alert_payload)

    computer = result.get("ComputerName", "unknown-host")
    signals = result.get("signals", "unknown")
    signal_count = result.get("signal_count", "unknown")
    first_seen = result.get("first_seen", "unknown")
    last_seen = result.get("last_seen", "unknown")

    return f"""Alert: Discovery + Lateral Movement Detection

Host: {computer}
Signal count: {signal_count}
Signals observed: {signals}
First seen: {first_seen}
Last seen: {last_seen}

Raw Splunk result:
{json.dumps(result, indent=2)}
"""


@app.get("/")
def health_check():
    return {
        "status": "ok",
        "service": "AI SOC Copilot",
        "time": datetime.utcnow().isoformat(),
    }


@app.post("/splunk-alert")
async def receive_splunk_alert(request: Request):
    raw_body = await request.body()

    try:
        alert_payload = json.loads(raw_body)
    except json.JSONDecodeError:
        alert_payload = {"raw": raw_body.decode(errors="ignore")}

    logger.info("Alert received: %s", json.dumps(alert_payload)[:500])

    if MOCK_MODE:
        triage_json = mock_triage_response(alert_payload)
        logger.info("MOCK triage result: %s", json.dumps(triage_json, indent=2))

        send_to_splunk_hec(triage_json, alert_payload)

        if SLACK_WEBHOOK_URL:
            send_to_slack(triage_json, alert_payload)

        return {
            "status": "triaged (mock)",
            "triage": triage_json,
        }

    if not gemini_model:
        return {
            "error": "GEMINI_API_KEY not configured and MOCK_MODE is off."
        }

    user_prompt = build_user_prompt(alert_payload)
    full_prompt = f"{SYSTEM_PROMPT}\n\n{user_prompt}"

    try:
        response = gemini_model.generate_content(full_prompt)
        raw_text = response.text.strip()

        cleaned = raw_text.replace("```json", "").replace("```", "").strip()
        triage_json = json.loads(cleaned)

    except json.JSONDecodeError:
        logger.error("LLM response JSON parse failed: %s", raw_text)
        return {
            "error": "LLM did not return valid JSON",
            "raw_response": raw_text,
        }

    except Exception as e:
        logger.error("LLM call failed: %s", str(e))
        return {"error": f"LLM call failed: {str(e)}"}

    logger.info("Triage result: %s", json.dumps(triage_json, indent=2))

    send_to_splunk_hec(triage_json, alert_payload)

    if SLACK_WEBHOOK_URL:
        send_to_slack(triage_json, alert_payload)

    return {
        "status": "triaged",
        "triage": triage_json,
    }


def send_to_splunk_hec(triage: dict, original_alert: dict):
    if not (SPLUNK_HEC_URL and SPLUNK_HEC_TOKEN):
        return

    result = original_alert.get("result", original_alert)

    event = {
        "sourcetype": "soc_copilot_triage",
        "index": SPLUNK_HEC_INDEX,
        "event": {
            "host": result.get("ComputerName", "unknown-host"),
            "summary": triage.get("summary", ""),
            "mitre": triage.get("mitre", []),
            "severity": triage.get("severity", ""),
            "confidence": triage.get("confidence", ""),
            "false_positive_probability": triage.get(
                "false_positive_probability", ""
            ),
            "why": triage.get("why", ""),
            "recommended_actions": triage.get(
                "recommended_actions", []
            ),
            "original_signal_count": result.get("signal_count", ""),
        },
    }

    try:
        requests.post(
            SPLUNK_HEC_URL,
            headers={"Authorization": f"Splunk {SPLUNK_HEC_TOKEN}"},
            json=event,
            verify=False,
            timeout=5,
        )
        logger.info("Triage result sent to Splunk HEC.")

    except Exception as e:
        logger.error("Splunk HEC request failed: %s", str(e))


def send_to_slack(triage: dict, original_alert: dict):
    result = original_alert.get("result", original_alert)
    host = result.get("ComputerName", "unknown-host")

    severity_emoji = {
        "Low": "🟢",
        "Medium": "🟡",
        "High": "🟠",
        "Critical": "🔴",
    }.get(triage.get("severity", ""), "⚪")

    slack_message = {
        "text": (
            f"{severity_emoji} *{triage.get('severity', 'Unknown')} "
            f"Severity Alert* — {host}\n\n"
            f"*Summary:* {triage.get('summary', '')}\n"
            f"*MITRE ATT&CK:* {', '.join(triage.get('mitre', []))}\n"
            f"*Confidence:* {triage.get('confidence', 'N/A')}\n"
            f"*False Positive Probability:* "
            f"{triage.get('false_positive_probability', 'N/A')}\n"
            f"*Why:* {triage.get('why', '')}\n"
            f"*Recommended Actions:*\n"
            + "\n".join(
                f"  • {action}"
                for action in triage.get("recommended_actions", [])
            )
        )
    }

    try:
        requests.post(
            SLACK_WEBHOOK_URL,
            json=slack_message,
            timeout=5,
        )
    except Exception as e:
        logger.error("Slack forward failed: %s", str(e))
