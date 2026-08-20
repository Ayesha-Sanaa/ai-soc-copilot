import requests
import json

SAMPLE_ALERT = {
    "result": {
        "ComputerName": "DESKTOP-HGL0NFV",
        "_time": "2026-08-19 16:55:00",
        "signal_count": "4",
        "signals": "Discovery Command\nNetwork Logon\nService Installed\nSpecial Privileges",
        "first_seen": "1787140500",
        "last_seen": "1787140500",
    }
}

response = requests.post(
    "http://127.0.0.1:8001/splunk-alert",
    json=SAMPLE_ALERT,
    timeout=30,
)

print("Status Code:", response.status_code)
print(json.dumps(response.json(), indent=2))
