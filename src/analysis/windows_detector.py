
import re

import pandas as pd


SUSPICIOUS_PATTERNS = {
    "encoded_powershell": re.compile(
        r"(?i)(?:-|/)(?:enc|encodedcommand)\b"
    ),
    "download_execution": re.compile(
        r"(?i)\b(?:invoke-webrequest|iwr|"
        r"downloadstring|downloadfile|invoke-expression|iex)\b"
    ),
    "system_reconnaissance": re.compile(
        r"(?i)\b(?:whoami|net\s+user|"
        r"net\s+group|nltest|quser|"
        r"ipconfig\s+/all)\b"
    ),
    "defense_evasion": re.compile(
        r"(?i)\b(?:set-mppreference|add-mppreference|"
        r"vssadmin\s+delete|wevtutil\s+cl)\b"
    )
}


def detect_windows_threats(df):
    """Detecta indicadores sospechosos en eventos Windows."""

    if df.empty:
        return []

    findings = []

    for _, row in df.iterrows():

        event_type = str(
            row.get("normalized_event_type", "")
        )

        command = row.get("normalized_command", "")
        description = row.get("event_description", "")

        command = "" if pd.isna(command) else str(command)
        description = (
            "" if pd.isna(description) else str(description)
        )

        text = f"{command} {description}"

        matches = [
            name
            for name, pattern in SUSPICIOUS_PATTERNS.items()
            if pattern.search(text)
        ]

        persistence = event_type in {
            "scheduled_task_created",
            "service_installed"
        }

        if not matches and not persistence:
            continue

        if "defense_evasion" in matches:
            severity = "Alto"
        elif "encoded_powershell" in matches:
            severity = "Alto"
        elif persistence:
            severity = "Medio"
        else:
            severity = "Medio"

        rule_id = (
            "SOC-WIN-002"
            if persistence and not matches
            else "SOC-WIN-001"
        )

        timestamp = row.get("normalized_timestamp")

        if not timestamp or pd.isna(timestamp):
            continue

        findings.append({
            "rule_id": rule_id,
            "title": (
                "Posible mecanismo de persistencia"
                if rule_id == "SOC-WIN-002"
                else "Ejecución o reconocimiento sospechoso"
            ),
            "source_ip": row.get("normalized_source_ip"),
            "username": row.get("username"),
            "first_seen": str(timestamp),
            "last_seen": str(timestamp),
            "severity": severity,
            "failed_attempts": 0,
            "success_after_failures": False,
            "evidence_rows": [int(row["source_row"])],
            "description": (
                "Indicadores: " + ", ".join(matches)
                if matches
                else f"Evento de persistencia: {event_type}"
            )
        })

    return findings
