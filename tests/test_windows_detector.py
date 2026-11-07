import pandas as pd

from src.analysis.windows_detector import detect_windows_threats


def test_encoded_powershell():
    df = pd.DataFrame([{
        "normalized_event_type": "process_creation",
        "normalized_command": "powershell.exe -EncodedCommand AAAA",
        "event_description": "Process created",
        "normalized_timestamp": "2026-10-23T10:00:00",
        "normalized_source_ip": "10.0.0.5",
        "username": "admin",
        "source_row": 2
    }])

    findings = detect_windows_threats(df)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "SOC-WIN-001"
    assert findings[0]["severity"] == "Alto"


def test_normal_process():
    df = pd.DataFrame([{
        "normalized_event_type": "process_creation",
        "normalized_command": "notepad.exe",
        "event_description": "Process created",
        "normalized_timestamp": "2026-10-23T10:00:00",
        "source_row": 3
    }])

    assert detect_windows_threats(df) == []
