
import pandas as pd

from src.analysis.incident_metrics import (
    calculate_incident_metrics
)


def test_incident_metrics_without_duplicates():
    df = pd.DataFrame({
        "source_row": [431, 432, 432, 433],
        "normalized_event_type": [
            "proxy_access"
        ] * 4,
        "normalized_timestamp": [
            "2026-10-23T10:43:00",
            "2026-10-23T10:43:18",
            "2026-10-23T10:43:18",
            "2026-10-23T10:43:36",
        ],
        "destination": [
            "198.51.100.88:443"
        ] * 4,
        "normalized_command": [
            "bytes_out=1000",
            "bytes_out=2000",
            "bytes_out=2000",
            "bytes_out=3000",
        ]
    })

    incident = {
        "evidence_rows": [431, 432, 433]
    }

    metrics = calculate_incident_metrics(
        df, incident
    )

    assert metrics["event_count"] == 3
    assert metrics["bytes_out_total"] == 6000
    assert metrics["duration_seconds"] == 36
    assert metrics["events_with_bytes"] == 3
    assert metrics["missing_rows"] == []


def test_missing_evidence():
    df = pd.DataFrame({
        "source_row": [10],
        "normalized_event_type": [
            "proxy_access"
        ],
        "normalized_command": [
            "bytes_out=500"
        ]
    })

    incident = {
        "evidence_rows": [10, 999]
    }

    metrics = calculate_incident_metrics(
        df, incident
    )

    assert metrics["event_count"] == 1
    assert metrics["bytes_out_total"] == 500
    assert metrics["missing_rows"] == [999]


def test_non_proxy_bytes_not_counted():
    df = pd.DataFrame({
        "source_row": [1],
        "normalized_event_type": [
            "windows_process"
        ],
        "normalized_command": [
            "bytes_out=999999"
        ]
    })

    incident = {
        "evidence_rows": [1]
    }

    metrics = calculate_incident_metrics(
        df, incident
    )

    assert metrics["event_count"] == 1
    assert metrics["bytes_out_total"] == 0
