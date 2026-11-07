
import pandas as pd

from src.ingestion.normalizer import (
    normalize_dataframe,
    normalize_event_type
)


def test_windows_event_types():
    assert normalize_event_type(4625) == (
        "authentication_failure"
    )

    assert normalize_event_type("4624") == (
        "authentication_success"
    )

    assert normalize_event_type(4688) == (
        "process_creation"
    )


def test_windows_normalization():
    df = pd.DataFrame([{
        "timestamp": "2026-10-23 10:00:00",
        "username": "CORP\\admin",
        "source_ip": "10.10.1.22",
        "event_id": 4625,
        "result": "Failure",
        "process_commandline": None,
        "severity": "Informational"
    }])

    result = normalize_dataframe(
        df,
        source_name="test.xlsx",
        sheet_name="Eventos"
    )

    row = result.iloc[0]

    assert row["normalized_event_id"] == "4625"
    assert row["normalized_event_type"] == (
        "authentication_failure"
    )
    assert row["normalized_result"] == "failure"
    assert row["normalized_command"] == ""
    assert row["normalized_severity"] == "Informativo"
