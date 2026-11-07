
import pandas as pd

from src.analysis.evidence_viewer import (
    get_incident_evidence,
    get_finding_evidence
)


def test_get_incident_evidence():
    df = pd.DataFrame({
        "source_row": [10, 11, 12, 13],
        "event_description": ["A", "B", "C", "D"]
    })

    incident = {
        "evidence_rows": [11, 13]
    }

    result = get_incident_evidence(df, incident)

    assert result["source_row"].tolist() == [11, 13]


def test_get_finding_evidence():
    df = pd.DataFrame({
        "source_row": [20, 21, 22],
        "event_description": ["A", "B", "C"]
    })

    finding = {
        "evidence_rows": [21]
    }

    result = get_finding_evidence(df, finding)

    assert result["source_row"].tolist() == [21]


def test_missing_evidence_rows():
    df = pd.DataFrame({
        "source_row": [1, 2, 3]
    })

    incident = {
        "evidence_rows": [999]
    }

    result = get_incident_evidence(df, incident)

    assert result.empty


def test_missing_source_row_column():
    df = pd.DataFrame({
        "event_description": ["A", "B"]
    })

    incident = {
        "evidence_rows": [1]
    }

    result = get_incident_evidence(df, incident)

    assert result.empty
