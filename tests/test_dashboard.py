
import pandas as pd

from src.dashboard.charts import (
    events_timeline,
    severity_distribution,
    top_source_ips,
    rule_distribution
)


def test_events_timeline():
    df = pd.DataFrame({
        "normalized_timestamp": [
            "2026-11-03T10:00:00",
            "2026-11-03T10:01:00",
            "2026-11-03T11:00:00"
        ]
    })

    fig = events_timeline(df)

    assert fig is not None
    assert sum(fig.data[0].y) == 3


def test_severity_distribution():
    incidents = [
        {"severity": "Alto"},
        {"severity": "Medio"},
        {"severity": "Alto"}
    ]

    fig = severity_distribution(incidents)

    assert fig is not None
    assert sum(fig.data[0].values) == 3


def test_top_source_ips():
    df = pd.DataFrame({
        "normalized_source_ip": [
            "192.168.1.10",
            "192.168.1.10",
            "192.168.1.20"
        ]
    })

    fig = top_source_ips(df)

    assert fig is not None
    assert sum(fig.data[0].y) == 3


def test_rule_distribution():
    findings = [
        {"rule_id": "SOC-BF-001"},
        {"rule_id": "SOC-BF-001"},
        {"rule_id": "SOC-PS-001"}
    ]

    fig = rule_distribution(findings)

    assert fig is not None
    assert sum(fig.data[0].y) == 3


def test_empty_data():
    assert events_timeline(pd.DataFrame()) is None
    assert severity_distribution([]) is None
    assert top_source_ips(pd.DataFrame()) is None
    assert rule_distribution([]) is None
