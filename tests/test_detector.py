
import pandas as pd

from src.analysis.validator import validate_for_brute_force
from src.analysis.detector import detect_brute_force


def make_events(actions, times=None):
    if times is None:
        times = pd.date_range(
            "2026-11-03 10:00:00",
            periods=len(actions),
            freq="min"
        )

    return pd.DataFrame({
        "normalized_timestamp": [
            time.isoformat() for time in times
        ],
        "normalized_source_ip": [
            "192.168.1.50"
        ] * len(actions),
        "username": ["admin"] * len(actions),
        "normalized_event_type": actions,
        "source_row": list(
            range(2, len(actions) + 2)
        )
    })


def analyze(df):
    valid_df, warnings = validate_for_brute_force(df)
    return detect_brute_force(valid_df)


def test_detects_five_failures():
    df = make_events([
        "authentication_failure"
    ] * 5)

    findings = analyze(df)

    assert len(findings) == 1
    assert findings[0]["severity"] == "Medio"
    assert findings[0]["failed_attempts"] == 5


def test_detects_success_after_failures():
    df = make_events(
        ["authentication_failure"] * 5
        + ["authentication_success"]
    )

    findings = analyze(df)

    assert len(findings) == 1
    assert findings[0]["success_after_failures"] is True
    assert findings[0]["severity"] == "Alto"


def test_does_not_alert_on_four_failures():
    df = make_events([
        "authentication_failure"
    ] * 4)

    findings = analyze(df)

    assert findings == []


def test_does_not_alert_on_spread_out_failures():
    times = pd.date_range(
        "2026-11-03 10:00:00",
        periods=5,
        freq="10min"
    )

    df = make_events(
        ["authentication_failure"] * 5,
        times=times
    )

    findings = analyze(df)

    assert findings == []


def test_detects_critical_episode():
    df = make_events(
        ["authentication_failure"] * 10
        + ["authentication_success"]
    )

    findings = analyze(df)

    assert len(findings) == 1
    assert findings[0]["severity"] == "Crítico"
    assert findings[0]["failed_attempts"] == 10
