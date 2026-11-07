
import pandas as pd

from src.analysis.validator import (
    validate_for_brute_force
)

from src.analysis.advanced_detector import (
    detect_advanced_threats
)


def make_events(records):
    df = pd.DataFrame(
        records,
        columns=["time", "ip", "user", "event"]
    )

    df["normalized_timestamp"] = df["time"]
    df["normalized_source_ip"] = df["ip"]
    df["username"] = df["user"]
    df["normalized_event_type"] = df["event"]
    df["source_row"] = range(2, len(df) + 2)

    valid, warnings = validate_for_brute_force(df)

    assert not warnings
    return valid


def test_password_spraying():
    records = [
        (
            f"2026-11-03 10:0{i}:00",
            "192.168.1.50",
            f"user{i}",
            "authentication_failure"
        )
        for i in range(5)
    ]

    findings = detect_advanced_threats(
        make_events(records)
    )

    spraying = [
        f for f in findings
        if f["rule_id"] == "SOC-PS-001"
    ]

    assert len(spraying) == 1
    assert len(spraying[0]["affected_users"]) == 5


def test_distributed_brute_force():
    records = [
        (
            f"2026-11-03 10:0{i}:00",
            f"192.168.1.{10 + i % 3}",
            "admin",
            "authentication_failure"
        )
        for i in range(6)
    ]

    findings = detect_advanced_threats(
        make_events(records)
    )

    distributed = [
        f for f in findings
        if f["rule_id"] == "SOC-DBF-001"
    ]

    assert len(distributed) == 1
    assert len(distributed[0]["source_ips"]) == 3


def test_success_correlation():
    records = [
        (
            f"2026-11-03 10:0{i}:00",
            f"192.168.1.{10 + i % 3}",
            "admin",
            "authentication_failure"
        )
        for i in range(6)
    ]

    records.append((
        "2026-11-03 10:07:00",
        "192.168.1.12",
        "admin",
        "authentication_success"
    ))

    findings = detect_advanced_threats(
        make_events(records)
    )

    distributed = next(
        f for f in findings
        if f["rule_id"] == "SOC-DBF-001"
    )

    assert distributed["success_after_failures"]
    assert distributed["severity"] == "Alto"
    assert distributed["success_ip"] == "192.168.1.12"


def test_no_false_spraying():
    records = [
        (
            f"2026-11-03 10:0{i}:00",
            "192.168.1.50",
            "admin",
            "authentication_failure"
        )
        for i in range(5)
    ]

    findings = detect_advanced_threats(
        make_events(records)
    )

    assert not any(
        f["rule_id"] == "SOC-PS-001"
        for f in findings
    )


def test_unrelated_success_not_correlated():
    records = [
        (
            f"2026-11-03 10:0{i}:00",
            f"192.168.1.{10 + i % 3}",
            "admin",
            "authentication_failure"
        )
        for i in range(6)
    ]

    records.append((
        "2026-11-03 10:07:00",
        "192.168.1.99",
        "admin",
        "authentication_success"
    ))

    findings = detect_advanced_threats(
        make_events(records)
    )

    distributed = next(
        f for f in findings
        if f["rule_id"] == "SOC-DBF-001"
    )

    assert not distributed["success_after_failures"]
