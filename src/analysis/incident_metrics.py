
import re

import pandas as pd


BYTES_PATTERN = re.compile(
    r"\bbytes_out\s*=\s*(\d+)\b",
    re.IGNORECASE
)


def extract_bytes_out(row):
    """
    Busca bytes_out en los campos textuales del registro.
    Evita sumar varias veces el mismo valor si aparece
    repetido en distintas columnas.
    """
    for column in (
        "bytes_out",
        "normalized_bytes_out",
    ):
        if column in row.index:
            value = pd.to_numeric(
                row[column], errors="coerce"
            )
            if pd.notna(value) and value >= 0:
                return int(value)

    for column in (
        "event_description",
        "normalized_command",
        "description",
        "message",
        "raw_message",
    ):
        if column not in row.index:
            continue

        value = row[column]

        if pd.isna(value):
            continue

        match = BYTES_PATTERN.search(str(value))

        if match:
            return int(match.group(1))

    return None


def calculate_incident_metrics(df, incident):
    evidence_rows = incident.get("evidence_rows", [])

    if df.empty or "source_row" not in df.columns:
        return {
            "event_count": 0,
            "bytes_out_total": 0,
            "bytes_out_mib": 0.0,
            "duration_seconds": None,
            "destinations": [],
            "verified_rows": [],
            "missing_rows": sorted(set(evidence_rows)),
            "events_with_bytes": 0,
        }

    rows = set(evidence_rows)

    evidence = df[
        df["source_row"].isin(rows)
    ].drop_duplicates(subset=["source_row"]).copy()

    verified_rows = set(
        evidence["source_row"].tolist()
    )

    missing_rows = rows - verified_rows

    total_bytes = 0
    events_with_bytes = 0

    for _, row in evidence.iterrows():
        # Solo sumar bytes de eventos proxy.
        event_type = str(
            row.get("normalized_event_type", "")
        ).lower()

        if event_type != "proxy_access":
            continue

        value = extract_bytes_out(row)

        if value is not None:
            total_bytes += value
            events_with_bytes += 1

    duration_seconds = None

    if "normalized_timestamp" in evidence.columns:
        timestamps = pd.to_datetime(
            evidence["normalized_timestamp"],
            errors="coerce",
            utc=True
        ).dropna()

        if not timestamps.empty:
            duration_seconds = int(
                (
                    timestamps.max()
                    - timestamps.min()
                ).total_seconds()
            )

    destination_column = next(
        (
            col for col in (
                "destination",
                "normalized_destination",
            )
            if col in evidence.columns
        ),
        None
    )

    destinations = []

    if destination_column:
        destinations = sorted(
            str(value)
            for value in evidence[
                destination_column
            ].dropna().unique()
            if str(value).strip()
        )

    return {
        "event_count": len(evidence),
        "bytes_out_total": total_bytes,
        "bytes_out_mib": round(
            total_bytes / (1024 ** 2), 2
        ),
        "duration_seconds": duration_seconds,
        "destinations": destinations,
        "verified_rows": sorted(verified_rows),
        "missing_rows": sorted(missing_rows),
        "events_with_bytes": events_with_bytes,
    }
