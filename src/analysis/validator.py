
import pandas as pd


REQUIRED_COLUMNS = [
    "normalized_timestamp",
    "normalized_source_ip",
    "username",
    "normalized_event_type"
]


def validate_for_brute_force(df):
    """Valida los registros antes de detectar ataques."""

    missing = [
        column for column in REQUIRED_COLUMNS
        if column not in df.columns
    ]

    if missing:
        return pd.DataFrame(), [
            "Faltan columnas: " + ", ".join(missing)
        ]

    result = df.copy()
    warnings = []

    # Rechazamos fechas con zona horaria explícita
    # hasta implementar conversión controlada a UTC.
    def parse_time(value):
        if pd.isna(value):
            return pd.NaT

        try:
            date = pd.Timestamp(value)

            if date.tzinfo is not None:
                return pd.NaT

            return date

        except (ValueError, TypeError, OverflowError):
            return pd.NaT

    result["event_time"] = pd.to_datetime(
        result["normalized_timestamp"].apply(parse_time),
        errors="coerce"
    )

    # Limpiar identificadores
    for column in ["normalized_source_ip", "username"]:
        result[column] = (
            result[column]
            .astype("string")
            .str.strip()
        )

    # Identificar registros válidos
    valid_mask = (
        result["event_time"].notna()
        & result["normalized_source_ip"].notna()
        & result["username"].notna()
        & result["normalized_event_type"].notna()
        & (result["normalized_source_ip"] != "")
        & (result["username"] != "")
    )

    invalid_count = int((~valid_mask).sum())

    if invalid_count:
        warnings.append(
            f"{invalid_count} registros excluidos por "
            "datos faltantes, inválidos o fechas "
            "con zona horaria no admitida."
        )

    result = result.loc[valid_mask].copy()

    result = result.sort_values(
        "event_time"
    ).reset_index(drop=True)

    return result, warnings
