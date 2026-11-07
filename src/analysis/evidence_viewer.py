
import pandas as pd


def get_incident_evidence(df, incident):
    """
    Recupera los registros normalizados asociados
    a un incidente mediante source_row.
    """
    if df.empty or "source_row" not in df.columns:
        return pd.DataFrame()

    evidence_rows = incident.get("evidence_rows", [])

    if not evidence_rows:
        return df.iloc[0:0].copy()

    return df[
        df["source_row"].isin(evidence_rows)
    ].copy()


def get_finding_evidence(df, finding):
    """
    Recupera los registros asociados a un hallazgo.
    """
    return get_incident_evidence(df, finding)
