
import pandas as pd
import plotly.express as px


SEVERITY_ORDER = [
    "Informativo",
    "Bajo",
    "Medio",
    "Alto",
    "Crítico"
]


def events_timeline(df):
    """Gráfico de eventos agrupados por hora."""

    if df.empty or "normalized_timestamp" not in df.columns:
        return None

    data = df.copy()

    data["event_time"] = pd.to_datetime(
        data["normalized_timestamp"],
        errors="coerce"
    )

    data = data.dropna(subset=["event_time"])

    if data.empty:
        return None

    data["hour"] = data["event_time"].dt.floor("h")

    timeline = (
        data.groupby("hour")
        .size()
        .reset_index(name="events")
    )

    fig = px.line(
        timeline,
        x="hour",
        y="events",
        markers=True,
        title="Evolución temporal de eventos",
        labels={
            "hour": "Fecha y hora",
            "events": "Cantidad de eventos"
        }
    )

    fig.update_layout(hovermode="x unified")

    return fig


def severity_distribution(incidents):
    """Distribución de incidentes por severidad."""

    if not incidents:
        return None

    data = pd.DataFrame(incidents)

    counts = (
        data["severity"]
        .value_counts()
        .reset_index()
    )

    counts.columns = ["severity", "count"]

    fig = px.pie(
        counts,
        names="severity",
        values="count",
        hole=0.45,
        title="Severidad de incidentes"
    )

    return fig


def top_source_ips(df, limit=10):
    """Direcciones IP con mayor cantidad de eventos."""

    if df.empty or "normalized_source_ip" not in df.columns:
        return None

    counts = (
        df["normalized_source_ip"]
        .dropna()
        .value_counts()
        .head(limit)
        .reset_index()
    )

    counts.columns = ["ip", "events"]

    if counts.empty:
        return None

    fig = px.bar(
        counts,
        x="ip",
        y="events",
        title="Principales IP de origen",
        labels={
            "ip": "Dirección IP",
            "events": "Cantidad de eventos"
        }
    )

    return fig


def rule_distribution(findings):
    """Cantidad de hallazgos por regla."""

    if not findings:
        return None

    data = pd.DataFrame(findings)

    counts = (
        data["rule_id"]
        .value_counts()
        .reset_index()
    )

    counts.columns = ["rule", "count"]

    fig = px.bar(
        counts,
        x="rule",
        y="count",
        title="Reglas de detección activadas",
        labels={
            "rule": "Regla",
            "count": "Hallazgos"
        }
    )

    return fig
