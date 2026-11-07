
import re

import pandas as pd

from urllib.parse import unquote_plus
from urllib.parse import urlsplit, parse_qsl, unquote_plus

WEB_TYPES = {"http_access"}

SENSITIVE_PATHS = re.compile(
    r"(?i)/(?:admin|login|api/v\d+/export)(?:[/?\s]|$)"
)





COMMAND_PARAMETER = re.compile(
    r"(?i)[?&](?:cmd|exec|command|shell)="
)

DANGEROUS_COMMAND = re.compile(
    r"(?i)(?:"
    r"\bwhoami\b|"
    r"\bid\b|"
    r"\buname\b|"
    r"\bcat\s+/etc/passwd\b|"
    r"\bcurl\b|"
    r"\bwget\b|"
    r"\bpowershell\b|"
    r"\bcmd\.exe\b|"
    r"\bbash\b|"
    r"\bsh\b"
    r")"
)

PATH_TRAVERSAL = re.compile(
    r"(?i)(?:\.\.[/\\]){2,}"
)



def is_suspicious_web_request(text):
    """Detecta comandos sospechosos y path traversal."""

    request = str(text)

    match = re.search(
        r"\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)"
        r"\s+(\S+)",
        request,
        re.IGNORECASE
    )

    url = match.group(1) if match else request.strip()

    # Analizar la ruta
    decoded_path = urlsplit(url).path

    for _ in range(2):
        new_path = unquote_plus(decoded_path)

        if new_path == decoded_path:
            break

        decoded_path = new_path

    if PATH_TRAVERSAL.search(decoded_path):
        return True

    # Analizar únicamente parámetros relevantes
    query = urlsplit(url).query

    for key, value in parse_qsl(
        query,
        keep_blank_values=True
    ):
        if key.lower() not in {
            "cmd", "exec", "command", "shell"
        }:
            continue

        decoded_value = value

        for _ in range(2):
            new_value = unquote_plus(decoded_value)

            if new_value == decoded_value:
                break

            decoded_value = new_value

        if DANGEROUS_COMMAND.search(decoded_value):
            return True

    return False


def build_finding(
    rule_id, title, severity, rows, description
):
    """Construye un hallazgo compatible con el correlador."""

    rows = sorted(rows, key=lambda r: r["event_time"])

    ips = sorted({
        str(row["normalized_source_ip"])
        for row in rows
    })

    users = sorted({
        str(row["username"])
        for row in rows
        if pd.notna(row.get("username"))
        and str(row["username"]).strip()
    })

    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "source_ip": ips[0] if len(ips) == 1 else None,
        "source_ips": ips,
        "username": users[0] if len(users) == 1 else None,
        "affected_users": users,
        "first_seen": rows[0]["event_time"].isoformat(),
        "last_seen": rows[-1]["event_time"].isoformat(),
        "failed_attempts": 0,
        "success_after_failures": False,
        "evidence_rows": sorted({
            int(row["source_row"]) for row in rows
        }),
        "description": description
    }


def get_web_events(df):
    """Prepara exclusivamente los registros HTTP."""

    if df.empty or "normalized_event_type" not in df.columns:
        return pd.DataFrame()

    web = df[
        df["normalized_event_type"].isin(WEB_TYPES)
    ].copy()

    if web.empty:
        return web

    required = [
        "normalized_timestamp",
        "normalized_source_ip",
        "source_row"
    ]

    if any(column not in web.columns for column in required):
        return pd.DataFrame()

    web["event_time"] = pd.to_datetime(
    web["normalized_timestamp"],
    errors="coerce"
    )

    web = web.dropna(
        subset=[
            "event_time",
            "normalized_source_ip",
            "source_row"
        ]
    )

    if web.empty:
        return web

    descriptions = web.get(
        "event_description",
        pd.Series("", index=web.index)
    ).fillna("").astype(str)

    commands = web.get(
        "normalized_command",
        pd.Series("", index=web.index)
    ).fillna("").astype(str)

    results = web.get(
        "result",
        pd.Series("", index=web.index)
    ).fillna("").astype(str)

    web["web_text"] = descriptions + " " + commands
    web["http_status"] = results.str.extract(
        r"\b([1-5]\d{2})\b",
        expand=False
    )

    return web.sort_values("event_time")




def detect_command_injection(web, window_minutes=5):
    """Agrupa solicitudes sospechosas en episodios temporales."""

    findings = []

    suspicious = web[
        web["web_text"].apply(is_suspicious_web_request)
    ]

    window = pd.Timedelta(minutes=window_minutes)

    for ip, group in suspicious.groupby("normalized_source_ip"):
        rows = group.sort_values("event_time").to_dict("records")

        if not rows:
            continue

        episode = [rows[0]]

        def add_finding(events):
            findings.append(build_finding(
                "SOC-WEB-001",
                "Posible ejecución de comandos vía web",
                "Alto",
                events,
                (
                    f"Se identificaron {len(events)} solicitudes "
                    f"sospechosas desde {ip} en un episodio "
                    f"de hasta {window_minutes} minutos. "
                    "Los registros contienen indicadores de "
                    "ejecución de comandos o path traversal. "
                    "No se confirma explotación efectiva."
                )
            ))

        for row in rows[1:]:
            if row["event_time"] - episode[0]["event_time"] <= window:
                episode.append(row)
            else:
                add_finding(episode)
                episode = [row]

        add_finding(episode)

    return findings




def detect_sensitive_path_scanning(
    web, threshold=5, window_minutes=5
):
    """Detecta múltiples accesos a rutas sensibles."""

    findings = []

    suspicious = web[
        web["web_text"].str.contains(
            SENSITIVE_PATHS,
            na=False
        )
    ]

    window = pd.Timedelta(minutes=window_minutes)

    for ip, group in suspicious.groupby(
        "normalized_source_ip"
    ):
        rows = group.sort_values(
            "event_time"
        ).to_dict("records")

        start = 0

        while start < len(rows):
            end = start

            while (
                end < len(rows)
                and rows[end]["event_time"]
                - rows[start]["event_time"] <= window
            ):
                end += 1

            episode = rows[start:end]

            if len(episode) >= threshold:
                findings.append(build_finding(
                    "SOC-WEB-002",
                    "Exploración de rutas web sensibles",
                    "Medio",
                    episode,
                    (
                        f"La IP {ip} realizó "
                        f"{len(episode)} solicitudes "
                        f"a rutas sensibles en un "
                        f"intervalo de {window_minutes} minutos."
                    )
                ))

                start = end
            else:
                start += 1

    return findings


def detect_http_errors(
    web, threshold=5, window_minutes=5
):
    """Detecta ráfagas de respuestas HTTP 404 y 500."""

    findings = []

    errors = web[
        web["http_status"].isin(["404", "500"])
    ]

    window = pd.Timedelta(minutes=window_minutes)

    for ip, group in errors.groupby(
        "normalized_source_ip"
    ):
        rows = group.sort_values(
            "event_time"
        ).to_dict("records")

        start = 0

        while start < len(rows):
            end = start

            while (
                end < len(rows)
                and rows[end]["event_time"]
                - rows[start]["event_time"] <= window
            ):
                end += 1

            episode = rows[start:end]

            if len(episode) >= threshold:
                findings.append(build_finding(
                    "SOC-WEB-003",
                    "Errores HTTP reiterados",
                    "Medio",
                    episode,
                    (
                        f"La IP {ip} generó "
                        f"{len(episode)} respuestas "
                        "HTTP 404/500 en un intervalo "
                        f"de {window_minutes} minutos."
                    )
                ))

                start = end
            else:
                start += 1

    return findings


def detect_web_threats(df):
    """Ejecuta todas las detecciones web."""

    web = get_web_events(df)

    if web.empty:
        return []

    findings = []

    findings.extend(detect_command_injection(web))
    findings.extend(detect_sensitive_path_scanning(web))
    findings.extend(detect_http_errors(web))

    return findings
