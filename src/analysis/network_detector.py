
import re
import ipaddress
import pandas as pd


PROXY_TYPE = "proxy_access"

SHARE_TYPES = {
    "network_share_access",
    "network_share_access_check"
}

BYTES_PATTERN = re.compile(
    r"\bbytes_out\s*=\s*(\d+)\b",
    re.IGNORECASE
)


def get_text(row, field):
    value = row.get(field)
    return "" if pd.isna(value) else str(value).strip()


def prepare_network_events(df):
    required = {
        "normalized_event_type",
        "normalized_timestamp",
        "normalized_source_ip",
        "source_row"
    }

    if df.empty or not required.issubset(df.columns):
        return pd.DataFrame()

    network_types = {PROXY_TYPE} | SHARE_TYPES

    result = df[
        df["normalized_event_type"].isin(network_types)
    ].copy()

    if result.empty:
        return result

    result["event_time"] = pd.to_datetime(
        result["normalized_timestamp"],
        errors="coerce"
    )

    result = result.dropna(
        subset=[
            "event_time",
            "normalized_source_ip",
            "source_row"
        ]
    ).copy()

    # El Excel actual utiliza fechas sin zona horaria.
    # Si hay fechas mixtas, deben normalizarse antes.
    if result.empty:
        return result

    result["network_text"] = result.apply(
        lambda row: " ".join([
            get_text(row, "event_description"),
            get_text(row, "normalized_command"),
            get_text(row, "process_commandline")
        ]),
        axis=1
    )

    result["network_destination"] = result.apply(
        lambda row: (
            get_text(row, "destination")
            or get_text(row, "normalized_destination_ip")
            or get_text(row, "destination_ip")
        ),
        axis=1
    )

    return result.sort_values("event_time")


def build_network_finding(
    rule_id, title, severity, rows, description
):
    rows = sorted(
        rows,
        key=lambda row: row["event_time"]
    )

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


def extract_bytes(text):
    match = BYTES_PATTERN.search(text)
    return int(match.group(1)) if match else None


def classify_transfer_severity(total_bytes, event_count):
    """
    Clasificación heurística basada en volumen
    y cantidad de eventos proxy.
    """
    mib = total_bytes / (1024 * 1024)

    if mib >= 500 and event_count >= 10:
        return (
            "Crítico",
            "Transferencia de al menos 500 MiB "
            "distribuida en 10 o más eventos."
        )

    if mib >= 200:
        return (
            "Alto",
            "Transferencia de al menos 200 MiB "
            "hacia un destino externo."
        )

    return (
        "Alto",
        "Transferencia superior al umbral de "
        "detección de 50 MiB hacia un destino externo."
    )


DOCUMENTATION_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24")
]


def is_external_destination(value):
    host = value.strip()

    if not host:
        return False

    if host.count(":") == 1:
        host = host.split(":")[0]

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False

    if address.is_global:
        return True

    # Solo para analizar datos sintéticos de laboratorio.
    return any(
        address in network
        for network in DOCUMENTATION_NETWORKS
    )



def detect_outbound_transfers(
    network,
    threshold_bytes=50 * 1024 * 1024,
    min_events=3,
    window_minutes=5
):
    findings = []

    proxy = network[
        network["normalized_event_type"] == PROXY_TYPE
    ].copy()

    if proxy.empty:
        return findings

    proxy["bytes_out"] = proxy["network_text"].apply(
        extract_bytes
    )

    proxy = proxy.dropna(subset=["bytes_out"])

    proxy = proxy[
        proxy["network_destination"].apply(
            is_external_destination
        )
    ]

    window = pd.Timedelta(minutes=window_minutes)

    for (ip, destination), group in proxy.groupby(
        ["normalized_source_ip", "network_destination"]
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

            total_bytes = sum(
                int(row["bytes_out"])
                for row in episode
            )

            if (
                len(episode) >= min_events
                and total_bytes >= threshold_bytes
            ):
                mib = total_bytes / (1024 * 1024)

                severity, reason = classify_transfer_severity(
                    total_bytes,
                    len(episode)
                )

                finding = build_network_finding(
                    "SOC-NET-001",
                    "Transferencia saliente elevada",
                    severity,
                    episode,
                    (
                        f"La IP {ip} transfirió "
                        f"{mib:.2f} MiB hacia "
                        f"{destination} mediante "
                        f"{len(episode)} eventos proxy "
                        f"en un intervalo máximo de "
                        f"{window_minutes} minutos. "
                        "Posible exfiltración; requiere "
                        "verificar el destino y la "
                        "actividad autorizada."
                    )
                )

                finding["destination"] = str(destination)
                finding["bytes_out"] = total_bytes
                finding["severity_reason"] = reason

                findings.append(finding)
                start = end

            else:
                start += 1

    return findings



def detect_share_scanning(
    network,
    min_destinations=3,
    window_minutes=10
):
    findings = []

    shares = network[
        network["normalized_event_type"].isin(
            SHARE_TYPES
        )
    ].copy()

    shares = shares[
        shares["network_destination"].ne("")
    ]

    window = pd.Timedelta(minutes=window_minutes)

    for ip, group in shares.groupby(
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

            destinations = {
                row["network_destination"].upper()
                for row in episode
            }

            if len(destinations) >= min_destinations:
                findings.append(build_network_finding(
                    "SOC-NET-002",
                    "Acceso a múltiples recursos de red",
                    "Medio",
                    episode,
                    (
                        f"La IP {ip} accedió a "
                        f"{len(destinations)} destinos "
                        f"de recursos compartidos "
                        f"en {window_minutes} minutos. "
                        "Posible reconocimiento o "
                        "movimiento lateral."
                    )
                ))

                start = end
            else:
                start += 1

    return findings


def detect_network_threats(df):
    network = prepare_network_events(df)

    if network.empty:
        return []

    findings = []
    findings.extend(detect_outbound_transfers(network))
    findings.extend(detect_share_scanning(network))

    return findings
