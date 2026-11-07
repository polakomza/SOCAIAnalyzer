
import pandas as pd

from src.analysis.detector import load_rules


FAILURE = "authentication_failure"
SUCCESS = "authentication_success"


def sliding_episodes(events, minutes, condition):
    """
    Busca ventanas que cumplen una condición.

    Agrupa ventanas solapadas para evitar
    múltiples alertas del mismo episodio.
    """
    events = events.sort_values("event_time")
    window = pd.Timedelta(minutes=minutes)

    rows = list(events.to_dict("records"))
    matches = []

    for start in range(len(rows)):
        end = start

        while (
            end < len(rows)
            and rows[end]["event_time"]
            - rows[start]["event_time"] <= window
        ):
            end += 1

        candidate = rows[start:end]

        if condition(candidate):
            matches.append((start, end))

    # Unir ventanas solapadas
    merged = []

    for start, end in matches:
        if merged and start < merged[-1][1]:
            merged[-1] = (
                merged[-1][0],
                max(merged[-1][1], end)
            )
        else:
            merged.append((start, end))

    return [
        rows[start:end]
        for start, end in merged
    ]


def make_finding(rule, episode, **extra):
    """Construye un hallazgo estructurado."""

    return {
        "rule_id": rule["rule_id"],
        "title": rule["name"],
        "first_seen": episode[0][
            "event_time"
        ].isoformat(),
        "last_seen": episode[-1][
            "event_time"
        ].isoformat(),
        "failed_attempts": len(episode),
        "evidence_rows": sorted({
            int(row["source_row"])
            for row in episode
        }),
        "severity": "Medio",
        "success_after_failures": False,
        **extra
    }


def detect_password_spraying(df):
    """Detecta una IP atacando múltiples usuarios."""

    rule = load_rules()["password_spraying"]

    if not rule["enabled"]:
        return []

    failures = df[
        df["normalized_event_type"] == FAILURE
    ]

    findings = []

    for ip, group in failures.groupby(
        "normalized_source_ip"
    ):

        def condition(rows):
            counts = pd.Series([
                row["username"] for row in rows
            ]).value_counts()

            return (
                len(counts) >= rule["min_users"]
                and counts.max()
                <= rule["max_failures_per_user"]
            )

        episodes = sliding_episodes(
            group,
            rule["window_minutes"],
            condition
        )

        for episode in episodes:
            users = sorted({
                str(row["username"])
                for row in episode
            })

            findings.append(make_finding(
                rule,
                episode,
                source_ip=str(ip),
                username=None,
                affected_users=users,
                source_ips=[str(ip)],
                description=(
                    f"La IP {ip} realizó intentos "
                    f"fallidos contra {len(users)} "
                    "usuarios diferentes."
                )
            ))

    return findings


def detect_distributed_brute_force(df):
    """Detecta múltiples IP atacando una cuenta."""

    rule = load_rules()["distributed_brute_force"]

    if not rule["enabled"]:
        return []

    failures = df[
        df["normalized_event_type"] == FAILURE
    ]

    findings = []

    for user, group in failures.groupby("username"):

        def condition(rows):
            ips = {
                row["normalized_source_ip"]
                for row in rows
            }

            return (
                len(ips) >= rule["min_source_ips"]
                and len(rows) >= rule["min_failures"]
            )

        episodes = sliding_episodes(
            group,
            rule["window_minutes"],
            condition
        )

        for episode in episodes:
            ips = sorted({
                str(row["normalized_source_ip"])
                for row in episode
            })

            findings.append(make_finding(
                rule,
                episode,
                username=str(user),
                source_ip=None,
                source_ips=ips,
                affected_users=[str(user)],
                description=(
                    f"La cuenta {user} recibió "
                    f"{len(episode)} intentos fallidos "
                    f"desde {len(ips)} IP diferentes."
                )
            ))

    return findings


def correlate_successes(df, findings):
    """
    Busca accesos exitosos posteriores
    relacionados con cada hallazgo.
    """

    rule = load_rules()["suspicious_success"]
    window = pd.Timedelta(
        minutes=rule["success_window_minutes"]
    )

    successes = df[
        df["normalized_event_type"] == SUCCESS
    ]

    for finding in findings:

        if not rule["enabled"]:
            continue

        last_time = pd.Timestamp(
            finding["last_seen"]
        )

        candidates = successes[
            (successes["event_time"] > last_time)
            & (
                successes["event_time"]
                <= last_time + window
            )
        ]

        source_ips = set(
            finding.get("source_ips", [])
        )

        if finding.get("source_ip"):
            source_ips.add(finding["source_ip"])

        users = set(
            finding.get("affected_users", [])
        )

        if finding.get("username"):
            users.add(finding["username"])

        # Requerimos que coincidan IP y usuario
        # con el episodio sospechoso.
        candidates = candidates[
            candidates["normalized_source_ip"].isin(
                source_ips
            )
            & candidates["username"].isin(users)
        ]

        if not candidates.empty:

            success = candidates.sort_values(
                "event_time"
            ).iloc[0]

            finding["success_after_failures"] = True
            finding["success_time"] = (
                success["event_time"].isoformat()
            )
            finding["success_ip"] = str(
                success["normalized_source_ip"]
            )
            finding["success_user"] = str(
                success["username"]
            )

            finding["evidence_rows"] = sorted(
                set(finding["evidence_rows"])
                | {int(success["source_row"])}
            )

            if finding["failed_attempts"] >= 10:
                finding["severity"] = "Crítico"
            else:
                finding["severity"] = "Alto"

    return findings


def detect_advanced_threats(df):
    """Ejecuta todas las reglas avanzadas."""

    if df.empty:
        return []

    findings = []

    findings.extend(
        detect_password_spraying(df)
    )

    findings.extend(
        detect_distributed_brute_force(df)
    )

    return correlate_successes(df, findings)
