
import json
from pathlib import Path

import pandas as pd


CONFIG_PATH = (
    Path(__file__).resolve().parents[2]
    / "config"
    / "detection_rules.json"
)


def load_rules():
    with open(CONFIG_PATH, encoding="utf-8") as file:
        return json.load(file)


def detect_brute_force(df):
    """
    Detecta ráfagas de fallos por IP y usuario.

    Devuelve una lista de hallazgos con evidencias.
    """

    config = load_rules()["brute_force"]

    if not config["enabled"] or df.empty:
        return []

    threshold = config["threshold"]
    window = pd.Timedelta(
        minutes=config["window_minutes"]
    )
    success_window = pd.Timedelta(
        minutes=config["success_window_minutes"]
    )

    findings = []

    groups = df.groupby(
        ["normalized_source_ip", "username"],
        dropna=True
    )

    for (ip, user), group in groups:

        group = group.sort_values("event_time")

        failures = group[
            group["normalized_event_type"]
            == "authentication_failure"
        ]

        successes = group[
            group["normalized_event_type"]
            == "authentication_success"
        ]

        # Cada elemento es una fila de evento fallido
        failed_rows = [
            row for _, row in failures.iterrows()
        ]

        index = 0

        while index < len(failed_rows):

            start = index
            end = start

            # Buscar fallos dentro de la ventana
            while (
                end < len(failed_rows)
                and failed_rows[end]["event_time"]
                - failed_rows[start]["event_time"]
                <= window
            ):
                end += 1

            count = end - start

            if count < threshold:
                index += 1
                continue

            # Extender el episodio mientras existan
            # ventanas solapadas con el umbral.
            episode_end = end
            cursor = start + 1

            while cursor < episode_end:

                next_end = cursor

                while (
                    next_end < len(failed_rows)
                    and failed_rows[next_end]["event_time"]
                    - failed_rows[cursor]["event_time"]
                    <= window
                ):
                    next_end += 1

                if next_end - cursor >= threshold:
                    episode_end = max(
                        episode_end, next_end
                    )

                cursor += 1

            episode = failed_rows[start:episode_end]

            first_time = episode[0]["event_time"]
            last_time = episode[-1]["event_time"]

            # Buscar éxito después del último fallo
            success_candidates = successes[
                (successes["event_time"] > last_time)
                & (
                    successes["event_time"]
                    <= last_time + success_window
                )
            ]

            success_found = not success_candidates.empty

            evidence_rows = [
                int(row["source_row"])
                for row in episode
            ]

            if success_found:
                evidence_rows.append(
                    int(success_candidates.iloc[0]["source_row"])
                )

            # El umbral alto se evalúa sobre el episodio.
            # Se registra también la cantidad total.
            total_failures = len(episode)

            if success_found and total_failures >= config["high_threshold"]:
                severity = "Crítico"
            elif success_found or total_failures >= config["high_threshold"]:
                severity = "Alto"
            else:
                severity = "Medio"

            findings.append({
                "rule_id": config["rule_id"],
                "title": config["name"],
                "source_ip": str(ip),
                "username": str(user),
                "first_seen": first_time.isoformat(),
                "last_seen": last_time.isoformat(),
                "failed_attempts": total_failures,
                "success_after_failures": success_found,
                "severity": severity,
                "evidence_rows": evidence_rows,
                "description": (
                    f"Se identificaron {total_failures} "
                    f"intentos fallidos para {user} "
                    f"desde {ip}."
                )
            })

            index = episode_end

    return findings
