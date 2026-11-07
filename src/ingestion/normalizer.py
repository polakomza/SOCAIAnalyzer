
import ipaddress
import re

import pandas as pd


# Equivalencias de eventos conocidos
EVENT_TYPES = {
    "login_failed": "authentication_failure",
    "failed_login": "authentication_failure",
    "logon_failure": "authentication_failure",
    "authentication_failed": "authentication_failure",

    "login_success": "authentication_success",
    "successful_login": "authentication_success",
    "logon_success": "authentication_success",
    "authentication_successful": "authentication_success",

    # Windows Security
    "4625": "authentication_failure",
    "4624": "authentication_success",
    "4634": "logoff",
    "4648": "explicit_credentials_logon",
    "4672": "special_privileges_assigned",
    "4688": "process_creation",
    "4698": "scheduled_task_created",
    "4663": "object_access",
    "5140": "network_share_access",
    "5145": "network_share_access_check",
    "5156": "network_connection_allowed",
    "4104": "powershell_script_block",

    # Windows System
    "7045": "service_installed",
    "7036": "service_state_changed"
}



# Equivalencias de severidad textual
SEVERITY_TEXT = {
    "critical": "Crítico",
    "critico": "Crítico",
    "high": "Alto",
    "alto": "Alto",
    "medium": "Medio",
    "medio": "Medio",
    "moderate": "Medio",
    "low": "Bajo",
    "bajo": "Bajo",
    "informational": "Informativo",
    "info": "Informativo",
}


def normalize_event_type(value):
    """Normaliza nombres y códigos de eventos."""

    if pd.isna(value):
        return "unknown"

    text = str(value).strip().lower()

    # Evita interpretar 4625.0 como un evento desconocido.
    if re.fullmatch(r"\d+\.0", text):
        text = text[:-2]

    text = re.sub(r"[\s-]+", "_", text)

    return EVENT_TYPES.get(text, text)



def normalize_ip(value):
    """Valida y clasifica direcciones IPv4 e IPv6."""

    if pd.isna(value) or str(value).strip() == "":
        return None, "No disponible"

    try:
        address = ipaddress.ip_address(str(value).strip())

        if address.is_loopback:
            category = "Loopback"
        elif address.is_link_local:
            category = "Link-local"
        elif address.is_multicast:
            category = "Multicast"
        elif address.is_unspecified:
            category = "No especificada"
        elif address.is_global:
            category = "Pública"
        elif address.is_private:
            category = "Privada / no global"
        else:
            category = "Especial / reservada"

        return str(address), category

    except ValueError:
        return None, "Inválida"



def normalize_severity(value):
    """
    Normaliza severidad textual.
    Los valores numéricos quedan sin clasificar
    hasta conocer la fuente.
    """

    if pd.isna(value):
        return "No disponible"

    text = str(value).strip().lower()

    if text in SEVERITY_TEXT:
        return SEVERITY_TEXT[text]

    return "No clasificada"



def normalize_timestamp(value, dayfirst=False):
    """Normaliza fechas sin inventar una zona horaria."""

    if pd.isna(value):
        return None

    try:
        timestamp = pd.to_datetime(
            value,
            errors="coerce",
            dayfirst=dayfirst
        )

        if pd.isna(timestamp):
            return None

        return timestamp.isoformat()

    except (ValueError, TypeError, OverflowError):
        return None


def normalize_event_id(value):
    """Normaliza identificadores numéricos de eventos."""

    if pd.isna(value):
        return None

    text = str(value).strip()

    if re.fullmatch(r"\d+\.0", text):
        text = text[:-2]

    return text or None


def normalize_result(value):
    """Normaliza resultados de operaciones."""

    if pd.isna(value):
        return "unknown"

    text = str(value).strip().lower()

    if text in {"success", "successful", "succeeded"}:
        return "success"

    if text in {"failure", "failed", "denied", "error"}:
        return "failure"

    return text or "unknown"


def normalize_command(value):
    """Conserva comandos como texto para detecciones."""

    if pd.isna(value):
        return ""

    return str(value).strip()


def normalize_dataframe(df, source_name, sheet_name, dayfirst=False):
    """
    Normaliza eventos conservando las columnas
    originales y agregando campos de análisis.
    """

    result = df.copy()

    # Identificación y trazabilidad
    result["source_file"] = source_name
    result["source_sheet"] = sheet_name
    result["source_row"] = range(2, len(result) + 2)

    # Normalización de fechas
    if "timestamp" in result.columns:
        result["normalized_timestamp"] = (
            result["timestamp"].apply(
                lambda value: normalize_timestamp(
                    value,
                    dayfirst=dayfirst
                )
            )
        )

    # Normalización de IP de origen
    if "source_ip" in result.columns:
        ip_results = result["source_ip"].apply(normalize_ip)

        result["normalized_source_ip"] = (
            ip_results.apply(lambda x: x[0])
        )

        result["source_ip_category"] = (
            ip_results.apply(lambda x: x[1])
        )

    # Normalización de IP de destino
    if "destination_ip" in result.columns:
        ip_results = result["destination_ip"].apply(normalize_ip)

        result["normalized_destination_ip"] = (
            ip_results.apply(lambda x: x[0])
        )

        result["destination_ip_category"] = (
            ip_results.apply(lambda x: x[1])
        )

    # Normalización de eventos
    if "event_type" in result.columns:
        result["normalized_event_type"] = (
            result["event_type"].apply(normalize_event_type)
        )

    # Normalización de severidad
    if "severity" in result.columns:
        result["normalized_severity"] = (
            result["severity"].apply(normalize_severity)
        )

    
    # Identificador del evento
    if "event_id" in result.columns:
        result["normalized_event_id"] = (
            result["event_id"].apply(normalize_event_id)
        )

    # Resultado de la operación
    if "result" in result.columns:
        result["normalized_result"] = (
            result["result"].apply(normalize_result)
        )

    # Comando ejecutado
    if "process_commandline" in result.columns:
        result["normalized_command"] = (
            result["process_commandline"].apply(
                normalize_command
            )
        )

    # Tipo de evento basado en Event_ID
    if "normalized_event_id" in result.columns:

        event_types = result[
            "normalized_event_id"
        ].apply(normalize_event_type)

        if "normalized_event_type" not in result.columns:
            result["normalized_event_type"] = event_types

        else:
            # Prioriza el código conocido cuando
            # el tipo textual no está reconocido.
            known_ids = result[
                "normalized_event_id"
            ].isin(EVENT_TYPES)

            result.loc[
                known_ids,
                "normalized_event_type"
            ] = event_types[known_ids]

    return result
