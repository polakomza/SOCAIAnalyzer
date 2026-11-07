import json
import re
import unicodedata
from pathlib import Path


CONFIG_PATH = (
    Path(__file__).resolve().parents[2]
    / "config"
    / "field_aliases.json"
)


def normalize_name(name):
    """Normaliza un nombre para poder compararlo."""

    text = str(name).strip().lower()

    text = unicodedata.normalize("NFKD", text)
    text = "".join(
        char for char in text
        if not unicodedata.combining(char)
    )

    return re.sub(r"[^a-z0-9]", "", text)


def load_aliases():
    """Carga las equivalencias configuradas."""

    with open(CONFIG_PATH, "r", encoding="utf-8") as file:
        return json.load(file)


def suggest_mapping(columns):
    """
    Sugiere una columna original para cada campo
    normalizado, evitando asignaciones duplicadas.
    """

    aliases = load_aliases()
    mapping = {}
    used_columns = set()

    for field, alternatives in aliases.items():

        candidates = [field] + alternatives

        for candidate in candidates:
            expected = normalize_name(candidate)

            for column in columns:

                if column in used_columns:
                    continue

                if normalize_name(column) == expected:
                    mapping[field] = column
                    used_columns.add(column)
                    break

            if field in mapping:
                break

    return mapping


def apply_mapping(df, mapping):
    """
    Crea un DataFrame normalizado.
    Conserva todos los campos originales.
    """

    result = df.copy()

    for field, original_column in mapping.items():

        if original_column not in df.columns:
            raise ValueError(
                f"La columna '{original_column}' no existe."
            )

        result[field] = df[original_column]

    return result
