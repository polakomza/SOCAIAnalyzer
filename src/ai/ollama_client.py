
import requests


OLLAMA_URL = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen2.5:3b"


class OllamaError(Exception):
    """Error controlado de comunicación con Ollama."""


def check_ollama():
    """Comprueba si el servicio local está disponible."""

    try:
        response = requests.get(
            f"{OLLAMA_URL}/api/tags",
            timeout=5
        )
        response.raise_for_status()
        return True

    except requests.RequestException:
        return False


def generate_response(
    prompt,
    model=DEFAULT_MODEL,
    timeout=180
):
    """Envía instrucciones al modelo local."""

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.2
        }
    }

    try:
        response = requests.post(
            f"{OLLAMA_URL}/api/generate",
            json=payload,
            timeout=timeout
        )

        response.raise_for_status()

        data = response.json()
        text = data.get("response", "").strip()

        if not text:
            raise OllamaError(
                "El modelo devolvió una respuesta vacía."
            )

        return text

    except requests.RequestException as exc:
        raise OllamaError(
            f"No se pudo obtener respuesta de Ollama: {exc}"
        ) from exc
