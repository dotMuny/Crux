"""Escala de severidad única y traducción desde cada herramienta.

Cada herramienta usa su propio vocabulario ("Medium", "warning", "4", "ERROR").
Aquí se normaliza todo a una sola escala ordenada para que la UI, los filtros y
los informes puedan comparar hallazgos de orígenes distintos.
"""

from __future__ import annotations

import enum
import re
from typing import Final

from cvss import CVSS3, CVSS4


class Severity(enum.IntEnum):
    """Escala ordenada. El valor entero permite comparar y ordenar directamente."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.label


class Confidence(enum.IntEnum):
    """Cuánto nos creemos el hallazgo. Determina si necesita verificación manual."""

    TENTATIVE = 0
    FIRM = 1
    CERTAIN = 2

    @property
    def label(self) -> str:
        return self.name.lower()


# Vocabulario de cada herramienta → escala propia. Se consulta en minúsculas.
_ALIASES: Final[dict[str, Severity]] = {
    # Escala canónica y variantes directas
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "none": Severity.INFO,
    "unknown": Severity.INFO,
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
    # semgrep
    "inventory": Severity.INFO,
    "experiment": Severity.INFO,
    "warning": Severity.MEDIUM,
    "error": Severity.HIGH,
    # nikto / wapiti usan niveles numéricos como texto
    "0": Severity.INFO,
    "1": Severity.LOW,
    "2": Severity.MEDIUM,
    "3": Severity.HIGH,
    "4": Severity.CRITICAL,
    # gitleaks y escáneres de secretos no gradúan: un secreto filtrado es grave
    "secret": Severity.HIGH,
}


def from_tool(value: str | int | float | None, *, default: Severity = Severity.INFO) -> Severity:
    """Traduce la severidad declarada por una herramienta a la escala propia."""
    if value is None:
        return default
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return from_cvss_score(float(value), default=default)
    text = str(value).strip().lower()
    if not text:
        return default
    if text in _ALIASES:
        return _ALIASES[text]
    # Algunas herramientas escriben "Severity: High" o "high confidence"
    for token in re.findall(r"[a-z0-9]+", text):
        if token in _ALIASES:
            return _ALIASES[token]
    return default


def from_cvss_score(score: float, *, default: Severity = Severity.INFO) -> Severity:
    """Rangos de severidad cualitativa de CVSS 3.1 / 4.0."""
    if score <= 0:
        return default
    if score < 4.0:
        return Severity.LOW
    if score < 7.0:
        return Severity.MEDIUM
    if score < 9.0:
        return Severity.HIGH
    return Severity.CRITICAL


def from_cvss_vector(vector: str) -> tuple[Severity, float] | None:
    """Puntúa un vector CVSS. Devuelve None si el vector no es parseable.

    Se acepta tanto 3.x como 4.0 porque nuclei y los avisos de dependencias
    mezclan ambas versiones.
    """
    vector = vector.strip()
    if not vector:
        return None
    try:
        parsed = CVSS4(vector) if vector.startswith("CVSS:4") else CVSS3(vector)
    except Exception:
        return None
    score = float(parsed.scores()[0])
    return from_cvss_score(score), score
