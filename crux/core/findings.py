"""El modelo de hallazgo normalizado: el contrato que une orquestador, UI e informes.

Toda herramienta y todo módulo propio produce `Finding`. La pieza crítica es el
`fingerprint`: un hash estable que hace que (a) dos herramientas reportando lo
mismo colapsen en un solo hallazgo y (b) al reescanear se pueda decir si un
hallazgo es nuevo, sigue ahí o está corregido.
"""

from __future__ import annotations

import enum
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from .severity import Confidence, Severity, from_cvss_vector, from_tool


class FindingStatus(enum.StrEnum):
    """Estado de triaje. Persiste entre escaneos vía `FindingState`."""

    NEW = "new"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    ACCEPTED_RISK = "accepted_risk"


class EvidenceKind(enum.StrEnum):
    HTTP = "http"
    CODE = "code"
    SCREENSHOT = "screenshot"
    RAW = "raw"


@dataclass(slots=True)
class Evidence:
    """Prueba de un hallazgo. `http` lleva petición/respuesta crudas."""

    kind: EvidenceKind
    request: str | None = None
    response: str | None = None
    snippet: str | None = None
    path: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)


# Identificadores que cambian en cada ejecución y romperían la estabilidad del
# fingerprint si entrasen en él: sesiones, nonces, tokens, timestamps.
_VOLATILE_PARAMS = frozenset(
    {
        "_", "cachebuster", "csrf", "csrfmiddlewaretoken", "csrftoken", "nonce",
        "rand", "random", "sid", "state", "t", "timestamp", "token", "ts",
        "jsessionid", "phpsessid", "asp.net_sessionid", "viewstate",
    }
)

_HEX_RUN = re.compile(r"\b[0-9a-f]{8,}\b", re.I)
_DIGIT_RUN = re.compile(r"\d+")
_UUID = re.compile(
    r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I
)


def normalize_target(target: str) -> str:
    """Reduce un objetivo a su forma estable para el fingerprint.

    Para URLs: conserva esquema, host, puerto y ruta, y de la query solo los
    *nombres* de parámetro (ordenados) descartando los volátiles. Los valores se
    tiran porque cambian en cada ejecución. Los segmentos de ruta que son
    identificadores (números, UUIDs, hashes) se colapsan a `{id}` para que
    `/user/41` y `/user/42` no sean dos hallazgos distintos.

    Para rutas de ficheros y host:puerto: se devuelve tal cual, en minúsculas.
    """
    target = target.strip()
    if not target:
        return ""
    split = urlsplit(target)
    if not split.scheme or not split.netloc:
        # Ruta de fichero o host:puerto: no hay nada que normalizar más allá del caso.
        return target.lower()

    host = split.hostname or ""
    port = split.port
    default_port = {"http": 80, "https": 443}.get(split.scheme)
    authority = host if port in (None, default_port) else f"{host}:{port}"

    segments = [_collapse_identifier(seg) for seg in split.path.split("/")]
    path = "/".join(segments) or "/"

    names = sorted(
        {
            name.lower()
            for name, _ in parse_qsl(split.query, keep_blank_values=True)
            if name.lower() not in _VOLATILE_PARAMS
        }
    )
    query = ("?" + "&".join(names)) if names else ""
    return f"{split.scheme.lower()}://{authority.lower()}{path}{query}"


def _collapse_identifier(segment: str) -> str:
    """`42`, un UUID o un hash largo dentro de una ruta se vuelven `{id}`."""
    if not segment:
        return segment
    if _UUID.fullmatch(segment):
        return "{id}"
    if segment.isdigit():
        return "{id}"
    if _HEX_RUN.fullmatch(segment):
        return "{id}"
    # Identificadores incrustados: `invoice-10294.pdf` → `invoice-{id}.pdf`
    return _DIGIT_RUN.sub("{id}", segment) if any(c.isdigit() for c in segment) else segment


def compute_fingerprint(
    *,
    check_id: str,
    target: str,
    param: str | None = None,
    extra: str | None = None,
) -> str:
    """Hash estable de la identidad de un hallazgo.

    Deliberadamente **no** incluye severidad, confianza, evidencia ni marcas de
    tiempo: todo eso puede cambiar entre ejecuciones sin que el hallazgo sea otro.
    `check_id` debe ser el identificador canónico de la comprobación cuando la
    herramienta lo da (p. ej. el template-id de nuclei o la rule-id de semgrep),
    nunca el título traducible.
    """
    parts = [
        check_id.strip().lower(),
        normalize_target(target),
        (param or "").strip().lower(),
        (extra or "").strip().lower(),
    ]
    digest = hashlib.sha256("\x1f".join(parts).encode("utf-8")).hexdigest()
    return digest[:32]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(slots=True)
class Finding:
    """Un hallazgo normalizado, independiente de la herramienta que lo produjo."""

    source: str                      # "nuclei" | "probe" | "semgrep" | "authz" | ...
    check_id: str                    # identificador canónico de la comprobación
    title: str
    target: str                      # URL, host:puerto o fichero:línea
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.FIRM
    description: str = ""
    remediation: str = ""
    param: str | None = None         # parámetro afectado, si aplica
    cvss_vector: str | None = None
    cvss_score: float | None = None
    cwe: list[str] = field(default_factory=list)
    owasp: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=_utcnow)
    # Discriminante extra para el fingerprint, cuando el mismo check en el mismo
    # objetivo puede dar hallazgos legítimamente distintos (p. ej. dos cabeceras).
    fingerprint_extra: str | None = None

    def __post_init__(self) -> None:
        # Del vector CVSS se deriva la puntuación, pero **no** se toca la
        # severidad: la etiqueta que da la herramienta manda. Muchas plantillas
        # de nuclei llevan un CVSS genérico junto a una severidad `info`, y
        # ascenderlas automáticamente inundaría la cola de triaje. El score se
        # guarda igualmente porque sirve para ordenar y para el informe.
        if self.cvss_vector and self.cvss_score is None:
            scored = from_cvss_vector(self.cvss_vector)
            if scored is not None:
                _, self.cvss_score = scored

    @property
    def fingerprint(self) -> str:
        """Identidad del hallazgo.

        Si la comprobación tiene identidad canónica declarada, se usa esa en
        lugar de `origen:check_id`: así dos herramientas que detectan lo mismo
        colapsan en un hallazgo, que es lo que el fingerprint promete.
        """
        from .equivalence import canonical_for

        canonical = canonical_for(self.source, self.check_id)
        if canonical is None:
            check_id = f"{self.source}:{self.check_id}"
            extra = self.fingerprint_extra
        else:
            check_id = canonical.check_id
            # En una comprobación agrupada el discriminante de la herramienta
            # (el matcher de nuclei) no distingue hallazgos: los multiplica.
            extra = None if canonical.grouped else self.fingerprint_extra
        return compute_fingerprint(
            check_id=check_id,
            target=self.target,
            param=self.param,
            extra=extra,
        )

    @classmethod
    def from_tool_severity(cls, severity: Any, **kwargs: Any) -> Finding:
        """Atajo para los adaptadores: traduce la severidad cruda al construir."""
        return cls(severity=from_tool(severity), **kwargs)
