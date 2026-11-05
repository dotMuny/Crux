"""Informe HTML. El sistema de diseño se inserta en línea, sin recursos externos."""

from __future__ import annotations

import base64
import html as html_escape
import re
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Sequence

from jinja2 import Environment, FileSystemLoader
from markupsafe import Markup

from ..findings import Finding
from ..scope import Scope
from ..severity import Severity

_HERE = Path(__file__).parent
_TEMPLATES = _HERE / "templates"
_TOKENS = _HERE / "tokens.css"
_FONTS = _HERE / "fonts"

# Familia, peso y fichero de cada corte que viaja dentro del informe.
_CORTES = (
    ("B612", 400, "B612-Regular.woff2"),
    ("B612", 700, "B612-Bold.woff2"),
    ("B612 Mono", 400, "B612Mono-Regular.woff2"),
)


@lru_cache(maxsize=1)
def fuentes_en_linea() -> str:
    """Las `@font-face` del informe, con la tipografía dentro.

    El informe se abre en equipos que no son el del analista —el de quien lo
    recibe, un visor de PDF, un servidor de correo que lo previsualiza—, y en
    ninguno está instalada la B612. Enlazarla sería una petición a la red desde
    un documento que promete no hacer ninguna; dejarla al sistema es que cada
    lector vea una letra distinta. Así que va en base64, como el resto del
    estilo. Son unos 190 kB por informe.

    Si falta algún fichero no se rompe nada: ese corte no se declara y el
    navegador sigue con la siguiente familia de la pila.
    """
    reglas = []
    for familia, peso, fichero in _CORTES:
        ruta = _FONTS / fichero
        if not ruta.is_file():
            continue
        datos = base64.b64encode(ruta.read_bytes()).decode("ascii")
        reglas.append(
            f'@font-face{{font-family:"{familia}";font-weight:{peso};font-style:normal;'
            f'src:url(data:font/woff2;base64,{datos}) format("woff2")}}'
        )
    return "\n".join(reglas)

LEVEL_TOKEN = {
    "critical": "crit", "high": "high", "medium": "med", "low": "low", "info": "info",
}
LEVEL_LABEL = {
    "critical": "crítica", "high": "alta", "medium": "media",
    "low": "baja", "info": "informativa",
}
ORDER = ["critical", "high", "medium", "low", "info"]

_HEADER_LINE = re.compile(r"^([A-Za-z][A-Za-z0-9-]*):", re.M)


def _http_filter(raw: str) -> Markup:
    """Resalta los nombres de cabecera en un volcado HTTP crudo.

    Escapa primero y marca después. Devuelve `Markup` porque el entorno
    escapa todo lo demás: sin esa marca, los `<span>` que se añaden aquí
    saldrían como texto.
    """
    escaped = html_escape.escape(raw or "")
    return Markup(_HEADER_LINE.sub(r'<span class="hk">\1</span>:', escaped))


def _environment() -> Environment:
    env = Environment(
        loader=FileSystemLoader(_TEMPLATES),
        # Escapado SIEMPRE, sin mirar la extensión. Antes era
        # `select_autoescape(["html", "xml"])`, que decide por cómo termina el
        # nombre del fichero: la plantilla se llama `report.html.j2`, termina
        # en `.j2`, y el escapado quedaba apagado sin que nada lo dijera. El
        # título, la descripción y la evidencia de un hallazgo salen del
        # objetivo auditado; un objetivo hostil podía meter un `<script>` en el
        # informe que luego abre el analista o su cliente. Lo poco que es HTML
        # de verdad —el estilo, el primer párrafo— se marca a mano.
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["http"] = lambda raw: _http_filter(raw)
    return env


def _lede(counts: dict[str, int], alive: int, probed: int, targets: int,
          kind: str = "web", ruta: str = "") -> str:
    """Primer párrafo del informe: lo que lee quien decide, no quien corrige."""
    critical, high = counts.get("critical", 0), counts.get("high", 0)
    if kind == "code":
        # La ruta la escribe quien lanza el análisis, pero este párrafo se
        # inserta como HTML: se escapa igual que todo lo demás.
        parts = [f"Se analizó el código de {html_escape.escape(ruta) or 'el repositorio'}, "
                 "sus dependencias y sus secretos. No se usó la red."]
    else:
        parts = [
            f"El escaneo cubrió {targets} objetivo(s) y encontró {alive} URL(s) "
            f"activas de {probed} probadas."
        ]
    if critical:
        parts.append(
            f"<b>{critical} hallazgo(s) de severidad crítica</b> requieren "
            "atención inmediata."
        )
        if high:
            parts.append(f"Otros {high} son de severidad alta.")
    elif high:
        parts.append(f"<b>{high} hallazgo(s) de severidad alta</b> encabezan la lista.")
    else:
        parts.append("No se encontró nada de severidad alta ni crítica.")
    return " ".join(parts)


def build_context(
    findings: Sequence[Finding],
    *,
    project: str,
    scan_id: int | str,
    profile: str,
    scope: Scope,
    started: datetime,
    duration: str,
    alive: int,
    probed: int,
    new: int = 0,
    fixed: int = 0,
    tools: Sequence[str] = (),
    version: str = "0.1.0",
    new_fingerprints: frozenset[str] = frozenset(),
    kind: str = "web",
    ruta: str = "",
) -> dict[str, Any]:
    ordered = sorted(findings, key=lambda f: (-int(f.severity), f.source, f.title))
    counts = {level: 0 for level in ORDER}
    for finding in ordered:
        counts[finding.severity.label] += 1

    # Los títulos de las plantillas de nuclei van en inglés y así se dejan.
    # Traducirlos obligaría a mantener un diccionario de textos ajenos que
    # cambia con cada actualización de plantillas, y atribuiría a Crux una
    # redacción que no es suya. El chip de origen (`nuclei:<id>`) deja claro
    # de quién es cada hallazgo. Ver docs/decisiones.md.
    prepared = []
    for finding in ordered:
        prepared.append(
            {
                "severity_label": finding.severity.label,
                "title": finding.title,
                "description": finding.description,
                "remediation": finding.remediation,
                "target": finding.target,
                "param": finding.param,
                "source": finding.source,
                "check_id": finding.check_id,
                "cwe": finding.cwe,
                "cvss_score": finding.cvss_score,
                "evidence": finding.evidence,
                "is_new": finding.fingerprint in new_fingerprints,
            }
        )

    return {
        "project": project,
        "scan_id": scan_id,
        "profile": profile,
        "started": started.strftime("%Y-%m-%d %H:%M"),
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "duration": duration,
        "targets_count": len(scope.entries),
        "alive": alive,
        "probed": probed,
        "new": new,
        "fixed": fixed,
        "findings": prepared,
        "severity_counts": counts,
        "level_token": LEVEL_TOKEN,
        "level_label": LEVEL_LABEL,
        "order": ORDER,
        "kind": kind,
        "headline": (f"Análisis del código de {ruta}" if kind == "code"
                     else f"Auditoría de {', '.join(scope.hosts[:3]) or 'objetivos internos'}"),
        "lede": _lede(counts, alive, probed, len(scope.entries), kind, ruta),
        "scope_text": (ruta if kind == "code"
                       else ", ".join(e.raw for e in scope.entries)),
        "egress": "0 conexiones fuera del alcance",
        "tools": ", ".join(tools) or "módulos propios",
        "version": version,
        "tokens": _TOKENS.read_text(encoding="utf-8"),
        "fuentes": fuentes_en_linea(),
    }


def render_html(context: dict[str, Any], destination: Path | None = None) -> str:
    """Renderiza el informe. Si se da destino, también lo escribe."""
    rendered = _environment().get_template("report.html.j2").render(**context)
    if destination is not None:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(rendered, encoding="utf-8")
    return rendered
