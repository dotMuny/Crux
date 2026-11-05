"""Identidad canónica de una comprobación, compartida entre herramientas.

Corrige una contradicción del diseño original. El fingerprint incluye
`source:check_id`, de modo que nuclei y un módulo propio detectando exactamente
lo mismo producían dos hallazgos distintos — justo lo contrario de lo que el
fingerprint promete. En el primer escaneo real eso se vio: nuclei reportó
`http-missing-security-headers` diez veces, una por cabecera, junto al hallazgo
único y ya agrupado de nuestro módulo pasivo. Doce filas para un solo problema.

Aquí se declara qué comprobaciones de herramientas distintas son la misma, y
con qué granularidad:

- `grouped=True`: todas las variantes son un único hallazgo. El discriminante
  propio de la herramienta (el matcher de nuclei, por ejemplo) se descarta,
  porque diez cabeceras ausentes son un problema con una sola corrección.
- `grouped=False`: la equivalencia vale, pero el discriminante se conserva.
  Dos cookies mal configuradas son dos hallazgos: se arreglan por separado.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True)
class Canonical:
    """Identidad compartida de una comprobación."""

    check_id: str
    grouped: bool = False
    # Cuando el origen de menor rango no puede aportar el discriminante que sí
    # aporta el nuestro, sus hallazgos se absorben: se descartan si ya existe
    # uno equivalente y mejor explicado sobre el mismo objetivo. Es el caso de
    # las cookies: nuclei dice "falta Secure" sin decir en qué cookie, mientras
    # que nuestro módulo emite un hallazgo por cookie con su nombre.
    absorb: bool = False


# Preferencia de origen al colapsar: gana el que mejor explica el hallazgo.
# Nuestros módulos agrupan, razonan la severidad y escriben la corrección,
# así que mandan sobre la salida cruda de una herramienta.
SOURCE_RANK: Final[dict[str, int]] = {
    "passive": 30,
    "authz": 30,
    "jwt": 30,
    "probe": 20,
    "gitleaks": 14,   # para un secreto, su veredicto es más fiable que un patrón
    "semgrep": 12,
    "trivy": 12,
    "nuclei": 10,
    "wapiti": 8,
    "nikto": 5,
}

# `origen:check_id` → identidad canónica.
EQUIVALENCES: Final[dict[str, Canonical]] = {
    # Cabeceras de seguridad: nuclei emite una por cabecera ausente; nosotros
    # una por origen. Un solo hallazgo, una sola corrección.
    "nuclei:http-missing-security-headers": Canonical("missing-security-headers", grouped=True),
    "passive:missing-security-headers": Canonical("missing-security-headers", grouped=True),

    # Atributos de cookie. nuclei separa por atributo (httponly, secure,
    # samesite) y no dice en qué cookie; nosotros emitimos uno por cookie con su
    # nombre. Los suyos se absorben: no aportan nada que el nuestro no diga
    # mejor, y conservarlos multiplica las filas por el número de atributos.
    "nuclei:cookies-without-": Canonical("cookie-missing-flags", absorb=True),
    "nuclei:missing-cookie-samesite": Canonical("cookie-missing-flags", absorb=True),
    "nuclei:cookie-without-": Canonical("cookie-missing-flags", absorb=True),
    "passive:cookie-missing-flags": Canonical("cookie-missing-flags"),

    # CORS
    "nuclei:cors-misconfig": Canonical("cors-misconfiguration", grouped=True),
    "passive:cors-reflects-any-origin": Canonical("cors-misconfiguration", grouped=True),
    "passive:cors-wildcard-credentials": Canonical("cors-misconfiguration", grouped=True),

    # Listado de directorio
    "nuclei:directory-listing": Canonical("directory-listing"),
    "passive:directory-listing": Canonical("directory-listing"),

    # Redirección abierta
    "nuclei:open-redirect": Canonical("open-redirect"),
    "passive:open-redirect": Canonical("open-redirect"),
    "activos:open-redirect": Canonical("open-redirect"),

    # ── Pilar de código ───────────────────────────────────────────────────
    # semgrep dispara varias reglas sobre la misma línea: cuatro para un
    # `subprocess` con shell=True, tres para una concatenación SQL. Son un
    # problema con una sola corrección, y el objetivo ya lleva fichero:línea,
    # así que agrupar por él no funde líneas distintas.
    "semgrep:subprocess-injection": Canonical("command-injection", grouped=True),
    "semgrep:dangerous-subprocess-use": Canonical("command-injection", grouped=True),
    "semgrep:dangerous-subprocess-use-audit": Canonical("command-injection", grouped=True),
    "semgrep:subprocess-shell-true": Canonical("command-injection", grouped=True),
    "semgrep:dangerous-system-call": Canonical("command-injection", grouped=True),
    "semgrep:dangerous-system-call-audit": Canonical("command-injection", grouped=True),
    "semgrep:detect-child-process": Canonical("command-injection", grouped=True),
    "semgrep:tainted-exec": Canonical("command-injection", grouped=True),
    "semgrep:exec-use": Canonical("command-injection", grouped=True),

    "semgrep:tainted-sql-string": Canonical("sql-injection-codigo", grouped=True),
    "semgrep:sqlalchemy-execute-raw-query": Canonical("sql-injection-codigo", grouped=True),
    "semgrep:formatted-sql-string": Canonical("sql-injection-codigo", grouped=True),
    "semgrep:jdbc-sqli": Canonical("sql-injection-codigo", grouped=True),
    "semgrep:csharp-sqli": Canonical("sql-injection-codigo", grouped=True),
    "semgrep:tainted-sql-query": Canonical("sql-injection-codigo", grouped=True),

    "semgrep:eval-injection": Canonical("code-injection", grouped=True),
    "semgrep:code-string-concat": Canonical("code-injection", grouped=True),
    "semgrep:eval-detected": Canonical("code-injection", grouped=True),

    "semgrep:insecure-hash-algorithm-md5": Canonical("weak-hash", grouped=True),
    "semgrep:md5-used-as-password": Canonical("weak-hash", grouped=True),
    "semgrep:insecure-hash-function": Canonical("weak-hash", grouped=True),
}


def canonical_for(source: str, check_id: str) -> Canonical | None:
    """Identidad canónica de una comprobación, por coincidencia exacta o prefijo.

    El prefijo hace falta porque los identificadores de plantilla de nuclei
    varían entre versiones y variantes: `missing-cookie-samesite` convive con
    `missing-cookie-samesite-strict`, y mantener la lista exacta al día sería
    una fuente garantizada de duplicados silenciosos.
    """
    clave = f"{source}:{check_id}"
    exacta = EQUIVALENCES.get(clave)
    if exacta is not None:
        return exacta
    for patron, canonical in EQUIVALENCES.items():
        if patron.endswith("-") and clave.startswith(patron):
            return canonical
        if clave.startswith(patron + "-"):
            return canonical
    return None


def prefer(a_source: str, b_source: str) -> bool:
    """¿Se prefiere `a` sobre `b` al colapsar dos hallazgos equivalentes?"""
    return SOURCE_RANK.get(a_source, 0) >= SOURCE_RANK.get(b_source, 0)
