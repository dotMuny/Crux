"""Adaptador de wapiti: inyección SQL, XSS y ejecución de órdenes.

Cubre de golpe tres clases que no tenemos como módulo propio. Se prefiere a
escribir un fuzzer nuestro porque wapiti ya está instalado, mantiene sus
cargas al día y distingue bien el reflejo del contexto en el que reflejó.

Aviso de egress: **wapiti envía un informe automático a sus autores cuando un
módulo falla**. `--no-bugreport` no es opcional.
"""

from __future__ import annotations

import json
from typing import Iterable
from urllib.parse import urlsplit

from ..core.egress import EgressPolicy
from ..core.findings import Evidence, EvidenceKind, Finding
from ..core.runner import ToolRun
from ..core.severity import Confidence, Severity
from .base import Adapter, ScanContext, register

_WAPITI_EGRESS = EgressPolicy(
    required=("--no-bugreport", "-f", "--scope"),
    forbidden=("--update", "--tor", "--proxy", "-p"),
    reasons={
        "--no-bugreport": "sin esto wapiti envía un informe a sus autores cuando un módulo falla",
        "-f": "el formato de salida es el que parseamos",
        "--scope": "sin alcance declarado wapiti sigue enlaces fuera del objetivo",
        "--update": "actualizar exige red",
        "--tor": "enrutar por Tor es tráfico saliente",
        "--proxy": "un proxy es una ruta de salida que no controlamos",
    },
)

# Qué módulos de wapiti se ejecutan y cómo se traduce cada hallazgo suyo.
# Nombre que usa wapiti → (check_id propio, severidad, CWE, OWASP)
TRADUCCION: dict[str, tuple[str, Severity, str, str]] = {
    # Los nombres son los que wapiti devuelve en `name()`, tomados de su propio
    # código: inventarlos es garantía de que un hallazgo pase sin traducir.
    "SQL Injection": ("sql-injection", Severity.CRITICAL, "CWE-89", "A03:2021"),
    "Blind SQL Injection": ("sql-injection-ciega", Severity.CRITICAL, "CWE-89", "A03:2021"),
    "Reflected Cross Site Scripting": ("xss-reflejado", Severity.HIGH, "CWE-79", "A03:2021"),
    "Stored Cross Site Scripting": ("xss-almacenado", Severity.CRITICAL, "CWE-79", "A03:2021"),
    "HTML Injection": ("html-injection", Severity.MEDIUM, "CWE-79", "A03:2021"),
    "Stored HTML Injection": ("html-injection-almacenada", Severity.HIGH, "CWE-79", "A03:2021"),
    "Command execution": ("ejecucion-de-ordenes", Severity.CRITICAL, "CWE-78", "A03:2021"),
    "Path Traversal": ("path-traversal", Severity.HIGH, "CWE-22", "A01:2021"),
    "Server Side Request Forgery": ("ssrf", Severity.HIGH, "CWE-918", "A10:2021"),
    "XML External Entity": ("xxe", Severity.HIGH, "CWE-611", "A05:2021"),
    "XPATH Injection": ("xpath-injection", Severity.HIGH, "CWE-643", "A03:2021"),
    "LDAP Injection": ("ldap-injection", Severity.HIGH, "CWE-90", "A03:2021"),
    "Open Redirect": ("open-redirect", Severity.MEDIUM, "CWE-601", "A01:2021"),
    "CRLF Injection": ("crlf-injection", Severity.MEDIUM, "CWE-93", "A03:2021"),
    "Log4Shell": ("log4shell", Severity.CRITICAL, "CWE-917", "A06:2021"),
    "Spring4Shell": ("spring4shell", Severity.CRITICAL, "CWE-94", "A06:2021"),
    "Unrestricted File Upload": ("subida-sin-restriccion", Severity.CRITICAL, "CWE-434", "A04:2021"),
    "Weak credentials": ("credenciales-debiles", Severity.CRITICAL, "CWE-521", "A07:2021"),
    "Potentially dangerous file": ("fichero-peligroso", Severity.MEDIUM, "CWE-200", ""),
    "Backup file": ("fichero-de-respaldo", Severity.MEDIUM, "CWE-530", ""),
    "Internal Server Error": ("error-interno", Severity.LOW, "CWE-209", ""),
    "Information Disclosure - Full Path": ("ruta-absoluta-revelada", Severity.INFO, "CWE-200", ""),
}

# Módulos por perfil. En activo seguro se excluyen los que escriben o tardan
# desproporcionadamente; el perfil agresivo los añade.
MODULOS_SEGUROS = ("sql", "xss", "redirect", "crlf")
MODULOS_AGRESIVOS = MODULOS_SEGUROS + ("exec", "file", "ssrf", "xxe", "permanentxss")


@register
class WapitiAdapter(Adapter):
    name = "wapiti"
    binary = "wapiti"
    kind = "web"
    egress = _WAPITI_EGRESS
    version_argv = ("--version",)
    # wapiti devuelve códigos variados según lo que encuentre; el informe es
    # la fuente de verdad, no el código de salida.
    ok_exit_codes = (0, 1, 2, 3, 4, 5, 6, 7, 8)

    def build_argv(self, ctx: ScanContext) -> list[str] | None:
        if not ctx.policy.allow_active_probes:
            # wapiti sólo sabe trabajar enviando cargas: en perfil pasivo no
            # tiene nada que hacer y ejecutarlo sería incumplir el perfil.
            return None

        objetivos = ctx.urls
        if not objetivos:
            return None
        # wapiti escanea un objetivo por ejecución; se toma el origen y se deja
        # que recorra desde ahí, que es su modo natural.
        partes = urlsplit(objetivos[0])
        base = f"{partes.scheme}://{partes.netloc}/"

        informe = ctx.artifact("wapiti.json")
        modulos = MODULOS_AGRESIVOS if ctx.policy.allow_injection else MODULOS_SEGUROS

        return [
            "wapiti",
            "-u", base,
            "--no-bugreport",           # sin esto escribe a sus autores
            "-f", "json",
            "-o", str(informe),
            "--scope", "folder",
            "-m", ",".join(modulos),
            "-l", "2" if ctx.policy.allow_injection else "1",
            "--max-scan-time", str(ctx.policy.task_timeout or 900),
            "--flush-session",          # sin reutilizar sesiones de escaneos previos
            "-v", "0",
            # Nivel 1 de detalle: incluye la petición HTTP de cada hallazgo,
            # que es lo que se muestra como evidencia.
            "--detailed-report", "1",
            *argumentos_de_sesion(ctx),
        ]

    def parse(self, run: ToolRun, ctx: ScanContext) -> Iterable[Finding]:
        informe = ctx.artifact("wapiti.json")
        datos, aviso = self.leer_json(informe, vacio={})
        if aviso is not None:
            yield aviso
        for nombre, entradas in ((datos or {}).get("vulnerabilities") or {}).items():
            traduccion = TRADUCCION.get(nombre)
            for entrada in entradas or []:
                yield self._a_finding(nombre, traduccion, entrada, ctx)

    def _a_finding(self, nombre, traduccion, entrada: dict, ctx) -> Finding:
        """Un hallazgo de wapiti, con su objetivo ya absoluto (ver `_absoluto`)."""
        check_id, severidad, cwe, owasp = traduccion or (
            nombre.lower().replace(" ", "-"), Severity.MEDIUM, "", ""
        )
        ruta = _absoluto(entrada.get("path") or entrada.get("url") or "", ctx)
        parametro = entrada.get("parameter") or None
        peticion = entrada.get("http_request") or ""

        return Finding(
            source=self.name,
            check_id=check_id,
            title=f"{nombre}" + (f" en el parámetro «{parametro}»" if parametro else ""),
            description=(entrada.get("info") or nombre).strip(),
            remediation=(
                "Usa consultas parametrizadas y no construyas SQL concatenando entrada."
                if "sql" in check_id else
                "Escapa la salida según el contexto —HTML, atributo, JavaScript— y "
                "añade una Content-Security-Policy."
                if "xss" in check_id else
                "Valida la entrada contra una lista blanca en el servidor."
            ),
            target=ruta,
            param=parametro,
            severity=severidad,
            # wapiti confirma enviando una carga y observando el efecto, no
            # infiriendo de una versión: su confianza es alta.
            confidence=Confidence.CERTAIN,
            cwe=[cwe] if cwe else [],
            owasp=[owasp] if owasp else [],
            evidence=[Evidence(
                kind=EvidenceKind.HTTP,
                request=peticion,
                snippet=entrada.get("curl_command") or None,
                meta={"nivel": entrada.get("level"), "modulo": entrada.get("module")},
            )] if peticion else [],
            fingerprint_extra=parametro or "",
            extra={"wapiti": nombre},
        )


def _absoluto(ruta: str, ctx) -> str:
    """Completa la ruta relativa que devuelve wapiti con su origen.

    wapiti informa de `/search`, no de `http://host:8999/search`. Un objetivo
    sin host no se puede colgar de ningún servicio: en el grafo de superficie
    aparecía como un host propio llamado «/search», y en el panel como un
    objetivo aparte. El origen es el mismo que se le pasó a ejecutar, así que
    reconstruirlo no inventa nada.
    """
    if not ruta or "://" in ruta:
        return ruta
    objetivos = ctx.urls
    if not objetivos:
        return ruta
    partes = urlsplit(objetivos[0])
    if not partes.netloc:
        return ruta
    return f"{partes.scheme}://{partes.netloc}" + ("" if ruta.startswith("/") else "/") + ruta


# Rutas que cierran la sesión. wapiti recorre por su cuenta, y un solo «salir»
# deja el resto del escaneo sin autenticar.
SALIDAS = ("/logout", "/signout", "/salir", "/cerrar-sesion", "/logoff", "/oauth2/sign_out",
           "/protocol/openid-connect/logout")


def argumentos_de_sesion(ctx: ScanContext) -> list[str]:
    """Cómo darle a wapiti la sesión del escaneo.

    Las cookies van en su fichero JSON (`-c`), que no aparece en `ps`. La
    cabecera Authorization solo admite `-H`, en la línea de órdenes: es el
    único sitio donde un token queda a la vista de otros usuarios del equipo,
    durante lo que dure wapiti. Se acepta porque los tokens de un proveedor
    como Keycloak caducan en minutos, y se documenta.
    """
    import json

    sesion = ctx.sesion
    if sesion is None:
        return []
    argv: list[str] = []
    if sesion.cookies:
        tarro: dict = {}
        for host in ctx.hosts_auditables():
            # El formato de wapiti: las IP tal cual, los nombres con un punto
            # delante, como los guarda su propio exportador.
            clave = host if host.replace(".", "").isdigit() else f".{host}"
            tarro.setdefault(clave, {}).setdefault("/", {}).update({
                nombre: {"value": valor, "version": 0, "expires": None,
                         "secure": False, "port": None}
                for nombre, valor in sesion.cookies.items()
            })
        argv += ["-c", str(ctx.fichero_secreto("wapiti-sesion.json", json.dumps(tarro)))]
    for nombre, valor in sesion.cabeceras.items():
        argv += ["-H", f"{nombre}: {valor}"]
    # Lo que cierra la sesión, fuera. Con la URL entera: `-x` no admite patrones.
    salidas = [u for u in ctx.urls if any(s in urlsplit(u).path.lower() for s in SALIDAS)]
    for url in dict.fromkeys(salidas):
        argv += ["-x", url]
    for raiz in dict.fromkeys(f"{urlsplit(u).scheme}://{urlsplit(u).netloc}" for u in ctx.urls):
        argv += ["-x", f"{raiz}/logout"]
    return argv
