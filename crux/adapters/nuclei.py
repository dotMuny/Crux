"""Adaptador de nuclei: el motor de detección principal.

Es el adaptador de referencia; el resto copia este patrón.

Aviso importante que justifica media política de egress: **nuclei sale a internet
por defecto**. Usa el servidor Interactsh *público* (`oast.pro`, `oast.live`,
`oast.site`…) para las pruebas OAST, y comprueba actualizaciones de binario y
plantillas al arrancar. `-ni` y `-duc` no son optimizaciones, son el requisito.
"""

from __future__ import annotations

import json
from typing import Iterable
from urllib.parse import urlsplit

from ..core import paths
from ..core.egress import EgressPolicy
from ..core.findings import Evidence, EvidenceKind, Finding
from ..core.runner import ToolRun
from ..core.severity import Confidence, from_tool
from .base import Adapter, ScanContext, register

# Etiquetas que se ejecutan siempre: no dependen de la tecnología y son las que
# concentran los hallazgos reales en aplicaciones internas.
BASELINE_TAGS: tuple[str, ...] = (
    "misconfig", "exposure", "default-login", "config", "files",
    "debug", "disclosure", "unauth",
)

# Traducción de la huella que produce nuestro probador a etiquetas de nuclei.
# Sin esto se lanzan las 14.000 plantillas, con las de WordPress y Cisco
# incluidas, contra una aplicación que no es ni lo uno ni lo otro: un escaneo
# que debería durar un minuto se va a quince.
TECH_TAGS: dict[str, tuple[str, ...]] = {
    "nginx": ("nginx",),
    "Apache httpd": ("apache",),
    "IIS": ("iis", "microsoft"),
    "Gunicorn": ("python",),
    "Werkzeug": ("python", "flask"),
    "ASP.NET Core Kestrel": ("aspnet", "microsoft"),
    "PHP": ("php",),
    "Express": ("nodejs", "express"),
    "ASP.NET": ("aspnet", "microsoft"),
    "ASP.NET WebForms": ("aspnet", "microsoft"),
    "Drupal": ("drupal",),
    "Java (servlet)": ("java", "tomcat"),
    "Django": ("django", "python"),
    "Laravel": ("laravel", "php"),
    "Angular": ("angular",),
    "Next.js": ("nextjs", "nodejs"),
    "Nuxt": ("nuxt", "nodejs"),
    "WordPress": ("wordpress", "wp-plugin"),
    "Blazor": ("aspnet",),
    "Spring Boot": ("springboot", "java"),
}


def tags_for(technologies: list[str]) -> list[str]:
    """Etiquetas de nuclei a partir de la tecnología detectada.

    Las claves se comparan por prefijo porque nuestra huella añade la versión
    ("Apache httpd 2.4.49") y el mapa está indexado por producto.
    """
    tags = set(BASELINE_TAGS)
    for tech in technologies:
        for product, product_tags in TECH_TAGS.items():
            if tech.startswith(product):
                tags.update(product_tags)
    return sorted(tags)

_NUCLEI_EGRESS = EgressPolicy(
    required=("-duc", "-ni", "-nc", "-jsonl"),
    forbidden=(
        "-uc", "-uncover", "-uq", "-uncover-query", "-ue", "-uncover-engine",
        "-turl", "-template-url", "-wurl", "-workflow-url",
        "-ai", "-prompt",
        "-cloud-upload", "-dashboard", "-dsn",
        "-ut", "-update-templates", "-un", "-update",
        "-iserver", "-interactsh-server", "-itoken", "-interactsh-token",
    ),
    reasons={
        "-duc": "sin esto nuclei consulta actualizaciones al arrancar",
        "-ni": "sin esto nuclei usa el Interactsh PÚBLICO (oast.pro) para OAST",
        "-nc": "salida sin códigos de color, para poder parsearla",
        "-jsonl": "la salida JSONL es la que parseamos",
        "-uc": "el motor uncover consulta Shodan, Censys y similares",
        "-uncover": "el motor uncover consulta Shodan, Censys y similares",
        "-turl": "descargaría plantillas desde una URL remota",
        "-wurl": "descargaría workflows desde una URL remota",
        "-ai": "la generación de plantillas por IA es un servicio remoto",
        "-prompt": "la generación de plantillas por IA es un servicio remoto",
        "-cloud-upload": "subiría los resultados a ProjectDiscovery Cloud",
        "-ut": "actualizar plantillas en tiempo de escaneo exige red",
        "-iserver": "un servidor Interactsh implica tráfico OAST saliente",
    },
)


@register
class NucleiAdapter(Adapter):
    name = "nuclei"
    binary = "nuclei"
    kind = "web"
    egress = _NUCLEI_EGRESS
    version_argv = ("-version",)
    # nuclei devuelve 0 también cuando no encuentra nada; otros códigos son fallo real.
    ok_exit_codes = (0,)

    def templates_dir(self):
        """Directorio local de plantillas. Nunca se delega en la autoactualización."""
        local = paths.nuclei_templates_dir()
        if local.is_dir() and any(local.iterdir()):
            return local
        # Ubicación por defecto de nuclei, por si el bootstrap usó la suya.
        fallback = paths.Path.home() / ".local" / "nuclei-templates"
        return fallback if fallback.is_dir() else None

    def targets_for(self, ctx: ScanContext) -> list[str]:
        """Qué URLs se le pasan a nuclei.

        Casi todas sus plantillas construyen su propia ruta a partir de
        `{{BaseURL}}`, así que darle cada URL descubierta multiplica el trabajo
        sin encontrar nada más: 3.000 plantillas por 16 rutas del mismo host son
        48.000 ejecuciones para cubrir lo mismo que 3.000. Se le dan los
        orígenes.

        La excepción es el fuzzing DAST, que sí necesita rutas concretas con sus
        parámetros, porque es ahí donde inyecta.
        """
        urls = ctx.urls
        if ctx.policy.allow_injection:
            return urls
        origins: list[str] = []
        for url in urls:
            split = urlsplit(url)
            if not split.scheme or not split.netloc:
                continue
            origin = f"{split.scheme}://{split.netloc}/"
            if origin not in origins:
                origins.append(origin)
        return origins

    def build_argv(self, ctx: ScanContext) -> list[str] | None:
        urls = self.targets_for(ctx)
        if not urls:
            return None
        templates = self.templates_dir()
        if templates is None:
            raise RuntimeError(
                "no hay plantillas de nuclei instaladas. Ejecuta "
                "`install/bootstrap.sh` o `nuclei -ut -ud "
                f"{paths.nuclei_templates_dir()}` con red disponible."
            )

        targets_file = ctx.artifact("nuclei-targets.txt")
        targets_file.write_text("\n".join(urls) + "\n", encoding="utf-8")
        results_file = ctx.artifact("nuclei-results.jsonl")

        policy = ctx.policy
        argv = [
            "nuclei",
            "-duc",                      # sin comprobación de actualizaciones
            "-ni",                       # sin Interactsh: nada de OAST remoto
            "-nc",
            "-jsonl",
            "-o", str(results_file),
            "-l", str(targets_file),
            "-t", str(templates),
            "-pt", "http",               # solo HTTP: el resto no aplica aquí
            "-s", policy.nuclei_severities,
            "-rl", str(policy.nuclei_rate_limit),
            "-c", str(policy.concurrency),
            "-timeout", str(int(policy.request_timeout)),
            "-retries", "1",
            "-stats", "-si", "30",       # progreso periódico a stderr
            "-disable-clustering",
        ]

        technologies = ctx.discovered.get("technologies") or []
        if policy.allow_injection:
            # Perfil agresivo: todo el catálogo y además fuzzing DAST.
            argv += ["-etags", "dos", "-dast"]
        else:
            # El resto de perfiles acotan el catálogo a lo que la huella dice
            # que hay delante. Es la razón de tener probador propio: sin esta
            # selección se lanzan 8.000 plantillas irrelevantes.
            argv += ["-tags", ",".join(tags_for(technologies))]
            if policy.allow_active_probes:
                argv += ["-etags", "intrusive,dos,fuzz"]
            else:
                # Perfil pasivo: nada que envíe cargas al objetivo.
                argv += ["-etags", "intrusive,dos,fuzz,dast,sqli,xss,rce,lfi"]

        secretos = secretos_de_sesion(ctx)
        if secretos is not None:
            argv += ["-sf", str(secretos)]
        return argv

    def parse(self, run: ToolRun, ctx: ScanContext) -> Iterable[Finding]:
        # nuclei escribe los resultados al fichero de `-o`; stdout lleva el
        # progreso. Se lee el fichero y, si no existe, se cae a stdout.
        results_file = ctx.artifact("nuclei-results.jsonl")
        if results_file.exists():
            raw = results_file.read_text(encoding="utf-8", errors="replace")
        else:
            raw = run.text()

        # nuclei escribe una línea JSON por hallazgo. Las que no se puedan
        # leer se cuentan y se dicen: cada una es un hallazgo suyo que este
        # escaneo no va a enseñar, y callarlo es dar por limpio lo que no se
        # ha podido mirar.
        ilegibles, sin_traducir = 0, 0
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            if not line.startswith("{"):
                # nuclei mezcla su propio progreso por esta vía cuando se cae
                # a stdout; no es un hallazgo perdido.
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                ilegibles += 1
                continue
            finding = self._to_finding(record)
            if finding is None:
                sin_traducir += 1
                continue
            yield finding

        if ilegibles or sin_traducir:
            partes = []
            if ilegibles:
                partes.append(f"{ilegibles} línea(s) no son JSON válido")
            if sin_traducir:
                partes.append(
                    f"{sin_traducir} resultado(s) llegaron sin identificador de "
                    "plantilla, así que no se pueden atribuir a ninguna comprobación"
                )
            yield self.aviso_de_salida(
                f"{ilegibles + sin_traducir} resultado(s) de nuclei no se pudieron leer",
                "; ".join(partes).capitalize()
                + ". Cada uno es un hallazgo suyo que no aparece en este informe.",
                detalle={"ilegibles": ilegibles, "sin_traducir": sin_traducir},
            )

    def _to_finding(self, record: dict) -> Finding | None:
        info = record.get("info") or {}
        template_id = record.get("template-id") or record.get("templateID")
        if not template_id:
            return None

        target = _absolute(
            record.get("matched-at") or record.get("matched") or record.get("host") or "",
            record,
        )
        if not target:
            return None

        classification = info.get("classification") or {}
        cvss_vector = classification.get("cvss-metrics") or None
        cvss_score = classification.get("cvss-score")

        cwe = _as_list(classification.get("cwe-id"))
        references = _as_list(info.get("reference"))
        cves = _as_list(classification.get("cve-id"))
        if cves:
            references = [*references, *(f"CVE: {c.upper()}" for c in cves)]

        evidence: list[Evidence] = []
        request, response = record.get("request"), record.get("response")
        if request or response:
            evidence.append(
                Evidence(
                    kind=EvidenceKind.HTTP,
                    request=request,
                    response=response,
                    meta={"curl": record.get("curl-command") or ""},
                )
            )
        extracted = record.get("extracted-results") or []
        if extracted:
            evidence.append(
                Evidence(kind=EvidenceKind.RAW, snippet="\n".join(map(str, extracted)))
            )

        # El matcher distingue dos hallazgos del mismo template en el mismo
        # objetivo (p. ej. dos cabeceras distintas), así que entra al fingerprint.
        matcher = record.get("matcher-name") or ""

        return Finding(
            source=self.name,
            check_id=str(template_id),
            title=str(info.get("name") or template_id),
            description=str(info.get("description") or "").strip(),
            remediation=str(info.get("remediation") or "").strip(),
            target=str(target),
            severity=from_tool(info.get("severity")),
            # nuclei casa por firma, no por inferencia: su confianza es alta.
            confidence=Confidence.CERTAIN if not extracted else Confidence.FIRM,
            cvss_vector=cvss_vector,
            cvss_score=float(cvss_score) if isinstance(cvss_score, (int, float)) else None,
            cwe=[c.upper() for c in cwe],
            references=references,
            tags=_as_list(info.get("tags")),
            evidence=evidence,
            fingerprint_extra=matcher,
            extra={
                "template_path": record.get("template-path") or record.get("template"),
                "type": record.get("type"),
                "matcher": matcher,
                "ip": record.get("ip"),
            },
        )


def _absolute(target: str, record: dict) -> str:
    """Devuelve el objetivo como URL absoluta.

    nuclei reporta unas veces `http://host:puerto/ruta` y otras `host:puerto` a
    secas, según la plantilla. Sin esquema, el fingerprint no puede casar el
    hallazgo con el de otra herramienta sobre el mismo objetivo, así que se
    completa aquí, en el borde del adaptador, y no en el normalizador genérico
    —que no tiene forma de adivinar el esquema—.
    """
    target = (target or "").strip()
    if not target or "://" in target:
        return target
    # El esquema sale del propio registro: de la URL del host, o del puerto.
    host = str(record.get("host") or "")
    if "://" in host:
        scheme = host.split("://", 1)[0]
    else:
        scheme = "https" if target.endswith(":443") else "http"
    return f"{scheme}://{target}"


def _as_list(value) -> list[str]:
    """nuclei usa indistintamente string, lista o nada para los mismos campos."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return [str(v) for v in value if str(v).strip()]
    return [str(value)]


def secretos_de_sesion(ctx: ScanContext):
    """La sesión en el formato de secretos de nuclei, o `None` si no hay sesión.

    Va en fichero (`-sf`) y no con `-H`: los argumentos de un proceso los ve
    cualquiera con `ps`. Y va atada a los hosts auditables: nuclei solo la manda
    a ellos, nunca a un tercero al que una plantilla le haga seguir un enlace.
    """
    import json

    sesion = ctx.sesion
    if sesion is None or not (sesion.cookies or sesion.cabeceras):
        return None
    dominios = ctx.hosts_auditables(con_puerto=True)
    if not dominios:
        return None
    entradas = []
    if sesion.cookies:
        entradas.append({
            "type": "cookie", "domains": dominios,
            "cookies": [{"key": k, "value": v} for k, v in sesion.cookies.items()],
        })
    if sesion.cabeceras:
        entradas.append({
            "type": "header", "domains": dominios,
            "headers": [{"key": k, "value": v} for k, v in sesion.cabeceras.items()],
        })
    # JSON es YAML válido, y así no hay que escapar nada a mano.
    return ctx.fichero_secreto("nuclei-sesion.yaml", json.dumps({"static": entradas}))
