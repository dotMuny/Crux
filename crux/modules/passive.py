"""Comprobaciones propias sobre lo que ya observó el probador.

Funciones puras: toman un `ProbeResult` y devuelven `Finding`. No tocan la red,
así que se pueden probar en aislamiento y no cuentan para el presupuesto de
peticiones del perfil.

Cubre el hueco que dejan las herramientas instaladas: nuclei detecta cabeceras
ausentes con plantillas sueltas y sin agrupar, y ninguna de las demás razona
sobre la combinación de atributos de cookie, la política CORS real o la
coherencia del transporte.
"""

from __future__ import annotations

import re
from typing import Iterable
from urllib.parse import urlsplit

from ..core.findings import Evidence, EvidenceKind, Finding
from ..core.severity import Confidence, Severity
from .auth import es_redireccion_de_acceso
from .probe import SECURITY_HEADERS, ProbeResult

# Cabeceras cuya ausencia pesa más que el resto: sin estas dos, las demás son
# detalle. Se usa para graduar la severidad en lugar de reportar todo igual.
_CORE_HEADERS = {"content-security-policy", "x-content-type-options"}

_VERSION_IN_HEADER = re.compile(r"\d+\.\d+(\.\d+)?")
_INDEX_TITLE = re.compile(r"^index of /", re.I)

# Cabeceras que delatan producto y versión concreta.
_DISCLOSING_HEADERS = (
    "server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version",
    "x-generator", "x-drupal-version", "x-jenkins",
)


def origin_of(url: str) -> str:
    """Esquema, host y puerto. El objetivo de las comprobaciones de sitio."""
    split = urlsplit(url)
    return f"{split.scheme}://{split.netloc}"


def _http_evidence(result: ProbeResult) -> list[Evidence]:
    return [
        Evidence(
            kind=EvidenceKind.HTTP,
            request=result.raw_request,
            response=result.raw_response,
            meta={"status": result.status, "final_url": result.final_url},
        )
    ]


def check_security_headers(result: ProbeResult) -> Iterable[Finding]:
    """Cabeceras de seguridad ausentes, agrupadas en un solo hallazgo.

    Un hallazgo por objetivo y no uno por cabecera: siete hallazgos separados
    para la misma causa y la misma corrección solo inflan la cola de triaje.
    """
    missing = result.missing_security_headers
    if not missing:
        return
    # HSTS solo tiene sentido sobre HTTPS; sobre HTTP el problema es el transporte.
    if urlsplit(result.final_url).scheme != "https":
        missing = [h for h in missing if h != "strict-transport-security"]
    if not missing:
        return

    severity = Severity.MEDIUM if _CORE_HEADERS.issubset(set(missing)) else Severity.LOW
    yield Finding(
        source="passive",
        check_id="missing-security-headers",
        title=f"{len(missing)} cabeceras de seguridad ausentes",
        description=(
            "La respuesta no incluye: " + ", ".join(missing) + ". "
            "Sin Content-Security-Policy ni X-Content-Type-Options, el navegador "
            "no tiene instrucciones para limitar el daño de una inyección de "
            "contenido ni para evitar la interpretación errónea del tipo MIME."
        ),
        remediation=(
            "Añade las cabeceras en el proxy inverso o en el middleware de la "
            "aplicación. Empieza por Content-Security-Policy y "
            "X-Content-Type-Options: nosniff, que son las que más aportan."
        ),
        target=origin_of(result.final_url),
        severity=severity,
        confidence=Confidence.CERTAIN,
        cwe=["CWE-693"],
        owasp=["A05:2021"],
        evidence=_http_evidence(result),
        extra={"missing": missing},
    )


def check_cookies(result: ProbeResult) -> Iterable[Finding]:
    """Atributos de cookie. Un hallazgo por cookie: la corrección es por cookie."""
    https = urlsplit(result.final_url).scheme == "https"
    for cookie in result.cookies:
        name = str(cookie.get("name", ""))
        problems: list[str] = []
        if not cookie.get("httponly"):
            problems.append("sin HttpOnly (accesible desde JavaScript)")
        if https and not cookie.get("secure"):
            problems.append("sin Secure (viaja en claro si hay una petición HTTP)")
        samesite = cookie.get("samesite")
        if not samesite:
            problems.append("sin SameSite (se envía en peticiones de otros sitios)")
        elif str(samesite).lower() == "none" and not cookie.get("secure"):
            problems.append("SameSite=None sin Secure, que el navegador rechaza")
        if not problems:
            continue

        # Una cookie que parece de sesión merece más severidad que una de
        # preferencias: es la diferencia entre robar la sesión y el tema oscuro.
        looks_session = bool(re.search(r"sess|sid|auth|token|jwt", name, re.I))
        yield Finding(
            source="passive",
            check_id="cookie-missing-flags",
            title=f"Cookie «{name}» {problems[0].split(' (')[0]}"
                  + (f" y {len(problems) - 1} atributo(s) más" if len(problems) > 1 else ""),
            description=(
                f"La cookie «{name}» se emite con problemas en sus atributos: "
                + "; ".join(problems) + ". "
                + ("El nombre sugiere que identifica la sesión, así que estos "
                   "atributos protegen directamente la cuenta del usuario."
                   if looks_session else
                   "Si en algún momento pasa a identificar sesión, estos "
                   "atributos dejan de ser opcionales.")
            ),
            remediation=(
                "Emite la cookie con HttpOnly, Secure y SameSite=Lax "
                "(o Strict si el flujo lo permite)."
            ),
            target=result.final_url,
            severity=Severity.MEDIUM if looks_session else Severity.LOW,
            confidence=Confidence.CERTAIN,
            cwe=["CWE-1004" if not cookie.get("httponly") else "CWE-614"],
            owasp=["A05:2021"],
            evidence=_http_evidence(result),
            fingerprint_extra=name,
            extra={"cookie": cookie, "problems": problems},
        )


def check_cors(result: ProbeResult) -> Iterable[Finding]:
    """Política CORS real, deducida del sondeo con un origen inexistente."""
    cors = result.cors
    if not cors or cors.get("error"):
        return

    credentials = bool(cors.get("allow_credentials"))
    if cors.get("reflects_origin"):
        # Reflejar el origen y además permitir credenciales es lo que de verdad
        # permite leer respuestas autenticadas desde cualquier página.
        yield Finding(
            source="passive",
            check_id="cors-reflects-any-origin",
            title="CORS refleja cualquier Origin"
                  + (" y permite credenciales" if credentials else ""),
            description=(
                f"El servidor copió el Origin de prueba ({cors.get('probe_origin')}) "
                "a Access-Control-Allow-Origin. "
                + ("Con Access-Control-Allow-Credentials: true, cualquier página "
                   "que abra un empleado puede leer respuestas autenticadas de "
                   "esta aplicación."
                   if credentials else
                   "Sin credenciales el impacto es menor, pero expone respuestas "
                   "que dependan de la red interna.")
                + ("" if cors.get("vary_origin") else
                   " Además falta Vary: Origin, de modo que una caché intermedia "
                   "puede servir la cabecera de un origen a otro.")
            ),
            remediation=(
                "Sustituye el reflejo por una lista blanca de orígenes. "
                "Access-Control-Allow-Credentials nunca debe combinarse con un "
                "origen reflejado. Añade Vary: Origin."
            ),
            target=origin_of(result.final_url),
            severity=Severity.HIGH if credentials else Severity.MEDIUM,
            confidence=Confidence.CERTAIN,
            cwe=["CWE-942"],
            owasp=["A05:2021"],
            evidence=[
                Evidence(
                    kind=EvidenceKind.HTTP,
                    request=f"GET {result.final_url}\r\nOrigin: {cors.get('probe_origin')}\r\n\r\n",
                    response=str(cors.get("raw_response", "")),
                )
            ],
            extra=dict(cors, raw_response=None),
        )
    elif cors.get("wildcard") and credentials:
        yield Finding(
            source="passive",
            check_id="cors-wildcard-credentials",
            title="CORS con comodín y credenciales",
            description=(
                "Access-Control-Allow-Origin: * junto a Allow-Credentials: true. "
                "Los navegadores rechazan esta combinación, así que además de "
                "insegura en intención, la política no funciona como se espera."
            ),
            remediation="Declara los orígenes concretos que deben poder usar credenciales.",
            target=origin_of(result.final_url),
            severity=Severity.MEDIUM,
            confidence=Confidence.CERTAIN,
            cwe=["CWE-942"],
            evidence=_http_evidence(result),
        )


def check_version_disclosure(result: ProbeResult) -> Iterable[Finding]:
    """Cabeceras que declaran producto y versión exacta."""
    disclosing = {
        name: result.headers[name]
        for name in _DISCLOSING_HEADERS
        if name in result.headers and _VERSION_IN_HEADER.search(result.headers[name])
    }
    if not disclosing:
        return
    yield Finding(
        source="passive",
        check_id="version-disclosure",
        title="El servidor declara producto y versión",
        description=(
            "Las cabeceras de respuesta revelan versiones concretas: "
            + "; ".join(f"{k}: {v}" for k, v in disclosing.items()) + ". "
            "Eso permite a un atacante buscar vulnerabilidades conocidas de esas "
            "versiones exactas sin tener que sondear la aplicación."
        ),
        remediation=(
            "Suprime o generaliza estas cabeceras en el proxy inverso "
            "(ServerTokens Prod en Apache, server_tokens off en nginx, "
            "y retira X-Powered-By en la aplicación)."
        ),
        target=origin_of(result.final_url),
        severity=Severity.INFO,
        confidence=Confidence.CERTAIN,
        cwe=["CWE-200"],
        evidence=_http_evidence(result),
        extra={"headers": disclosing},
    )


def check_transport(result: ProbeResult) -> Iterable[Finding]:
    """HTTP que no lleva a HTTPS: todo lo demás viaja en claro."""
    if urlsplit(result.final_url).scheme != "http":
        return
    yield Finding(
        source="passive",
        check_id="cleartext-transport",
        title="La aplicación responde por HTTP sin redirigir a HTTPS",
        description=(
            "La petición terminó en una URL http:// sin redirección a https. "
            "Credenciales, cookies de sesión y datos viajan en claro por la red "
            "interna, donde cualquiera con acceso al segmento puede leerlos."
        ),
        remediation=(
            "Redirige todo el tráfico HTTP a HTTPS y añade "
            "Strict-Transport-Security una vez funcione."
        ),
        target=origin_of(result.final_url),
        severity=Severity.MEDIUM,
        confidence=Confidence.CERTAIN,
        cwe=["CWE-319"],
        owasp=["A02:2021"],
        evidence=_http_evidence(result),
    )


def check_directory_listing(result: ProbeResult) -> Iterable[Finding]:
    """Índice automático de directorio."""
    if not _INDEX_TITLE.search(result.title or ""):
        return
    files = re.findall(r'href="([^"?/][^"]*)"', result.body_preview)[:20]
    yield Finding(
        source="passive",
        check_id="directory-listing",
        title="Listado de directorio habilitado",
        description=(
            "El servidor genera un índice navegable del directorio, que revela "
            "nombres de ficheros no enlazados desde la aplicación"
            + (f": {', '.join(files[:6])}" if files else ".")
        ),
        remediation=(
            "Desactiva el índice automático (Options -Indexes en Apache, "
            "autoindex off en nginx) y retira los ficheros que no deban publicarse."
        ),
        target=result.final_url,
        severity=Severity.LOW,
        confidence=Confidence.CERTAIN,
        cwe=["CWE-548"],
        evidence=_http_evidence(result),
        extra={"files": files},
    )


def check_out_of_scope_redirect(result: ProbeResult) -> Iterable[Finding]:
    """Redirección fuera del alcance: casi siempre es una redirección abierta.

    El probador corta el salto y deja constancia en `error`. Que una app interna
    pueda enviar al navegador a un destino arbitrario es, además de una fuga de
    alcance para nosotros, un vector de phishing para ellos.
    """
    if not result.error or "fuera del alcance" not in result.error:
        return
    destination = result.redirect_chain[-1] if result.redirect_chain else "?"
    # Mandar a un anónimo a autenticarse en el Keycloak de la casa no es una
    # redirección abierta: el destino lo fija la configuración, no la petición.
    # Salía en el informe de cada aplicación protegida por SSO.
    if es_redireccion_de_acceso(destination, result.url):
        return
    yield Finding(
        source="passive",
        check_id="open-redirect",
        title="Redirección hacia un destino externo controlable",
        description=(
            f"La aplicación respondió con una redirección a {destination}, fuera "
            "de la red interna. El escaneo no la siguió. Si el destino procede de "
            "un parámetro de la petición, es una redirección abierta: sirve para "
            "dar apariencia legítima a un enlace de phishing."
        ),
        remediation=(
            "Valida el destino contra una lista blanca de rutas internas, o usa "
            "identificadores en lugar de URLs completas en el parámetro."
        ),
        target=result.url,
        severity=Severity.MEDIUM,
        confidence=Confidence.FIRM,
        cwe=["CWE-601"],
        owasp=["A01:2021"],
        evidence=_http_evidence(result),
        extra={"destination": destination, "chain": result.redirect_chain},
    )




# ── Contenido sensible en la respuesta ───────────────────────────────────────
# Motivo de existir: en el primer escaneo real, /debug/env devolvió el DSN de
# la base de datos, la clave de sesión y la contraseña de SMTP con un 200, y
# ninguna comprobación lo marcó. Un endpoint accesible no es un hallazgo; un
# endpoint accesible que devuelve credenciales, sí.

# (etiqueta, patrón, CWE, ¿group(1) es el nombre del campo?)
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str, bool], ...] = (
    (
        "cadena de conexión con credenciales",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)"
                   r"://[^\s:'\"]+:([^\s@'\"]{3,})@[^\s/'\"]+", re.I),
        "CWE-522",
        False,
    ),
    (
        "clave privada",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
        "CWE-321",
        False,
    ),
    (
        "clave de acceso de AWS",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "CWE-798",
        False,
    ),
    (
        "credencial en un campo de configuración",
        # Clave con pinta de secreto y un valor que no es vacío ni un hueco.
        re.compile(
            r"[\"']?\b((?:[A-Za-z_][A-Za-z0-9_]*)?(?:PASSWORD|PASSWD|SECRET_KEY|SECRET|"
            r"API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY|AUTH_TOKEN))\b[\"']?\s*[:=]\s*"
            r"[\"']([^\"'\s,}]{6,})[\"']",
            re.I,
        ),
        "CWE-215",
        True,
    ),
)

# Valores que aparecen en plantillas y ejemplos: marcarlos sería ruido.
_PLACEHOLDERS = re.compile(
    r"^(?:\*+|x+|changeme|password|secret|your[-_]?\w*|<[^>]+>|\$\{[^}]+\}|"
    r"null|none|true|false|example|todo|redacted|\.{3,})$",
    re.I,
)


def _redact(value: str) -> str:
    """Muestra lo justo para reconocer el secreto sin reproducirlo entero.

    El informe circula por correo y se adjunta a tickets; el valor completo vive
    en la evidencia, no en el titular.
    """
    if len(value) <= 4:
        return "*" * len(value)
    # Máscara de largo fijo: proporcional al secreto desbordaba el informe.
    return f"{value[:2]}{'*' * 6}{value[-2:]}"


def check_sensitive_content(result: ProbeResult) -> Iterable[Finding]:
    """Credenciales o secretos devueltos en el cuerpo de una respuesta."""
    body = result.body_preview
    if not body or result.status >= 400:
        return

    encontrados: list[dict[str, str]] = []
    for etiqueta, patron, cwe, tiene_campo in _SECRET_PATTERNS:
        for match in patron.finditer(body):
            # El último grupo capturado es el valor; si no hay grupos, el match.
            valor = next((g for g in reversed(match.groups()) if g), match.group(0))
            if _PLACEHOLDERS.match(valor.strip()):
                continue
            # Solo un patrón captura el nombre del campo; en los demás, group(1)
            # es el propio secreto y no debe acabar de titular.
            campo = match.group(1) if tiene_campo else etiqueta
            encontrados.append(
                {"tipo": etiqueta, "campo": campo, "valor": _redact(valor), "cwe": cwe}
            )
    if not encontrados:
        return

    # Deduplicar por campo: un .env repetido no son veinte hallazgos.
    por_campo: dict[str, dict[str, str]] = {}
    for item in encontrados:
        por_campo.setdefault(item["campo"].upper(), item)
    items = list(por_campo.values())

    yield Finding(
        source="passive",
        check_id="sensitive-content-exposed",
        title=f"La respuesta expone {len(items)} credencial(es) en claro",
        description=(
            "La respuesta contiene valores con aspecto de secreto, accesibles "
            "sin autenticar: "
            + "; ".join(f"{i['campo']} = {i['valor']} ({i['tipo']})" for i in items)
            + ". Los valores van parcialmente ocultos aquí; están completos en "
            "la evidencia."
        ),
        remediation=(
            "Retira el endpoint del despliegue de producción y rota todas las "
            "credenciales expuestas: hay que darlas por comprometidas, porque "
            "cualquiera con acceso a la red interna ha podido leerlas."
        ),
        target=result.final_url,
        severity=Severity.HIGH,
        confidence=Confidence.FIRM,
        cwe=sorted({i["cwe"] for i in items}),
        owasp=["A05:2021"],
        evidence=_http_evidence(result),
        extra={"secretos": items},
    )


# Comprobaciones que describen una RUTA concreta: se aplican a cada resultado.
PER_URL_CHECKS = (
    check_cookies,
    check_directory_listing,
    check_out_of_scope_redirect,
    check_sensitive_content,
)

# Comprobaciones que describen el SITIO: cabeceras, versiones, transporte y CORS
# son propiedades del origen, no de la ruta. Se evalúan sobre una respuesta
# representativa por origen y anotan en cuántas rutas se observaron, en lugar de
# producir un hallazgo idéntico por cada URL visitada.
PER_SITE_CHECKS = (
    check_security_headers,
    check_cors,
    check_version_disclosure,
    check_transport,
)

ALL_CHECKS = PER_URL_CHECKS + PER_SITE_CHECKS


# Qué identificador emite cada comprobación. Hace falta para saber qué se
# comprobó, que no es lo mismo que qué se encontró: una comprobación que corre
# y no encuentra nada es indistinguible de una que no llegó a correr, salvo que
# se declare explícitamente.
CHECK_IDS: dict[object, str] = {
    check_security_headers: "missing-security-headers",
    check_cookies: "cookie-missing-flags",
    check_cors: "cors-reflects-any-origin",
    check_version_disclosure: "version-disclosure",
    check_transport: "cleartext-transport",
    check_directory_listing: "directory-listing",
    check_out_of_scope_redirect: "open-redirect",
    check_sensitive_content: "sensitive-content-exposed",
}


def coverage(results: Iterable[ProbeResult]) -> set[str]:
    """Comprobaciones que de verdad se evaluaron sobre estos resultados.

    Casi todas se evalúan siempre que haya una respuesta viva. La de CORS es la
    excepción: depende de un sondeo adicional que el perfil pasivo no autoriza,
    así que si ningún resultado trae datos de CORS, esa comprobación no corrió y
    sus hallazgos previos no se pueden dar por corregidos.
    """
    results = [r for r in results if r.alive or r.error]
    if not results:
        return set()
    cubiertas = {
        cid for check, cid in CHECK_IDS.items() if check is not check_cors
    }
    if any(r.cors and not r.cors.get("error") for r in results):
        cubiertas.add(CHECK_IDS[check_cors])
    return cubiertas


def run_all(results: Iterable[ProbeResult]) -> list[Finding]:
    """Aplica las comprobaciones: por ruta unas, por origen las demás."""
    results = [r for r in results if r.alive or r.error]
    findings: list[Finding] = []

    for result in results:
        for check in PER_URL_CHECKS:
            findings.extend(check(result))

    # Un representante por origen: la primera respuesta viva, que es la que
    # lleva cabeceras y cookies reales. Si solo hubo errores, se usa la primera.
    by_origin: dict[str, list[ProbeResult]] = {}
    for result in results:
        by_origin.setdefault(origin_of(result.final_url), []).append(result)

    for origin, group in by_origin.items():
        representative = next((r for r in group if r.alive), group[0])
        paths = sorted({urlsplit(r.final_url).path or "/" for r in group if r.alive})
        for check in PER_SITE_CHECKS:
            for finding in check(representative):
                finding.extra["observed_on"] = paths
                finding.extra["paths_checked"] = len(paths)
                if len(paths) > 1:
                    finding.description += (
                        f" Observado en las {len(paths)} rutas analizadas de {origin}."
                    )
                findings.append(finding)
    return findings
