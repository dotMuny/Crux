"""Comprobaciones propias que envían cargas al objetivo.

Separadas de `passive` a propósito: éstas modifican lo que se pide y sólo
corren si el perfil autoriza sondeo activo. Trabajan sobre los parámetros que
descubrió el crawler, que es lo que las hace precisas: en vez de fuzzear a
ciegas, prueban el parámetro concreto que la aplicación acepta.
"""

from __future__ import annotations

import asyncio
import re
from typing import Iterable, Sequence
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx

from ..core.findings import Evidence, EvidenceKind, Finding
from ..core.policy import Policy
from ..core.scope import Scope
from ..core.severity import Confidence, Severity

# Nombres de parámetro que suelen llevar un destino de redirección.
PARAMS_DE_REDIRECCION = re.compile(
    r"^(next|url|uri|redirect|redirect_uri|redirect_url|return|return_to|returnurl|"
    r"dest|destination|continue|go|target|forward|callback|r|u)$", re.I
)

# Dominio reservado por RFC 2606: no existe, no resuelve y no puede pertenecer
# a nadie. Si el servidor nos manda aquí, es que acepta cualquier destino.
MARCADOR = "https://crux-redirect-probe.invalid/comprobacion"


def _sustituir(url: str, parametro: str, valor: str) -> str:
    partes = urlsplit(url)
    query = [(k, valor if k == parametro else v)
             for k, v in parse_qsl(partes.query, keep_blank_values=True)]
    if parametro not in dict(query):
        query.append((parametro, valor))
    return urlunsplit((partes.scheme, partes.netloc, partes.path,
                       urlencode(query, doseq=True), partes.fragment))


async def comprobar_redireccion_abierta(
    scope: Scope, policy: Policy, endpoints: Sequence[dict], *, sesion=None,
) -> list[Finding]:
    """Sustituye los parámetros de destino y mira a dónde manda el servidor.

    No sigue la redirección: le basta con leer la cabecera Location. Seguirla
    sería salir del alcance, que es precisamente lo que esta herramienta no
    hace ni para comprobar una redirección abierta.
    """
    if not policy.allow_active_probes:
        return []

    candidatos: list[tuple[str, str]] = []
    for endpoint in endpoints:
        url = endpoint.get("url", "")
        if not url or not scope.allows_url(url):
            continue
        for parametro in endpoint.get("params", []):
            if PARAMS_DE_REDIRECCION.match(parametro):
                candidatos.append((url, parametro))
    if not candidatos:
        return []

    hallazgos: list[Finding] = []
    vistos: set[tuple[str, str]] = set()
    async with httpx.AsyncClient(
        trust_env=False, follow_redirects=False, verify=False,
        timeout=httpx.Timeout(policy.request_timeout),
        headers={"User-Agent": "crux/0.1 (authorized internal audit)",
                 **(sesion.cabeceras if sesion is not None else {})},
        # La mitad de los parámetros de redirección viven detrás del login: el
        # «volver a» de después de una acción, el «siguiente» de un asistente.
        cookies=sesion.cookies if sesion is not None else None,
    ) as cliente:
        semaforo = asyncio.Semaphore(policy.concurrency)

        async def probar(url: str, parametro: str) -> None:
            clave = (urlsplit(url).path, parametro)
            if clave in vistos:
                return
            vistos.add(clave)
            sonda = _sustituir(url, parametro, MARCADOR)
            async with semaforo:
                try:
                    r = await cliente.get(sonda)
                except httpx.HTTPError:
                    return
            destino = r.headers.get("location", "")
            # También cuenta una redirección por meta refresh o por JavaScript,
            # que es la variante que muchos escáneres pasan por alto.
            en_cuerpo = MARCADOR in r.text[:4000] and r.status_code < 400
            if not (destino.startswith(MARCADOR) or en_cuerpo):
                return

            hallazgos.append(Finding(
                source="activos",
                check_id="open-redirect",
                title=f"Redirección abierta en el parámetro «{parametro}»",
                description=(
                    f"Con {parametro}={MARCADOR}, el servidor respondió "
                    f"{r.status_code} y "
                    + (f"apuntó Location a ese destino." if destino.startswith(MARCADOR)
                       else "reprodujo el destino en el cuerpo para redirigir desde el cliente.")
                    + " La aplicación redirige a cualquier sitio que se le indique, "
                    "así que un enlace que empieza por el dominio interno de la "
                    "organización puede acabar en una página de phishing. El escaneo "
                    "no siguió la redirección."
                ),
                remediation=(
                    "Valida el destino contra una lista blanca de rutas internas, o usa "
                    "un identificador en lugar de una URL completa en el parámetro."
                ),
                target=url,
                param=parametro,
                severity=Severity.MEDIUM,
                confidence=Confidence.CERTAIN,
                cwe=["CWE-601"],
                owasp=["A01:2021"],
                evidence=[Evidence(
                    kind=EvidenceKind.HTTP,
                    request=f"GET {sonda}\r\n\r\n",
                    response=f"HTTP/1.1 {r.status_code}\r\n"
                             + "".join(f"{k}: {v}\r\n" for k, v in r.headers.items())
                             + "\r\n" + r.text[:400],
                )],
                fingerprint_extra=parametro,
            ))

        await asyncio.gather(*(probar(u, p) for u, p in candidatos))
    return hallazgos
