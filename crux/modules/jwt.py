"""Análisis de JSON Web Tokens.

Módulo propio en lugar de `jwt_tool` por dos motivos: PyJWT y jwcrypto ya están
en el sistema, y sobre todo porque aquí hace falta encadenar el análisis con una
prueba activa —forjar un token y ver si el servidor lo traga— que una
herramienta externa no puede hacer sin que le digamos a qué endpoint.

Dos clases de comprobación:

- **Estáticas**: se leen del propio token y no tocan el objetivo. Algoritmo
  declarado, caducidad, reclamaciones sensibles, firma vacía.
- **Activas**: se forja un token y se envía. Son las que demuestran el fallo en
  vez de sugerirlo, y por eso sólo corren si el perfil autoriza sondeo activo.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable

import httpx

from ..core.findings import Evidence, EvidenceKind, Finding
from ..core.severity import Confidence, Severity

# Un JWT son tres bloques base64url separados por puntos. El tercero puede ir
# vacío, que es precisamente el caso de `alg: none`.
PATRON_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")

# Reclamaciones que no deberían viajar en un token que el cliente puede leer:
# el payload va en base64, no cifrado.
CLAIMS_SENSIBLES = ("password", "passwd", "secret", "ssn", "dni", "nif", "iban",
                    "credit_card", "tarjeta", "api_key", "private")

# Secretos que aparecen una y otra vez en tutoriales y plantillas. La lista es
# corta a propósito: esto comprueba lo evidente, no sustituye a un ataque de
# diccionario en condiciones.
SECRETOS_HABITUALES = (
    "secret", "secretkey", "secret_key", "jwt_secret", "jwtsecret", "changeme",
    "password", "123456", "key", "mysecret", "supersecret", "your-256-bit-secret",
    "your_jwt_secret", "s3cr3t", "test", "dev", "development", "admin", "token",
    "qwerty", "clave", "miclave", "contrasena", "shhhhh", "jwt", "default",
)


def _b64d(dato: str) -> bytes:
    return base64.urlsafe_b64decode(dato + "=" * (-len(dato) % 4))


def _b64e(dato: bytes) -> str:
    return base64.urlsafe_b64encode(dato).decode().rstrip("=")


@dataclass(slots=True)
class TokenJwt:
    crudo: str
    cabecera: dict[str, Any] = field(default_factory=dict)
    payload: dict[str, Any] = field(default_factory=dict)
    firma: str = ""
    origen: str = ""          # cookie:NOMBRE | header | body | storage

    @property
    def alg(self) -> str:
        return str(self.cabecera.get("alg", "")).lower()

    @property
    def resumen(self) -> str:
        """Identificador corto para no reproducir el token entero en el informe."""
        return f"{self.crudo[:12]}…{self.crudo[-6:]}" if len(self.crudo) > 24 else "…"


def parsear(crudo: str, origen: str = "") -> TokenJwt | None:
    partes = crudo.split(".")
    if len(partes) != 3:
        return None
    try:
        cabecera = json.loads(_b64d(partes[0]))
        payload = json.loads(_b64d(partes[1]))
    except Exception:
        return None
    if not isinstance(cabecera, dict) or not isinstance(payload, dict):
        return None
    return TokenJwt(crudo=crudo, cabecera=cabecera, payload=payload,
                    firma=partes[2], origen=origen)


def extraer(textos: Iterable[tuple[str, str]]) -> list[TokenJwt]:
    """Encuentra JWTs en pares (origen, texto). Deduplica por token."""
    encontrados: dict[str, TokenJwt] = {}
    for origen, texto in textos:
        if not texto:
            continue
        for coincidencia in PATRON_JWT.findall(texto):
            if coincidencia in encontrados:
                continue
            token = parsear(coincidencia, origen)
            if token is not None:
                encontrados[coincidencia] = token
    return list(encontrados.values())


# ── Comprobaciones estáticas ────────────────────────────────────────────────
def analizar(token: TokenJwt, objetivo: str) -> list[Finding]:
    """Lo que se deduce del token sin tocar el servidor."""
    hallazgos: list[Finding] = []
    evidencia = [Evidence(
        kind=EvidenceKind.RAW,
        snippet=f"header:  {json.dumps(token.cabecera, ensure_ascii=False)}\n"
                f"payload: {json.dumps(token.payload, ensure_ascii=False)}\n"
                f"firma:   {token.firma[:24] or '(vacía)'}",
        meta={"origen": token.origen},
    )]

    if token.alg in ("none", ""):
        hallazgos.append(Finding(
            source="jwt", check_id="jwt-alg-none-emitido",
            title="El servidor emite un JWT sin firmar",
            description=(
                f"El token hallado en {token.origen or 'la respuesta'} declara "
                f"alg «{token.alg or 'ausente'}» y no lleva firma. Cualquiera "
                "puede reescribir el payload, incluido el rol."
            ),
            remediation="Firma los tokens con HS256 o RS256 y rechaza alg none en el verificador.",
            target=objetivo, severity=Severity.CRITICAL, confidence=Confidence.CERTAIN,
            cwe=["CWE-347"], owasp=["A02:2021"], evidence=evidencia,
            fingerprint_extra=token.origen,
        ))

    if "exp" not in token.payload:
        hallazgos.append(Finding(
            source="jwt", check_id="jwt-sin-caducidad",
            title="El JWT no tiene fecha de caducidad",
            description=(
                "El payload no incluye la reclamación «exp», así que el token "
                "vale indefinidamente. Un token robado no deja de servir nunca, "
                "y revocarlo exige una lista negra que casi nunca existe."
            ),
            remediation="Añade exp con una vida corta y usa tokens de refresco para renovar.",
            target=objetivo, severity=Severity.MEDIUM, confidence=Confidence.CERTAIN,
            cwe=["CWE-613"], evidence=evidencia, fingerprint_extra=token.origen,
        ))
    else:
        with_exp = token.payload.get("exp")
        iat = token.payload.get("iat", time.time())
        if isinstance(with_exp, (int, float)) and isinstance(iat, (int, float)):
            dias = (with_exp - iat) / 86400
            if dias > 30:
                hallazgos.append(Finding(
                    source="jwt", check_id="jwt-vida-excesiva",
                    title=f"El JWT vive {dias:.0f} días",
                    description=(
                        "Una vida tan larga equivale a no caducar: si el token se "
                        "filtra, el acceso dura meses."
                    ),
                    remediation="Reduce exp a minutos u horas y renueva con un token de refresco.",
                    target=objetivo, severity=Severity.LOW, confidence=Confidence.FIRM,
                    cwe=["CWE-613"], evidence=evidencia, fingerprint_extra=token.origen,
                ))

    sensibles = [c for c in token.payload if any(s in c.lower() for s in CLAIMS_SENSIBLES)]
    if sensibles:
        hallazgos.append(Finding(
            source="jwt", check_id="jwt-claims-sensibles",
            title=f"El JWT lleva {len(sensibles)} reclamación(es) sensible(s)",
            description=(
                f"El payload incluye {', '.join(sensibles)}. El payload de un JWT "
                "va en base64, no cifrado: cualquiera que vea el token lo lee."
            ),
            remediation="Saca esos datos del token y guárdalos en el servidor, referenciados por un identificador opaco.",
            target=objetivo, severity=Severity.HIGH, confidence=Confidence.CERTAIN,
            cwe=["CWE-312"], evidence=evidencia, fingerprint_extra=token.origen,
        ))

    if token.alg.startswith("hs"):
        secreto = romper_secreto(token)
        if secreto is not None:
            hallazgos.append(Finding(
                source="jwt", check_id="jwt-secreto-debil",
                title="La firma del JWT usa un secreto trivial",
                description=(
                    f"La firma se reproduce con el secreto «{secreto}», de una lista "
                    f"de {len(SECRETOS_HABITUALES)} valores habituales en tutoriales. "
                    "Con él se puede emitir cualquier token, con cualquier rol."
                ),
                remediation=(
                    "Genera un secreto aleatorio de al menos 256 bits, guárdalo fuera "
                    "del código y rótalo: hay que dar por comprometidos los tokens ya emitidos."
                ),
                target=objetivo, severity=Severity.CRITICAL, confidence=Confidence.CERTAIN,
                cwe=["CWE-321"], owasp=["A02:2021"], evidence=evidencia,
                fingerprint_extra=token.origen,
            ))
    return hallazgos


def romper_secreto(token: TokenJwt) -> str | None:
    """Prueba la lista corta de secretos habituales contra la firma HMAC."""
    algoritmos = {"hs256": hashlib.sha256, "hs384": hashlib.sha384, "hs512": hashlib.sha512}
    digest = algoritmos.get(token.alg)
    if digest is None or not token.firma:
        return None
    firmado = token.crudo.rsplit(".", 1)[0].encode()
    for candidato in SECRETOS_HABITUALES:
        esperada = _b64e(hmac.new(candidato.encode(), firmado, digest).digest())
        if hmac.compare_digest(esperada, token.firma):
            return candidato
    return None


# ── Comprobación activa ─────────────────────────────────────────────────────
def forjar_alg_none(token: TokenJwt, **sobrescribir: Any) -> str:
    """Construye un token con alg none, sin firma, y el payload alterado."""
    cabecera = {**token.cabecera, "alg": "none"}
    payload = {**token.payload, **sobrescribir}
    return f"{_b64e(json.dumps(cabecera).encode())}.{_b64e(json.dumps(payload).encode())}."


async def probar_alg_none(
    cliente: httpx.AsyncClient, url: str, token: TokenJwt,
    *, cabecera: str = "Authorization", prefijo: str = "Bearer ",
) -> Finding | None:
    """Envía un token forjado y comprueba si el servidor lo acepta.

    Esto es lo que separa «el token no está firmado» de «el servidor acepta
    tokens sin firmar»: la segunda es la vulnerabilidad, y hace falta probarla.
    """
    forjado = forjar_alg_none(token, role="admin", rol="admin", admin=True)
    # La referencia es un token BASURA, no el legítimo.
    #
    # Comparar contra el legítimo parece natural y es un error: si el token que
    # tenemos ya no vale —ha caducado, es de otro entorno, la aplicación lo
    # rechaza por cualquier motivo—, ambas respuestas difieren y la prueba se
    # da por negativa aunque el servidor esté tragando tokens sin firmar. Lo
    # que hay que demostrar es que el servidor distingue un token inválido de
    # uno con alg:none; si rechaza el basura y acepta el forjado, no está
    # verificando la firma.
    basura = f"{_b64e(b'{\"alg\":\"HS256\"}')}.{_b64e(b'{\"sub\":\"x\"}')}.aW52YWxpZG8"
    try:
        control = await cliente.get(url, headers={cabecera: prefijo + basura})
        falsa = await cliente.get(url, headers={cabecera: prefijo + forjado})
    except httpx.HTTPError:
        return None

    aceptado = 200 <= falsa.status_code < 300
    control_rechazado = control.status_code >= 400
    if not (aceptado and control_rechazado):
        return None

    return Finding(
        source="jwt", check_id="jwt-alg-none-aceptado",
        title="El servidor acepta un JWT con alg:none",
        description=(
            f"Se envió a {url} un token con la cabecera alg puesta a «none», sin "
            f"firma y con el rol reescrito a admin. El servidor respondió "
            f"{falsa.status_code}. El mismo endpoint rechaza con "
            f"{control.status_code} un token de firma inválida, así que sí "
            "comprueba algo — pero no la firma del token sin firmar. Cualquiera "
            "puede suplantar a cualquier usuario."
        ),
        remediation=(
            "Fija una lista de algoritmos permitidos en el verificador y rechaza "
            "«none» explícitamente. Verifica también iss, aud y exp."
        ),
        target=url, severity=Severity.CRITICAL, confidence=Confidence.CERTAIN,
        cwe=["CWE-347"], owasp=["A02:2021"],
        evidence=[Evidence(
            kind=EvidenceKind.HTTP,
            request=f"GET {url}\r\n{cabecera}: {prefijo}{forjado}\r\n\r\n",
            response=f"HTTP/1.1 {falsa.status_code}\r\n\r\n{falsa.text[:600]}",
            meta={"token_forjado": forjado, "control_firma_invalida": control.status_code},
        )],
    )
