"""Probador HTTP y huella tecnológica. Módulo propio, no un envoltorio.

Sustituye al `httpx` de ProjectDiscovery, que en esta máquina no está instalado
(`/usr/bin/httpx` es el CLI de la librería Python, otra cosa). Escribirlo nosotros
da dos cosas que un binario externo no daba: control total del egress y una huella
tecnológica que alimenta directamente nuestro modelo de datos.

Garantías de red de este módulo:
- `trust_env=False`: httpx **no** lee `HTTP_PROXY`/`HTTPS_PROXY` del entorno.
- Cada petición y **cada redirect** se valida contra el alcance congelado. Los
  redirects se siguen a mano precisamente para poder cortar en el salto en que
  una app interna intenta llevarnos fuera.
- `verify=False`: los certificados autofirmados son la norma en una intranet. El
  estado real del TLS lo reporta el módulo `tls`, no se silencia.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass, field
from typing import Iterable, Sequence

import httpx

from ..core.policy import Policy
from ..core.scope import Scope, ScopeViolation

# Origen inexistente para el sondeo CORS: si el servidor lo refleja en
# Access-Control-Allow-Origin, acepta cualquier origen.
CORS_PROBE_ORIGIN = "https://crux-cors-probe.invalid"

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_GENERATOR = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)

# Cabeceras de seguridad cuya ausencia evalúa el módulo de checks pasivos.
SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
)

# Firmas de tecnología. Tabla deliberadamente corta: solo señales inequívocas.
# (campo, patrón, tecnología)
_SIGNATURES: tuple[tuple[str, re.Pattern[str], str], ...] = (
    ("header:server", re.compile(r"nginx/?([\d.]+)?", re.I), "nginx"),
    ("header:server", re.compile(r"apache/?([\d.]+)?", re.I), "Apache httpd"),
    ("header:server", re.compile(r"microsoft-iis/?([\d.]+)?", re.I), "IIS"),
    ("header:server", re.compile(r"gunicorn/?([\d.]+)?", re.I), "Gunicorn"),
    ("header:server", re.compile(r"werkzeug/?([\d.]+)?", re.I), "Werkzeug"),
    ("header:server", re.compile(r"kestrel", re.I), "ASP.NET Core Kestrel"),
    ("header:x-powered-by", re.compile(r"php/?([\d.]+)?", re.I), "PHP"),
    ("header:x-powered-by", re.compile(r"express", re.I), "Express"),
    ("header:x-powered-by", re.compile(r"asp\.net", re.I), "ASP.NET"),
    ("header:x-aspnet-version", re.compile(r"(.+)"), "ASP.NET"),
    ("header:x-drupal-cache", re.compile(r"."), "Drupal"),
    ("header:x-generator", re.compile(r"drupal", re.I), "Drupal"),
    ("cookie", re.compile(r"^jsessionid$", re.I), "Java (servlet)"),
    ("cookie", re.compile(r"^phpsessid$", re.I), "PHP"),
    ("cookie", re.compile(r"^asp\.net_sessionid$", re.I), "ASP.NET"),
    # `csrftoken` es distintivo de Django. `sessionid` a secas NO: lo usan
    # demasiados frameworks y marcos propios, y producía falsos positivos.
    ("cookie", re.compile(r"^csrftoken$", re.I), "Django"),
    ("cookie", re.compile(r"^laravel_session$", re.I), "Laravel"),
    ("cookie", re.compile(r"^connect\.sid$", re.I), "Express"),
    ("body", re.compile(r"<[^>]+\sng-version=", re.I), "Angular"),
    ("body", re.compile(r"__NEXT_DATA__", re.I), "Next.js"),
    ("body", re.compile(r"__nuxt", re.I), "Nuxt"),
    ("body", re.compile(r"wp-content/|wp-includes/", re.I), "WordPress"),
    ("body", re.compile(r"/_framework/blazor", re.I), "Blazor"),
    ("body", re.compile(r'name="__VIEWSTATE"', re.I), "ASP.NET WebForms"),
    ("body", re.compile(r"Set up your Spring Boot|Whitelabel Error Page", re.I), "Spring Boot"),
    ("generator", re.compile(r"(.+)"), "generator"),
)


@dataclass(slots=True)
class ProbeResult:
    """Lo que sabemos de una URL tras tocarla una vez."""

    url: str
    final_url: str
    status: int
    reason: str = ""
    http_version: str = ""
    title: str = ""
    server: str = ""
    content_type: str = ""
    content_length: int = 0
    headers: dict[str, str] = field(default_factory=dict)
    cookies: list[dict[str, object]] = field(default_factory=list)
    redirect_chain: list[str] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    body_hash: str = ""
    body_preview: str = ""
    tls: dict[str, object] = field(default_factory=dict)
    # Resultado del sondeo CORS: se hace aquí, con la red, para que el módulo
    # de checks pasivos pueda ser una función pura sobre este objeto.
    cors: dict[str, object] = field(default_factory=dict)
    error: str | None = None
    # Snapshot crudo para la evidencia de los hallazgos que se deriven de aquí.
    raw_request: str = ""
    raw_response: str = ""

    @property
    def alive(self) -> bool:
        return self.error is None and self.status > 0

    @property
    def missing_security_headers(self) -> list[str]:
        present = {k.lower() for k in self.headers}
        return [h for h in SECURITY_HEADERS if h not in present]


class Prober:
    """Prueba URLs respetando el alcance y el perfil."""

    def __init__(self, scope: Scope, policy: Policy, *, max_redirects: int = 5,
                 sesion=None) -> None:
        self.scope = scope
        self.policy = policy
        self.max_redirects = max_redirects
        # Con sesión, las sondas ven lo mismo que un usuario dentro: la portada
        # de verdad, las cookies que pone tras el login, las cabeceras de las
        # páginas privadas. Sin ella, las comprobaciones pasivas analizaban la
        # redirección al formulario de acceso y nada más.
        self.sesion = sesion
        self._semaphore = asyncio.Semaphore(policy.concurrency)

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            # Sin herencia de proxies del entorno: el egress no se negocia.
            trust_env=False,
            # Los redirects se siguen a mano para validar el alcance en cada salto.
            follow_redirects=False,
            # Intranet: los certificados autofirmados son lo normal. El estado
            # real del TLS lo reporta el módulo `tls`, no se oculta.
            verify=False,
            timeout=httpx.Timeout(self.policy.request_timeout),
            limits=httpx.Limits(max_connections=self.policy.concurrency),
            # Las cabeceras HTTP deben ser ASCII: el User-Agent va sin acentos.
            headers={"User-Agent": "crux/0.1 (authorized internal audit)",
                     **(self.sesion.cabeceras if self.sesion is not None else {})},
            cookies=self.sesion.cookies if self.sesion is not None else None,
        )

    async def probe_many(self, urls: Sequence[str]) -> list[ProbeResult]:
        async with self._client() as client:
            tasks = [self._probe_guarded(client, url) for url in urls]
            return list(await asyncio.gather(*tasks))

    async def _probe_guarded(self, client: httpx.AsyncClient, url: str) -> ProbeResult:
        async with self._semaphore:
            try:
                return await self.probe(client, url)
            except ScopeViolation as exc:
                return ProbeResult(url=url, final_url=url, status=0, error=str(exc))
            except httpx.HTTPError as exc:
                return ProbeResult(
                    url=url, final_url=url, status=0, error=f"{type(exc).__name__}: {exc}"
                )

    async def probe(self, client: httpx.AsyncClient, url: str) -> ProbeResult:
        """Una URL: petición, redirects validados, y huella de lo que responde."""
        if not self.scope.allows_url(url):
            raise ScopeViolation(f"{url} está fuera del alcance")

        chain: list[str] = []
        current = url
        response: httpx.Response | None = None

        for _ in range(self.max_redirects + 1):
            response = await client.get(current)
            location = response.headers.get("location")
            if response.status_code not in (301, 302, 303, 307, 308) or not location:
                break
            target = str(httpx.URL(current).join(location))
            # Aquí está el punto importante: un redirect hacia fuera se corta,
            # y el hallazgo queda registrado en el propio resultado.
            if not self.scope.allows_url(target):
                chain.append(target)
                result = self._build(url, current, response, chain)
                result.error = (
                    f"redirect hacia {target}, fuera del alcance: no se sigue"
                )
                return result
            chain.append(target)
            current = target

        assert response is not None
        result = self._build(url, current, response, chain)
        if self.policy.allow_active_probes:
            result.cors = await self._probe_cors(client, current)
        return result

    async def _probe_cors(self, client: httpx.AsyncClient, url: str) -> dict[str, object]:
        """Una petición con un Origin inexistente. Revela la política CORS real.

        Se considera sondeo activo porque añade una petición, pero no modifica
        nada: en perfil pasivo no se ejecuta.
        """
        try:
            response = await client.get(url, headers={"Origin": CORS_PROBE_ORIGIN})
        except httpx.HTTPError as exc:
            return {"error": str(exc)}
        allow_origin = response.headers.get("access-control-allow-origin", "")
        return {
            "probe_origin": CORS_PROBE_ORIGIN,
            "allow_origin": allow_origin,
            "allow_credentials":
                response.headers.get("access-control-allow-credentials", "").lower() == "true",
            "reflects_origin": allow_origin.strip() == CORS_PROBE_ORIGIN,
            "wildcard": allow_origin.strip() == "*",
            "vary_origin": "origin" in response.headers.get("vary", "").lower(),
            "raw_response": _raw_response(response, ""),
        }

    def _build(
        self,
        url: str,
        final_url: str,
        response: httpx.Response,
        chain: list[str],
    ) -> ProbeResult:
        body = response.text if _is_textual(response) else ""
        headers = {k.lower(): v for k, v in response.headers.items()}
        result = ProbeResult(
            url=url,
            final_url=final_url,
            status=response.status_code,
            reason=response.reason_phrase or "",
            http_version=response.http_version,
            title=_extract_title(body),
            server=headers.get("server", ""),
            content_type=headers.get("content-type", ""),
            content_length=len(response.content),
            headers=headers,
            cookies=_describe_cookies(response),
            redirect_chain=chain,
            body_hash=hashlib.sha256(response.content).hexdigest()[:16],
            body_preview=body[:2000],
            raw_request=_raw_request(response.request),
            raw_response=_raw_response(response, body),
        )
        result.technologies = detect_technologies(result)
        return result


def detect_technologies(result: ProbeResult) -> list[str]:
    """Huella tecnológica a partir de cabeceras, cookies y cuerpo."""
    found: list[str] = []
    cookie_names = [str(c.get("name", "")) for c in result.cookies]
    generator = _GENERATOR.search(result.body_preview)

    for field_name, pattern, tech in _SIGNATURES:
        haystacks: Iterable[str]
        if field_name.startswith("header:"):
            haystacks = [result.headers.get(field_name.split(":", 1)[1], "")]
        elif field_name == "cookie":
            haystacks = cookie_names
        elif field_name == "body":
            haystacks = [result.body_preview]
        elif field_name == "generator":
            haystacks = [generator.group(1)] if generator else []
        else:  # pragma: no cover - tabla cerrada
            haystacks = []

        for haystack in haystacks:
            if not haystack:
                continue
            match = pattern.search(haystack)
            if not match:
                continue
            label = tech
            if tech == "generator":
                label = match.group(1).strip()
            else:
                version = next((g for g in match.groups() if g), None)
                if version:
                    label = f"{tech} {version}"
            if label not in found:
                found.append(label)
            break
    return found


def _is_textual(response: httpx.Response) -> bool:
    ctype = response.headers.get("content-type", "")
    return any(t in ctype for t in ("text/", "json", "xml", "javascript", "html"))


def _extract_title(body: str) -> str:
    match = _TITLE.search(body)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:300]


def _describe_cookies(response: httpx.Response) -> list[dict[str, object]]:
    """Atributos de cada cookie, que es lo que audita el módulo `cookies`."""
    described: list[dict[str, object]] = []
    for raw in response.headers.get_list("set-cookie"):
        parts = [p.strip() for p in raw.split(";")]
        name, _, value = parts[0].partition("=")
        attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else True)
                 for p in parts[1:] if p}
        described.append(
            {
                "name": name.strip(),
                # El valor hace falta para analizar tokens; la longitud sola no
                # permite ver si una cookie lleva un JWT dentro.
                "value": value,
                "value_length": len(value),
                "secure": "secure" in attrs,
                "httponly": "httponly" in attrs,
                "samesite": attrs.get("samesite", None),
                "path": attrs.get("path", "/"),
                "domain": attrs.get("domain", None),
                "expires": attrs.get("expires", None),
                "max_age": attrs.get("max-age", None),
            }
        )
    return described


def _raw_request(request: httpx.Request) -> str:
    lines = [f"{request.method} {request.url.raw_path.decode()} HTTP/1.1"]
    lines += [f"{k}: {v}" for k, v in request.headers.items()]
    return "\r\n".join(lines) + "\r\n\r\n"


def _raw_response(response: httpx.Response, body: str) -> str:
    lines = [f"HTTP/{response.http_version.split('/')[-1]} {response.status_code} "
             f"{response.reason_phrase}".strip()]
    lines += [f"{k}: {v}" for k, v in response.headers.items()]
    return "\r\n".join(lines) + "\r\n\r\n" + body[:8000]
