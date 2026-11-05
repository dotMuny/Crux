"""Control de acceso: compara lo que ve cada rol.

El problema de fondo es que nadie le dice a la herramienta cuál es la política
de acceso prevista, así que «esta sesión no debería ver esto» no se puede
deducir en general. Lo que sí se puede afirmar con rigor son tres cosas, y el
módulo se limita a ellas:

1. **Falta autenticación**: una sesión anónima recibe lo mismo que una
   autenticada. Si la ruta está detrás de un formulario de acceso, ese acceso
   no sirve de nada.
2. **Falta autorización**: dos roles distintos reciben respuestas equivalentes
   en una ruta cuyo nombre declara privilegio (`/admin`, `/export`, `/manage`).
   El propio desarrollador llamó «admin» a la ruta: ésa es la política, escrita
   por él.
3. **IDOR**: una sesión obtiene con éxito un recurso cuyo identificador
   pertenece a otra, descubierto en el listado de la otra.

Fuera de esos tres casos el módulo calla. Un hallazgo de control de acceso que
resulta ser el comportamiento previsto quema la confianza en todo el informe.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any, Iterable, Sequence
from urllib.parse import urlsplit, urlunsplit

import httpx

from ..core.findings import Evidence, EvidenceKind, Finding
from ..core.policy import Policy
from ..core.scope import Scope
from ..core.severity import Confidence, Severity
from .auth import Sesion

# Rutas cuyo propio nombre declara que exigen privilegio. No es adivinación:
# es leer la intención que el desarrollador dejó escrita en la URL.
RUTA_PRIVILEGIADA = re.compile(
    r"/(admin|administra|manage|gestion|backoffice|internal|interno|export|"
    r"usuarios|users|settings|config|audit|billing|facturacion)(/|$|\?)", re.I
)

# Segmentos que parecen identificadores de recurso.
ID_EN_RUTA = re.compile(r"/(\d{1,12})(/|$)")

# Por encima de esto dos respuestas se consideran la misma. No se usa 1.0
# porque casi toda aplicación mete el nombre de usuario o un token en la página.
UMBRAL_IGUALDAD = 0.92

# Se recortan antes de comparar: cambian entre sesiones sin que cambie el
# control de acceso, y harían fallar la comparación por los motivos erróneos.
# El patrón tiene que llevarse el VALOR, no sólo el nombre del campo. Borrar
# `csrf_token` y dejar `value="aaaa1111"` hacía que la similitud entre dos
# respuestas cayera al 0,80 por culpa de un token que cambia siempre, y el
# módulo no habría detectado nada en ninguna aplicación con protección CSRF
# —es decir, en casi ninguna—.
VOLATIL = re.compile(
    r"""(?:
        (?:csrf|xsrf|authenticity_token|_token|nonce|state)[^>]{0,200}  # el campo entero
      | \b[0-9a-f]{16,}\b                                              # hashes e identificadores
      | \b[A-Za-z0-9+/]{40,}={0,2}\b                                   # cadenas base64 largas
      | \d{2}:\d{2}:\d{2}                                             # horas
      | \d{4}-\d{2}-\d{2}T[\d:.]+                                     # marcas ISO
    )""",
    re.I | re.X,
)


@dataclass(slots=True)
class Respuesta:
    estado: int
    texto: str
    longitud: int
    sesion: str

    @property
    def correcta(self) -> bool:
        """Una respuesta que entrega contenido, no una negativa ni un desvío."""
        return 200 <= self.estado < 300 and self.longitud > 0


@dataclass(slots=True)
class Comparacion:
    url: str
    respuestas: dict[str, Respuesta] = field(default_factory=dict)


def normalizar(texto: str) -> str:
    return VOLATIL.sub("", texto)[:20000]


def equivalentes(a: Respuesta, b: Respuesta) -> float:
    """Cuánto se parecen dos respuestas, de 0 a 1."""
    if a.estado != b.estado:
        return 0.0
    return SequenceMatcher(None, normalizar(a.texto), normalizar(b.texto)).ratio()


class ComparadorDeRoles:
    def __init__(self, scope: Scope, policy: Policy, sesiones: Sequence[Sesion]) -> None:
        self.scope = scope
        self.policy = policy
        # El orden importa: se asume que viene de menos a más privilegio, con
        # la anónima la primera. Se usa para decidir quién no debería ver qué.
        self.sesiones = list(sesiones)

    def _cliente(self, sesion: Sesion) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            trust_env=False, follow_redirects=False, verify=False,
            timeout=httpx.Timeout(self.policy.request_timeout),
            headers={"User-Agent": "crux/0.1 (authorized internal audit)",
                     **sesion.cabeceras},
            cookies=sesion.cookies,
        )

    async def comparar(self, urls: Sequence[str]) -> list[Comparacion]:
        urls = [u for u in urls if self.scope.allows_url(u)]
        comparaciones = [Comparacion(url=u) for u in urls]
        for sesion in self.sesiones:
            async with self._cliente(sesion) as cliente:
                semaforo = asyncio.Semaphore(self.policy.concurrency)

                async def pedir(comparacion: Comparacion) -> None:
                    async with semaforo:
                        try:
                            r = await cliente.get(comparacion.url)
                        except httpx.HTTPError:
                            return
                        comparacion.respuestas[sesion.nombre] = Respuesta(
                            estado=r.status_code, texto=r.text,
                            longitud=len(r.content), sesion=sesion.nombre,
                        )

                await asyncio.gather(*(pedir(c) for c in comparaciones))
        return comparaciones

    # -- interpretación ------------------------------------------------------
    def evaluar(self, comparaciones: Iterable[Comparacion],
                publicas: Iterable[str] = ()) -> list[Finding]:
        """Interpreta la matriz de respuestas.

        `publicas` son las URLs a las que el crawler anónimo llegó siguiendo
        enlaces. Si la propia aplicación las publica, que respondan igual a
        todo el mundo suele ser su comportamiento previsto: marcarlas llenaría
        el informe de portadas y páginas de ayuda.

        La excepción, y es importante: **una ruta con identificador de recurso
        no es pública por diseño aunque esté enlazada**. Que la portada enlace
        /invoice/1001 no convierte esa factura en información pública; al
        contrario, enlazarla es parte del fallo. La regla anterior, más simple,
        hacía desaparecer precisamente el hallazgo que importaba.
        """
        publicas = {
            u.rstrip("/") for u in publicas
            if not ID_EN_RUTA.search(urlsplit(u).path)
        }
        hallazgos: list[Finding] = []
        anonima = next((s for s in self.sesiones if not s.autenticada), None)
        autenticadas = [s for s in self.sesiones if s.autenticada]

        for comparacion in comparaciones:
            # 1. Falta autenticación, sólo en rutas que la aplicación no
            #    publica por su cuenta.
            if anonima and autenticadas and comparacion.url.rstrip("/") not in publicas:
                ra = comparacion.respuestas.get(anonima.nombre)
                for sesion in autenticadas:
                    rs = comparacion.respuestas.get(sesion.nombre)
                    if not (ra and rs and ra.correcta and rs.correcta):
                        continue
                    if equivalentes(ra, rs) < UMBRAL_IGUALDAD:
                        continue
                    hallazgos.append(self._hallazgo_sin_auth(comparacion, ra, rs, sesion))
                    break

            # 2. Falta autorización entre roles, solo en rutas que declaran
            #    privilegio en su propio nombre.
            if len(autenticadas) >= 2 and RUTA_PRIVILEGIADA.search(comparacion.url):
                menor, mayor = autenticadas[0], autenticadas[-1]
                rm = comparacion.respuestas.get(menor.nombre)
                rM = comparacion.respuestas.get(mayor.nombre)
                if rm and rM and rm.correcta and rM.correcta and \
                        equivalentes(rm, rM) >= UMBRAL_IGUALDAD:
                    hallazgos.append(self._hallazgo_sin_authz(comparacion, rm, rM, menor, mayor))
        return hallazgos

    def _hallazgo_sin_auth(self, comparacion, ra, rs, sesion) -> Finding:
        return Finding(
            source="authz", check_id="acceso-sin-autenticar",
            title="La ruta responde igual sin iniciar sesión",
            description=(
                f"Una petición anónima a {comparacion.url} devolvió {ra.estado} con "
                f"un contenido equivalente al que recibe la sesión «{sesion.nombre}» "
                f"({rs.estado}). La autenticación no está protegiendo esta ruta: lo "
                "que se oculta es el enlace, no el recurso."
            ),
            remediation=(
                "Comprueba la sesión en el servidor antes de responder. Ocultar el "
                "enlace en la interfaz no es un control de acceso."
            ),
            target=comparacion.url, severity=Severity.HIGH, confidence=Confidence.FIRM,
            cwe=["CWE-306"], owasp=["A01:2021"],
            evidence=[Evidence(
                kind=EvidenceKind.HTTP,
                request=f"GET {comparacion.url}\r\n(sin cookies de sesión)\r\n\r\n",
                response=f"HTTP/1.1 {ra.estado}\r\n\r\n{ra.texto[:700]}",
                meta={"estado_autenticado": rs.estado, "similitud": round(equivalentes(ra, rs), 3)},
            )],
        )

    def _hallazgo_sin_authz(self, comparacion, rm, rM, menor, mayor) -> Finding:
        return Finding(
            source="authz", check_id="autorizacion-rota-entre-roles",
            title=f"El rol «{menor.rol or menor.nombre}» accede a una ruta de administración",
            description=(
                f"La ruta {comparacion.url} declara privilegio en su propio nombre, "
                f"pero la sesión «{menor.nombre}» recibió {rm.estado} con contenido "
                f"equivalente al de «{mayor.nombre}». El servidor no comprueba el rol."
            ),
            remediation=(
                "Comprueba el rol en el servidor, en el propio manejador de la ruta. "
                "No te fíes del rol que venga del cliente —cookie, token o parámetro—."
            ),
            target=comparacion.url, severity=Severity.HIGH, confidence=Confidence.FIRM,
            cwe=["CWE-285"], owasp=["A01:2021"],
            evidence=[Evidence(
                kind=EvidenceKind.HTTP,
                request=f"GET {comparacion.url}\r\nCookie: (sesión de {menor.nombre})\r\n\r\n",
                response=f"HTTP/1.1 {rm.estado}\r\n\r\n{rm.texto[:700]}",
                meta={"rol": menor.rol, "similitud": round(equivalentes(rm, rM), 3)},
            )],
        )

    # -- IDOR ----------------------------------------------------------------
    async def buscar_idor(self, urls: Sequence[str],
                          anonimamente_legibles: Iterable[str] = ()) -> list[Finding]:
        """Pide con una sesión los recursos que vio la otra.

        Sólo se consideran identificadores que **otra sesión mostró como
        suyos**. Probar números al azar generaría ruido y además tocaría datos
        que nadie ha dicho que existan.

        Lo que ya se lee sin sesión alguna no es un IDOR: es falta de
        autenticación, que es más grave y la subsume. Reportar ambas cosas
        sobre la misma URL duplica la causa raíz en la cola de triaje.
        """
        anonimas = {u.rstrip("/") for u in anonimamente_legibles}
        autenticadas = [s for s in self.sesiones if s.autenticada]
        if len(autenticadas) < 2:
            return []

        propios: dict[str, set[str]] = {}
        for sesion in autenticadas:
            async with self._cliente(sesion) as cliente:
                vistos: set[str] = set()
                for url in urls:
                    if not self.scope.allows_url(url):
                        continue
                    try:
                        r = await cliente.get(url)
                    except httpx.HTTPError:
                        continue
                    if r.status_code == 200:
                        # Solo los identificadores que la propia sesión enlaza:
                        # son los que esa sesión declara como suyos.
                        enlaces = " ".join(re.findall(r'href="([^"]+)"', r.text))
                        vistos.update(m[0] for m in ID_EN_RUTA.findall(enlaces))
                propios[sesion.nombre] = vistos

        hallazgos: list[Finding] = []
        plantillas = {
            urlunsplit((p.scheme, p.netloc, ID_EN_RUTA.sub("/{id}/", p.path), "", ""))
            for p in map(urlsplit, urls) if ID_EN_RUTA.search(p.path)
        }

        for atacante in autenticadas:
            ajenos: set[str] = set()
            for otra, ids in propios.items():
                if otra != atacante.nombre:
                    ajenos |= ids - propios.get(atacante.nombre, set())
            if not ajenos:
                continue
            async with self._cliente(atacante) as cliente:
                for plantilla in plantillas:
                    for identificador in sorted(ajenos)[:5]:
                        url = plantilla.replace("/{id}/", f"/{identificador}").rstrip("/")
                        if not self.scope.allows_url(url) or url in anonimas:
                            continue
                        try:
                            r = await cliente.get(url)
                        except httpx.HTTPError:
                            continue
                        if r.status_code != 200 or not r.content:
                            continue
                        hallazgos.append(Finding(
                            source="authz", check_id="idor",
                            title="Recurso de otro usuario accesible cambiando el identificador",
                            description=(
                                f"La sesión «{atacante.nombre}» obtuvo {url} con un 200. "
                                f"Ese identificador apareció en el listado de otra sesión, "
                                "no en la suya: el servidor no comprueba de quién es el recurso."
                            ),
                            remediation=(
                                "Comprueba la propiedad del recurso en el servidor antes de "
                                "devolverlo. Ocultar el enlace no basta."
                            ),
                            target=url, severity=Severity.HIGH, confidence=Confidence.FIRM,
                            cwe=["CWE-639"], owasp=["A01:2021"],
                            evidence=[Evidence(
                                kind=EvidenceKind.HTTP,
                                request=f"GET {url}\r\nCookie: (sesión de {atacante.nombre})\r\n\r\n",
                                response=f"HTTP/1.1 {r.status_code}\r\n\r\n{r.text[:600]}",
                                meta={"identificador_ajeno": identificador},
                            )],
                            fingerprint_extra=atacante.nombre,
                        ))
                        break
        return hallazgos


# Nombres de cookie que identifican una sesión. Comparar todas las cookies daría
# falsos positivos con las de idioma o consentimiento, que no deben cambiar.
COOKIE_DE_SESION = re.compile(r"(sess|sid$|^sid|auth|token|jwt|login)", re.I)


def comprobar_fijacion_de_sesion(sesion: Sesion, objetivo: str) -> list[Finding]:
    """¿Se renovó el identificador de sesión al autenticarse?

    Si el identificador que el navegador llevaba antes de entrar sigue siendo
    válido después, quien lo haya fijado —con un enlace, con una cookie
    inyectada desde un subdominio— entra en la cuenta de la víctima sin
    conocer su contraseña.

    Sólo se miran las cookies cuyo nombre indica sesión: exigir que cambien
    todas marcaría también las de idioma o consentimiento, que no deben cambiar.
    """
    if not sesion.autenticada or not sesion.cookies_previas:
        return []

    sin_renovar = [
        nombre for nombre, valor in sesion.cookies_previas.items()
        if COOKIE_DE_SESION.search(nombre)
        and valor
        and sesion.cookies.get(nombre) == valor
    ]
    if not sin_renovar:
        return []

    return [Finding(
        source="authz",
        check_id="fijacion-de-sesion",
        title=f"El identificador de sesión no se renueva al iniciar sesión",
        description=(
            f"Las cookies {', '.join(sin_renovar)} valían lo mismo antes y después "
            f"de autenticarse como «{sesion.nombre}». Quien consiga fijar ese "
            "identificador en el navegador de la víctima —un enlace preparado, una "
            "cookie escrita desde un subdominio— queda dentro de su cuenta en "
            "cuanto ella se autentique, sin saber su contraseña."
        ),
        remediation=(
            "Genera un identificador nuevo al autenticar y descarta el anterior. "
            "En la mayoría de marcos es una sola llamada: regenerate / cycle_key / "
            "session.regenerate_id."
        ),
        target=objetivo,
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        cwe=["CWE-384"],
        owasp=["A07:2021"],
        evidence=[Evidence(
            kind=EvidenceKind.RAW,
            snippet="\n".join(
                f"{n}: antes={sesion.cookies_previas[n][:24]}… "
                f"después={sesion.cookies.get(n, '')[:24]}…"
                for n in sin_renovar
            ),
        )],
        fingerprint_extra=",".join(sorted(sin_renovar)),
    )]
