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

# Operaciones de API que suelen ser públicas a propósito. Solo se usan cuando
# no hay un segundo rol con el que distinguir lo público de lo privado.
PUBLICA_POR_DISENO = re.compile(
    r"/(health[a-z]*|status|ready|live|ping|version|metrics|login|logout|auth|"
    r"token|oauth2?|openapi|swagger|api-docs|csrf|public|i18n|locales?|config|"
    r"settings/public)(/|$|\.)", re.I)

# Un fichero de un directorio oculto —`/.git/config`, `/.svn/entries`— casa con
# el patrón de ruta privilegiada por la palabra «config», y que responda igual a
# todo el mundo no es un fallo de autorización: es un fichero que no debería
# estar servido, y para eso hay un hallazgo propio.
DIRECTORIO_OCULTO = re.compile(r"/\.[^/]+/")

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


def aviso_de_operaciones_omitidas(todas: Sequence["Operacion"],
                                  comparadas: Sequence["Operacion"],
                                  policy: Policy) -> list[Finding]:
    """Dice qué operaciones de la API no se compararon entre roles, y por qué.

    Un informe que no encuentra fallos de autorización en las operaciones de
    escritura puede significar dos cosas muy distintas: que están bien, o que
    no se miraron. Sin decirlo, se lee como la primera.
    """
    omitidas = [o for o in todas if o not in comparadas]
    if not omitidas:
        return []
    metodos = sorted({o.metodo.upper() for o in omitidas})
    titulo = (f"{len(omitidas)} operaciones de la API no se compararon entre roles"
              if len(omitidas) != 1 else
              "Una operación de la API no se comparó entre roles")
    return [Finding(
        source="authz", check_id="autorizacion-no-comprobada",
        title=titulo,
        description=(
            f"Se dejaron fuera las de {', '.join(metodos)}. Comparar una operación es "
            "repetir la misma petición con cada sesión, y con un método que escribe eso "
            "significa crear o modificar algo una vez por sesión, en una aplicación en "
            f"uso. El perfil «{policy.profile}» no lo autoriza. DELETE no se compara con "
            "ningún perfil: la petición se repetiría también con la sesión con "
            "privilegio, y entonces el dato desaparece de verdad."),
        remediation=(
            "Para comprobar la autorización de las operaciones de escritura, repite el "
            "escaneo con el perfil agresivo en un entorno de preproducción, o pruébalas "
            "a mano con las dos sesiones."),
        target=omitidas[0].url, severity=Severity.INFO, confidence=Confidence.CERTAIN,
        tags=["cobertura", "api"],
        extra={"metodos": metodos, "operaciones": len(omitidas)},
    )]


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
class Operacion:
    """Una llamada concreta a la API: no basta la URL, hace falta el método.

    En una interfaz, una ruta es una página y compararla es pedirla. En una API
    la misma ruta son varias operaciones con permisos distintos: leer un pedido
    y borrarlo no se autorizan igual. Comparar solo con GET dejaba sin mirar
    justo las que cambian datos.
    """

    url: str
    metodo: str = "GET"
    cuerpo: str = ""
    tipo_contenido: str = ""


# Métodos que solo leen. El resto cambia estado, y repetir la misma petición
# con cada sesión significa cambiarlo una vez por sesión.
METODOS_DE_LECTURA = frozenset({"GET", "HEAD", "OPTIONS"})
# Los de escritura que se comparan cuando el perfil lo autoriza. DELETE no está
# y no es un olvido: la comparación repite la petición con la sesión con
# privilegio también, así que un DELETE que funcione destruye el dato que la
# auditoría tenía que dejar intacto.
METODOS_DE_ESCRITURA = ("POST", "PUT", "PATCH")


@dataclass(slots=True)
class Comparacion:
    url: str
    respuestas: dict[str, Respuesta] = field(default_factory=dict)
    metodo: str = "GET"

    @property
    def etiqueta(self) -> str:
        return f"{self.metodo} {self.url}" if self.metodo != "GET" else self.url


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

    def operaciones_comparables(self, operaciones: Sequence[Operacion]) -> list[Operacion]:
        """Las que se pueden repetir con cada sesión sin romper nada.

        Las de lectura, siempre. Las de escritura solo con el perfil que
        autoriza métodos destructivos, porque un `POST` a una API crea algo de
        verdad —una vez por cada sesión que se compara—. Sin ese permiso se
        quedan fuera y el escaneo lo dice, en vez de dar por comprobado lo que
        no se miró.
        """
        permitidos = set(METODOS_DE_LECTURA)
        if self.policy.allow_destructive_methods:
            permitidos.update(METODOS_DE_ESCRITURA)
        return [o for o in operaciones
                if o.metodo.upper() in permitidos and self.scope.allows_url(o.url)]

    async def comparar_operaciones(
        self, operaciones: Sequence[Operacion]
    ) -> list[Comparacion]:
        """La misma matriz de respuestas, pero por operación en vez de por URL."""
        comparables = self.operaciones_comparables(operaciones)
        comparaciones = [Comparacion(url=o.url, metodo=o.metodo.upper())
                         for o in comparables]
        for sesion in self.sesiones:
            async with self._cliente(sesion) as cliente:
                semaforo = asyncio.Semaphore(self.policy.concurrency)

                async def pedir(operacion: Operacion, comparacion: Comparacion) -> None:
                    async with semaforo:
                        cabeceras = ({"Content-Type": operacion.tipo_contenido}
                                     if operacion.tipo_contenido and operacion.cuerpo
                                     else None)
                        try:
                            r = await cliente.request(
                                comparacion.metodo, operacion.url,
                                content=operacion.cuerpo.encode() or None,
                                headers=cabeceras,
                            )
                        except httpx.HTTPError:
                            return
                        comparacion.respuestas[sesion.nombre] = Respuesta(
                            estado=r.status_code, texto=r.text,
                            longitud=len(r.content), sesion=sesion.nombre,
                        )

                await asyncio.gather(*(
                    pedir(o, c) for o, c in zip(comparables, comparaciones)
                ))
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
            if (len(autenticadas) >= 2 and RUTA_PRIVILEGIADA.search(comparacion.url)
                    and not DIRECTORIO_OCULTO.search(comparacion.url)):
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
                f"Una petición anónima a {comparacion.etiqueta} devolvió {ra.estado} con "
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
                request=(f"{comparacion.metodo} {comparacion.url}\r\n"
                         "(sin cookies de sesión)\r\n\r\n"),
                response=f"HTTP/1.1 {ra.estado}\r\n\r\n{ra.texto[:700]}",
                meta={"estado_autenticado": rs.estado, "similitud": round(equivalentes(ra, rs), 3)},
            )],
        )

    def _hallazgo_sin_authz(self, comparacion, rm, rM, menor, mayor) -> Finding:
        return Finding(
            source="authz", check_id="autorizacion-rota-entre-roles",
            title=f"El rol «{menor.rol or menor.nombre}» accede a una ruta de administración",
            description=(
                f"La operación {comparacion.etiqueta} declara privilegio en el propio "
                "nombre de la ruta, "
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
                request=(f"{comparacion.metodo} {comparacion.url}\r\n"
                         f"Cookie: (sesión de {menor.nombre})\r\n\r\n"),
                response=f"HTTP/1.1 {rm.estado}\r\n\r\n{rm.texto[:700]}",
                meta={"rol": menor.rol, "similitud": round(equivalentes(rm, rM), 3)},
            )],
        )

    def evaluar_api(self, comparaciones: Iterable[Comparacion]) -> list[Finding]:
        """Operaciones de la API que responden lo mismo sin autenticarse.

        En una interfaz, que una ruta responda igual a todo el mundo suele ser
        su portada. En una API no hay portadas, pero sí hay operaciones
        públicas a propósito: la comprobación de vida, la versión, el propio
        acceso. Marcarlas todas llenaría el informe de ruido.

        El discriminante es mirar si la operación **devuelve algo distinto a
        cada usuario**. Si a dos roles les contesta cosas distintas, está
        sirviendo datos de alguien; que el anónimo reciba lo mismo que uno de
        ellos significa que recibió la vista de esa persona. Si a los dos les
        contesta lo mismo, es información pública y se calla.

        Con un solo rol no hay con qué comparar: entonces se descartan por
        nombre las que suelen ser públicas y el resto se marca como tentativo,
        que es exactamente lo que se sabe.
        """
        import itertools

        anonima = next((s for s in self.sesiones if not s.autenticada), None)
        autenticadas = [s for s in self.sesiones if s.autenticada]
        if anonima is None or not autenticadas:
            return []

        hallazgos: list[Finding] = []
        for comparacion in comparaciones:
            # Las rutas con identificador de recurso las lleva `evaluar`, con la
            # regla de siempre: una factura no es pública porque esté enlazada.
            if ID_EN_RUTA.search(urlsplit(comparacion.url).path):
                continue
            ra = comparacion.respuestas.get(anonima.nombre)
            if ra is None or not ra.correcta:
                continue
            iguales = [s for s in autenticadas
                       if (r := comparacion.respuestas.get(s.nombre)) is not None
                       and r.correcta and equivalentes(ra, r) >= UMBRAL_IGUALDAD]
            if not iguales:
                continue

            personalizada = any(
                (r1 := comparacion.respuestas.get(a.nombre)) is not None
                and (r2 := comparacion.respuestas.get(b.nombre)) is not None
                and r1.correcta and r2.correcta
                and equivalentes(r1, r2) < UMBRAL_IGUALDAD
                for a, b in itertools.combinations(autenticadas, 2)
            )
            if personalizada:
                confianza = Confidence.FIRM
            elif len(autenticadas) >= 2:
                # Dos usuarios distintos reciben lo mismo: es información
                # pública, no la vista de nadie.
                continue
            elif PUBLICA_POR_DISENO.search(urlsplit(comparacion.url).path):
                continue
            else:
                confianza = Confidence.TENTATIVE
            hallazgos.append(self._hallazgo_api_sin_auth(
                comparacion, ra, iguales[0], confianza, personalizada))
        return hallazgos

    def _hallazgo_api_sin_auth(self, comparacion, ra, sesion, confianza,
                               personalizada) -> Finding:
        porque = (
            "La misma operación contesta cosas distintas a cada usuario, así que lo "
            f"que recibió el anónimo es la vista de «{sesion.nombre}»."
            if personalizada else
            "No había un segundo rol con el que comprobar si la respuesta es la misma "
            "para todos, así que podría ser información pública a propósito: "
            "verifícalo a mano."
        )
        return Finding(
            source="authz", check_id="api-sin-autenticar",
            title=f"La API responde a {comparacion.metodo} sin autenticarse",
            description=(
                f"{comparacion.etiqueta} devolvió {ra.estado} a una petición sin "
                f"sesión, con contenido equivalente al que recibe «{sesion.nombre}». "
                + porque),
            remediation=(
                "Comprueba la sesión en el servidor para esta operación. En una API no "
                "hay interfaz que oculte el enlace: la ruta es el único control."),
            target=comparacion.url, severity=Severity.HIGH, confidence=confianza,
            cwe=["CWE-306"], owasp=["A01:2021", "API1:2023"],
            evidence=[Evidence(
                kind=EvidenceKind.HTTP,
                request=(f"{comparacion.metodo} {comparacion.url}\r\n"
                         "(sin cookies de sesión)\r\n\r\n"),
                response=f"HTTP/1.1 {ra.estado}\r\n\r\n{ra.texto[:700]}",
                meta={"personalizada": personalizada,
                      "similitud": round(equivalentes(
                          ra, comparacion.respuestas[sesion.nombre]), 3)},
            )],
            fingerprint_extra=comparacion.metodo,
        )

    def evaluar_metodos(self, comparaciones: Iterable[Comparacion]) -> list[Finding]:
        """La ruta que se protege para leer y no para escribir.

        Es el cuarto caso que se puede afirmar sin conocer la política de
        acceso, y lo escribió la propia aplicación: si a esta sesión le niega
        el `GET` de la ruta, es que sabe que no tiene por qué verla. Que
        entonces le acepte un `POST` o un `PUT` en la misma ruta no es una
        política más permisiva, es un control que se aplicó en un sitio y se
        olvidó en el otro —el caso típico: el decorador puesto en el manejador
        de lectura y no en el de escritura—.

        La dirección importa y es la mitad del rigor. Lo contrario —leer
        permitido, escribir denegado— es el comportamiento correcto y
        aparecería en cada API del mundo.
        """
        hallazgos: list[Finding] = []
        por_ruta: dict[tuple[str, str], dict[str, Respuesta]] = {}
        for comparacion in comparaciones:
            partes = urlsplit(comparacion.url)
            ruta = urlunsplit((partes.scheme, partes.netloc, partes.path, "", ""))
            for nombre, respuesta in comparacion.respuestas.items():
                por_ruta.setdefault((nombre, ruta), {})[comparacion.metodo] = respuesta

        for (nombre, ruta), respuestas in sorted(por_ruta.items()):
            negadas = [m for m in METODOS_DE_LECTURA
                       if (r := respuestas.get(m)) is not None and r.estado in (401, 403)]
            if not negadas:
                continue
            for metodo in METODOS_DE_ESCRITURA:
                respuesta = respuestas.get(metodo)
                if respuesta is None or not respuesta.correcta:
                    continue
                hallazgos.append(self._hallazgo_metodo_sin_control(
                    nombre, ruta, negadas[0], metodo, respuestas[negadas[0]], respuesta))
                break
        return hallazgos

    def _hallazgo_metodo_sin_control(self, nombre, ruta, lectura, escritura,
                                     r_lectura, r_escritura) -> Finding:
        return Finding(
            source="authz", check_id="control-de-acceso-por-metodo",
            title=f"La ruta se protege para {lectura} pero acepta {escritura}",
            description=(
                f"Con la sesión «{nombre}», {lectura} {ruta} devolvió "
                f"{r_lectura.estado}: la aplicación sabe que esta sesión no tiene por "
                f"qué acceder a esa ruta. Pero {escritura} en la misma ruta devolvió "
                f"{r_escritura.estado} y entregó contenido. El control existe y está "
                "puesto en un método y no en el otro, así que se puede escribir donde "
                "no se puede ni leer."),
            remediation=(
                "Comprueba el permiso donde esté la regla para todos los métodos de la "
                "ruta, no manejador por manejador. Si el control es un decorador, "
                "revisa que esté en todos."),
            target=ruta, severity=Severity.HIGH, confidence=Confidence.FIRM,
            cwe=["CWE-285"], owasp=["A01:2021", "API5:2023"],
            evidence=[Evidence(
                kind=EvidenceKind.HTTP,
                request=f"{escritura} {ruta}\r\nCookie: (sesión de {nombre})\r\n\r\n",
                response=f"HTTP/1.1 {r_escritura.estado}\r\n\r\n{r_escritura.texto[:700]}",
                meta={"metodo_denegado": lectura, "estado_denegado": r_lectura.estado},
            )],
            fingerprint_extra=f"{lectura}->{escritura}",
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
