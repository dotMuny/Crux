"""GraphQL: un solo endpoint HTTP y cien operaciones detrás.

Para el resto del escaneo, `POST /graphql` es un endpoint con un parámetro
llamado `query`. Eso es todo lo que se veía, y por eso una aplicación con
GraphQL salía casi vacía del informe: las herramientas de inyección prueban el
parámetro `query` como si fuera un campo de texto, cuando lo que hay dentro son
operaciones con sus propios argumentos.

Qué hace este módulo, en orden de lo que vale:

1. **Encuentra el endpoint.** Por lo que vio el navegador, o probando las rutas
   habituales con una consulta que no hace nada (`{__typename}`).
2. **Pide el esquema.** Si la introspección está abierta, la aplicación entrega
   la lista completa de operaciones y argumentos. Eso es un hallazgo en sí y,
   además, el inventario que necesita el resto.
3. **Si está cerrada, prueba el atajo conocido.** Con las sugerencias de campo
   activadas, el error de una consulta con un campo mal escrito dice cómo se
   llamaba de verdad: el esquema se reconstruye consulta a consulta.
4. **Comprueba lo que no requiere adivinar nada**: si responde sin sesión, si
   acepta lotes de consultas en una sola petición.
5. **Prueba los argumentos de texto de las consultas**, buscando errores de
   base de datos. Solo consultas, nunca mutaciones: una mutación cambia datos,
   y aquí se audita una aplicación en uso.

Lo que **no** hace: fuzzing a fondo de cada argumento. Para eso haría falta un
fuzzer propio —lo que este proyecto evita a propósito—, y GraphQL no lo cubre
ninguna de las herramientas instaladas. Lo que se hace en su lugar es entregar
el inventario en el informe, para que el analista sepa exactamente qué hay y
pueda ir a mano a lo que importe.
"""

from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence
from urllib.parse import urlsplit

import httpx

from ..core.findings import Evidence, EvidenceKind, Finding
from ..core.policy import Policy
from ..core.scope import Scope
from ..core.severity import Confidence, Severity

# Rutas donde se sirve GraphQL casi siempre.
RUTAS = (
    "/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql", "/v2/graphql",
    "/gql", "/api/gql", "/query", "/api/query", "/graphql/console",
)

# Una consulta que no pide ningún dato de la aplicación: solo el nombre del
# tipo raíz. Sirve para saber si hay GraphQL detrás sin tocar nada.
SONDA = "{__typename}"

# La introspección, recortada a lo que se usa: operaciones y sus argumentos.
# La consulta completa de GraphiQL pide el esquema entero y son cientos de
# kilobytes que no se van a leer.
INTROSPECCION = """
query {
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields(includeDeprecated: true) {
        name
        args { name type { name kind ofType { name kind } } }
        type { name kind ofType { name kind fields { name type { name kind } } } }
      }
    }
  }
}
"""

# Errores de motor de base de datos. Es la detección por error, la misma que
# usan las herramientas de siempre: si la aplicación devuelve el error del
# motor, la entrada llegó hasta la consulta sin pasar por ningún parámetro.
ERRORES_DE_BASE = re.compile(
    r"sqlite3?\.\w*Error|unrecognized token|\[SQLITE_ERROR\]"
    r"|syntax error at or near|PG::\w*Error|PSQLException"
    r"|You have an error in your SQL syntax|MySQLSyntaxErrorException|mysqli?_\w+\(\)"
    r"|Unclosed quotation mark|Microsoft OLE DB Provider|SQLServerException"
    r"|ORA-\d{5}|quoted string not properly terminated",
    re.I,
)

# Comilla simple: la entrada mínima que rompe una consulta SQL construida
# concatenando. No altera datos ni intenta leer nada que no sea el error.
MARCA = "crux'"

# Topes: una aplicación con GraphQL tiene cientos de campos y cada argumento es
# una petición. Se mira lo que cabe en un escaneo, y se dice cuánto quedó.
MAX_CAMPOS_PROBADOS = 40


@dataclass(slots=True)
class Argumento:
    nombre: str
    tipo: str = ""

    @property
    def es_texto(self) -> bool:
        return self.tipo in ("String", "ID")


@dataclass(slots=True)
class Operacion:
    """Una consulta o mutación del esquema, con sus argumentos."""

    nombre: str
    clase: str                      # "consulta" | "mutacion"
    argumentos: list[Argumento] = field(default_factory=list)
    # Un campo escalar del tipo que devuelve, para poder construir la consulta.
    campo_de_salida: str = ""

    @property
    def etiqueta(self) -> str:
        args = ", ".join(f"{a.nombre}: {a.tipo}" for a in self.argumentos)
        return f"{self.nombre}({args})" if args else self.nombre


@dataclass(slots=True)
class Servicio:
    """Un endpoint GraphQL encontrado, con lo que se sepa de él."""

    url: str
    introspeccion: bool = False
    sugerencias: bool = False
    lotes: bool = False
    sin_sesion: bool = False
    operaciones: list[Operacion] = field(default_factory=list)
    campos_insinuados: list[str] = field(default_factory=list)

    @property
    def consultas(self) -> list[Operacion]:
        return [o for o in self.operaciones if o.clase == "consulta"]

    @property
    def mutaciones(self) -> list[Operacion]:
        return [o for o in self.operaciones if o.clase == "mutacion"]

    @property
    def resumen(self) -> str:
        partes = [f"{len(self.consultas)} consultas", f"{len(self.mutaciones)} mutaciones"]
        if self.introspeccion:
            partes.append("introspección abierta")
        return f"{self.url}: " + ", ".join(partes)


def _cliente(policy: Policy, sesion: Any = None) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        trust_env=False, follow_redirects=False, verify=False,
        timeout=httpx.Timeout(policy.request_timeout),
        headers={"User-Agent": "crux/0.1 (authorized internal audit)",
                 "Content-Type": "application/json",
                 **(sesion.cabeceras if sesion is not None else {})},
        cookies=sesion.cookies if sesion is not None else None,
    )


async def _preguntar(cliente: httpx.AsyncClient, url: str, cuerpo: Any) -> dict | list | None:
    """Manda una petición GraphQL y devuelve el JSON, o `None` si no lo es."""
    try:
        respuesta = await cliente.post(url, content=json.dumps(cuerpo).encode())
    except httpx.HTTPError:
        return None
    try:
        return respuesta.json()
    except ValueError:
        return None


def _es_graphql(datos: Any) -> bool:
    """¿Esta respuesta la ha dado un servidor GraphQL?

    Vale tanto `data` como `errors`: un endpoint que exige autenticación
    contesta con un error de GraphQL, y eso ya dice que hay GraphQL detrás.
    """
    if not isinstance(datos, dict):
        return False
    if isinstance(datos.get("data"), dict):
        return True
    errores = datos.get("errors")
    return isinstance(errores, list) and bool(errores)


def rutas_candidatas(scope: Scope, urls: Iterable[str],
                     vistos: Iterable[str] = ()) -> list[str]:
    """Dónde buscar GraphQL: lo que vio el navegador y las rutas habituales."""
    candidatas: list[str] = [u for u in vistos if scope.allows_url(u)]
    origenes: list[str] = []
    for url in urls:
        partes = urlsplit(url)
        if not partes.scheme or not partes.netloc:
            continue
        origen = f"{partes.scheme}://{partes.netloc}"
        if origen not in origenes:
            origenes.append(origen)
    for origen in origenes[:5]:
        for ruta in RUTAS:
            candidata = origen + ruta
            if candidata not in candidatas and scope.allows_url(candidata):
                candidatas.append(candidata)
    return candidatas


async def descubrir(scope: Scope, policy: Policy, urls: Sequence[str], *,
                    sesion: Any = None, vistos: Iterable[str] = ()) -> Servicio | None:
    """Encuentra el endpoint GraphQL y lo examina.

    La sonda es una consulta que no pide ningún dato (`{__typename}`), pero es
    una petición POST a una ruta que puede no ser GraphQL, así que probar las
    rutas habituales necesita el perfil que autoriza sondas activas. Lo que el
    navegador vio usarse se prueba siempre: ahí ya se sabe que hay GraphQL.
    """
    confirmados = [u for u in vistos if scope.allows_url(u)]
    candidatas = (confirmados if not policy.allow_active_probes
                  else rutas_candidatas(scope, urls, vistos))
    if not candidatas:
        return None

    async with _cliente(policy, sesion) as cliente:
        for url in candidatas:
            datos = await _preguntar(cliente, url, {"query": SONDA})
            if not _es_graphql(datos):
                continue
            servicio = Servicio(url=url)
            await _examinar(cliente, servicio, policy)
            if sesion is not None:
                servicio.sin_sesion = await _responde_sin_sesion(policy, url)
            return servicio
    return None


async def _examinar(cliente: httpx.AsyncClient, servicio: Servicio,
                    policy: Policy) -> None:
    """Esquema, sugerencias de campo y lotes."""
    datos = await _preguntar(cliente, servicio.url, {"query": INTROSPECCION})
    esquema = (datos or {}).get("data", {}).get("__schema") if isinstance(datos, dict) else None
    if isinstance(esquema, dict):
        servicio.introspeccion = True
        servicio.operaciones = operaciones_del_esquema(esquema)
    else:
        servicio.campos_insinuados = await _sugerencias(cliente, servicio.url)
        servicio.sugerencias = bool(servicio.campos_insinuados)

    # Lotes: dos consultas en una petición. Si contesta con dos resultados, un
    # atacante puede multiplicar intentos sin multiplicar peticiones.
    lote = await _preguntar(cliente, servicio.url,
                            [{"query": SONDA}, {"query": SONDA}])
    servicio.lotes = isinstance(lote, list) and len(lote) == 2


async def _sugerencias(cliente: httpx.AsyncClient, url: str) -> list[str]:
    """Los nombres que delata el mensaje de error de un campo mal escrito.

    Es el atajo conocido cuando la introspección está cerrada: el servidor
    responde «Cannot query field "usuariox" … Did you mean "usuarios"?». Con
    eso, el esquema se reconstruye adivinando y preguntando.
    """
    datos = await _preguntar(cliente, url, {"query": "{usuariox}"})
    if not isinstance(datos, dict):
        return []
    # De los mensajes en claro, no del JSON serializado: ahí las comillas van
    # escapadas y el patrón no casaba con nada.
    mensajes = " ".join(
        str(e.get("message") or "") for e in (datos.get("errors") or [])
        if isinstance(e, dict)
    )
    nombres: list[str] = []
    for trozo in re.findall(r"Did you mean ([^?]+)", mensajes):
        nombres.extend(re.findall(r'"([^"]+)"', trozo))
    return list(dict.fromkeys(nombres))[:8]


async def _responde_sin_sesion(policy: Policy, url: str) -> bool:
    """¿Contesta a quien no se ha autenticado?

    Un endpoint GraphQL que responde `data` a un anónimo expone todo su esquema
    de consultas a cualquiera que llegue a la red.
    """
    async with _cliente(policy, None) as cliente:
        datos = await _preguntar(cliente, url, {"query": SONDA})
    return isinstance(datos, dict) and isinstance(datos.get("data"), dict)


# ── Leer el esquema ─────────────────────────────────────────────────────────


def _nombre_de_tipo(tipo: Any) -> str:
    """El nombre de un tipo, atravesando NON_NULL y LIST."""
    visto = 0
    while isinstance(tipo, dict) and visto < 6:
        if tipo.get("name"):
            return str(tipo["name"])
        tipo = tipo.get("ofType")
        visto += 1
    return ""


def operaciones_del_esquema(esquema: dict[str, Any]) -> list[Operacion]:
    """Las consultas y mutaciones que declara el esquema."""
    tipos = {t.get("name"): t for t in esquema.get("types") or []
             if isinstance(t, dict) and t.get("name")}
    raices = (
        ("consulta", _nombre_de_tipo(esquema.get("queryType"))),
        ("mutacion", _nombre_de_tipo(esquema.get("mutationType"))),
    )
    operaciones: list[Operacion] = []
    for clase, nombre_raiz in raices:
        raiz = tipos.get(nombre_raiz)
        if not isinstance(raiz, dict):
            continue
        for campo in raiz.get("fields") or []:
            if not isinstance(campo, dict) or not campo.get("name"):
                continue
            argumentos = [
                Argumento(nombre=str(a.get("name")), tipo=_nombre_de_tipo(a.get("type")))
                for a in (campo.get("args") or []) if isinstance(a, dict) and a.get("name")
            ]
            operaciones.append(Operacion(
                nombre=str(campo["name"]), clase=clase, argumentos=argumentos,
                campo_de_salida=_campo_escalar(campo.get("type"), tipos),
            ))
    return operaciones


ESCALARES = frozenset({"String", "Int", "Float", "Boolean", "ID"})


def _campo_escalar(tipo: Any, tipos: dict[str, Any]) -> str:
    """Un campo simple del tipo que devuelve una operación.

    Hace falta para poder preguntar: en GraphQL, pedir un objeto sin decir qué
    campos suyos se quieren es un error de sintaxis, así que sin esto no se
    puede construir ni una consulta válida.
    """
    nombre = _nombre_de_tipo(tipo)
    if not nombre or nombre in ESCALARES:
        return ""
    declarado = tipos.get(nombre)
    campos = (declarado or {}).get("fields") or []
    for campo in campos:
        if isinstance(campo, dict) and _nombre_de_tipo(campo.get("type")) in ESCALARES:
            return str(campo.get("name") or "")
    # Puede venir anidado en el propio `ofType` de la introspección recortada.
    anidado = tipo.get("ofType") if isinstance(tipo, dict) else None
    for campo in (anidado or {}).get("fields") or []:
        if isinstance(campo, dict) and _nombre_de_tipo(campo.get("type")) in ESCALARES:
            return str(campo.get("name") or "")
    return ""


def consulta_de(operacion: Operacion, valores: dict[str, str]) -> str:
    """El texto de una consulta a un campo, con los valores dados."""
    argumentos = ", ".join(
        f'{nombre}: "{valor}"' for nombre, valor in valores.items()
    )
    llamada = f"{operacion.nombre}({argumentos})" if argumentos else operacion.nombre
    seleccion = f" {{ {operacion.campo_de_salida} }}" if operacion.campo_de_salida else ""
    return f"query {{ {llamada}{seleccion} }}"


# ── Probar los argumentos ───────────────────────────────────────────────────


async def probar_argumentos(servicio: Servicio, policy: Policy, *,
                            sesion: Any = None) -> tuple[list[Finding], int]:
    """Busca errores de base de datos en los argumentos de texto.

    Solo consultas: una mutación cambia datos, y esto corre contra la
    aplicación de verdad. Solo detección por error —si el motor devuelve su
    propio mensaje, la entrada llegó hasta la consulta—, que es lo que se puede
    afirmar sin inventar nada.

    Devuelve los hallazgos y cuántos argumentos quedaron sin probar.
    """
    if not policy.allow_active_probes:
        return [], sum(len([a for a in o.argumentos if a.es_texto])
                       for o in servicio.consultas)

    pendientes = [
        (operacion, argumento)
        for operacion in servicio.consultas
        for argumento in operacion.argumentos
        if argumento.es_texto
    ]
    probables, resto = pendientes[:MAX_CAMPOS_PROBADOS], pendientes[MAX_CAMPOS_PROBADOS:]
    hallazgos: list[Finding] = []
    semaforo = asyncio.Semaphore(policy.concurrency)

    async with _cliente(policy, sesion) as cliente:
        async def probar(operacion: Operacion, argumento: Argumento) -> None:
            async with semaforo:
                texto = consulta_de(operacion, {argumento.nombre: MARCA})
                datos = await _preguntar(cliente, servicio.url, {"query": texto})
                if datos is None:
                    return
                crudo = json.dumps(datos, ensure_ascii=False)
                error = ERRORES_DE_BASE.search(crudo)
                if error is None:
                    return
                hallazgos.append(_hallazgo_de_inyeccion(
                    servicio, operacion, argumento, texto, crudo, error.group(0)))

        await asyncio.gather(*(probar(o, a) for o, a in probables))
    return hallazgos, len(resto)


def _hallazgo_de_inyeccion(servicio, operacion, argumento, consulta, respuesta,
                           senal) -> Finding:
    return Finding(
        source="graphql", check_id="graphql-inyeccion-sql",
        title=(f"El argumento «{argumento.nombre}» de la consulta "
               f"«{operacion.nombre}» llega a la base de datos"),
        description=(
            f"Al pasar una comilla en {operacion.nombre}({argumento.nombre}), la "
            f"respuesta trae el error del motor: «{senal}». El valor se está "
            "concatenando en la consulta en lugar de ir como parámetro, así que es "
            "una inyección. Ningún escáner de los habituales llega aquí: para ellos "
            "esto es un POST con un campo de texto llamado «query»."),
        remediation=(
            "Usa consultas parametrizadas en el resolutor de ese campo. Y no devuelvas "
            "el error del motor al cliente: dice la estructura de la base."),
        target=servicio.url, param=f"{operacion.nombre}.{argumento.nombre}",
        severity=Severity.CRITICAL, confidence=Confidence.FIRM,
        cwe=["CWE-89"], owasp=["A03:2021", "API8:2023"],
        evidence=[Evidence(
            kind=EvidenceKind.HTTP,
            request=f"POST {servicio.url}\r\n\r\n{json.dumps({'query': consulta})}",
            response=respuesta[:900],
        )],
        fingerprint_extra=f"{operacion.nombre}.{argumento.nombre}",
        extra={"operacion": operacion.etiqueta},
    )


# ── Lo que se cuenta del servicio ───────────────────────────────────────────


def hallazgos(servicio: Servicio, *, argumentos_sin_probar: int = 0,
              policy: Policy | None = None) -> list[Finding]:
    salida: list[Finding] = [_inventario(servicio, argumentos_sin_probar, policy)]

    if servicio.introspeccion:
        salida.append(Finding(
            source="graphql", check_id="graphql-introspeccion-abierta",
            title="La introspección de GraphQL está abierta",
            description=(
                f"{servicio.url} entrega su esquema completo a quien lo pida: "
                f"{len(servicio.consultas)} consultas y {len(servicio.mutaciones)} "
                "mutaciones con todos sus argumentos y tipos. Es el mapa de la "
                "aplicación, y con él no hay que adivinar nada para empezar a probar. "
                "En desarrollo es una herramienta; en producción, información que no "
                "hace falta dar."),
            remediation=(
                "Desactiva la introspección en producción —en la mayoría de "
                "implementaciones es una opción del servidor— y con ella las "
                "sugerencias de campo, que la reconstruyen a trozos."),
            target=servicio.url, severity=Severity.LOW, confidence=Confidence.CERTAIN,
            cwe=["CWE-200"], owasp=["API9:2023"], tags=["graphql", "disclosure"],
            extra={"consultas": len(servicio.consultas),
                   "mutaciones": len(servicio.mutaciones)},
        ))

    if servicio.sugerencias:
        salida.append(Finding(
            source="graphql", check_id="graphql-sugerencias-de-campo",
            title="GraphQL sugiere los nombres de los campos en sus errores",
            description=(
                "La introspección está cerrada, pero el error de una consulta con un "
                "campo mal escrito dice cómo se llamaba de verdad: "
                f"{', '.join(servicio.campos_insinuados)}. Preguntando así se "
                "reconstruye el esquema sin introspección, que es el atajo conocido "
                "para saltarse haberla desactivado."),
            remediation=(
                "Desactiva las sugerencias de campo («field suggestions») además de la "
                "introspección, y devuelve un error genérico."),
            target=servicio.url, severity=Severity.LOW, confidence=Confidence.FIRM,
            cwe=["CWE-200"], owasp=["API9:2023"], tags=["graphql", "disclosure"],
            evidence=[Evidence(kind=EvidenceKind.RAW,
                               snippet="\n".join(servicio.campos_insinuados))],
        ))

    if servicio.lotes:
        salida.append(Finding(
            source="graphql", check_id="graphql-lotes-permitidos",
            title="GraphQL acepta varias consultas en una sola petición",
            description=(
                f"{servicio.url} responde a una lista de consultas con una lista de "
                "resultados. Cualquier límite por peticiones —de intentos de acceso, "
                "de código de un segundo factor, de llamadas por minuto— deja de "
                "contar: mil intentos caben en una petición."),
            remediation=(
                "Desactiva el procesado por lotes si la aplicación no lo necesita, o "
                "limita cuántas operaciones admite una petición y cuenta cada "
                "operación, no cada petición, en los límites de intentos."),
            target=servicio.url, severity=Severity.MEDIUM, confidence=Confidence.CERTAIN,
            cwe=["CWE-307"], owasp=["API4:2023"], tags=["graphql"],
        ))

    if servicio.sin_sesion:
        salida.append(Finding(
            source="graphql", check_id="graphql-sin-autenticar",
            title="El endpoint GraphQL responde sin autenticarse",
            description=(
                f"{servicio.url} contestó con datos a una petición sin sesión, en una "
                "aplicación en la que el escaneo sí tuvo que autenticarse. En GraphQL "
                "esto importa más que en una ruta cualquiera: por el mismo endpoint "
                "pasan todas las operaciones."),
            remediation=(
                "Exige sesión en el endpoint, y además comprueba el permiso en cada "
                "resolutor: un único control en la entrada no distingue entre "
                "operaciones."),
            target=servicio.url, severity=Severity.HIGH, confidence=Confidence.FIRM,
            cwe=["CWE-306"], owasp=["A01:2021", "API1:2023"], tags=["graphql"],
        ))
    return salida


def _inventario(servicio: Servicio, sin_probar: int,
                policy: Policy | None = None) -> Finding:
    """Qué hay detrás del endpoint, y qué se miró de ello.

    Esto es lo que sustituye al fuzzer que no se escribe: la lista exacta de
    operaciones y argumentos, para que quien audita sepa a dónde ir a mano.
    """
    consultas = ", ".join(o.etiqueta for o in servicio.consultas[:25]) or "ninguna"
    mutaciones = ", ".join(o.etiqueta for o in servicio.mutaciones[:25]) or "ninguna"
    detalle = [
        f"Endpoint: {servicio.url}. ",
        f"Consultas ({len(servicio.consultas)}): {consultas}. ",
        f"Mutaciones ({len(servicio.mutaciones)}): {mutaciones}. ",
    ]
    if not servicio.introspeccion:
        detalle.append(
            "La introspección está cerrada, así que esta lista es solo lo que se pudo "
            "deducir: puede haber muchas más operaciones. ")
    if policy is not None and not policy.allow_active_probes:
        detalle.append(
            f"Con el perfil «{policy.profile}» no se envía nada, así que los "
            f"{sin_probar} argumentos de texto de las consultas quedaron sin probar: "
            "esto es un inventario, no una comprobación. ")
    else:
        detalle.append(
            "De los argumentos de texto de las consultas se comprobó si llegan a la "
            "base de datos. Las mutaciones no se prueban: cambian datos. ")
        if sin_probar:
            detalle.append(
                f"Quedaron {sin_probar} argumentos sin probar por el tope del "
                "escaneo. ")
    detalle.append(
        "El fuzzing a fondo de cada argumento no lo hace ninguna de las herramientas "
        "instaladas, y aquí no se escribe uno propio: esta lista es para ir a mano.")

    return Finding(
        source="graphql", check_id="graphql-inventario",
        title=(f"GraphQL: {len(servicio.consultas)} consultas y "
               f"{len(servicio.mutaciones)} mutaciones detrás de un endpoint"),
        description="".join(detalle),
        remediation="",
        target=servicio.url, severity=Severity.INFO, confidence=Confidence.CERTAIN,
        tags=["cobertura", "graphql"],
        extra={
            "consultas": [o.etiqueta for o in servicio.consultas],
            "mutaciones": [o.etiqueta for o in servicio.mutaciones],
            "introspeccion": servicio.introspeccion,
            "argumentos_sin_probar": sin_probar,
        },
    )
