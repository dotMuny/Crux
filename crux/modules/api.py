"""La API que hay por debajo de la interfaz.

Casi toda aplicación interna moderna es una interfaz que habla con una API, y
la API es donde está la lógica: la autorización, las consultas, los ficheros.
El crawler ve esas llamadas mientras recorre la aplicación, pero solo las que
la interfaz llega a hacer. Lo que no se pulsa, no se ve.

Cuando la aplicación publica su especificación —OpenAPI 3 o Swagger 2— hay otra
forma de verlo: la lista completa de rutas, métodos y parámetros, escrita por
quien la programó. Este módulo la busca, la lee y la convierte en endpoints que
las demás fases pueden auditar.

Dos reglas que no se negocian:

- **La especificación es dato del objetivo, no configuración nuestra.** Declara
  sus propios servidores, y uno puede apuntar a `api.pagos-externos.com`. De un
  servidor declarado se toma solo la ruta; el host es siempre el del alcance.
  Un escaneo no se sale del alcance porque un fichero del objetivo lo diga.
- **Los métodos que destruyen no se tocan sin permiso.** `DELETE /pedidos/{id}`
  está en la especificación de cualquier API; ejecutarlo en la aplicación de
  verdad de un cliente borra un pedido de verdad. Solo entran con el perfil que
  autoriza métodos destructivos.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Sequence
from urllib.parse import urljoin, urlsplit

import httpx

from ..core.findings import Evidence, EvidenceKind, Finding
from ..core.policy import Policy
from ..core.scope import Scope
from ..core.severity import Confidence, Severity
from .crawler import Endpoint, claves_planas

# Dónde publica cada marco su especificación. El orden importa poco: se prueban
# todas y se queda la primera que sea legible.
RUTAS_DE_ESPECIFICACION: tuple[str, ...] = (
    "/openapi.json", "/openapi.yaml", "/openapi.yml",
    "/swagger.json", "/swagger.yaml",
    "/v3/api-docs", "/v2/api-docs",                 # Spring Boot
    "/swagger/v1/swagger.json",                     # ASP.NET Core
    "/api-docs", "/api/openapi.json", "/api/swagger.json",
    "/api/v1/openapi.json", "/api/docs/openapi.json",
    "/.well-known/openapi.json",
    "/docs/openapi.json", "/redoc/openapi.json",
)

# Métodos que cambian o borran estado. Entran solo con permiso explícito.
METODOS_DESTRUCTIVOS = frozenset({"PUT", "PATCH", "DELETE"})
METODOS = ("get", "post", "put", "patch", "delete")

# Una especificación más grande que esto no se lee: a partir de aquí no es una
# especificación, es otra cosa que casualmente responde en esa ruta.
TAMANO_MAXIMO = 8 * 1024 * 1024

# Cuántos orígenes distintos se registran buscando la especificación.
MAX_ORIGENES = 10


@dataclass(slots=True)
class Especificacion:
    """Una especificación encontrada, ya interpretada."""

    origen: str                     # URL donde se encontró, o ruta del fichero
    formato: str                    # "OpenAPI 3.1", "Swagger 2.0"
    titulo: str = ""
    endpoints: list[Endpoint] = field(default_factory=list)
    # Servidores que declaraba y que no están en el alcance: no se tocan, pero
    # se dicen. Una API interna que declara un servidor de fuera es información.
    servidores_fuera: list[str] = field(default_factory=list)
    # Rutas que se saltaron por ser destructivas sin tener permiso para ello.
    omitidos_destructivos: int = 0
    # La especificación se sirve sin autenticar.
    sin_autenticar: bool = False
    # El documento tal como venía. Lo necesitan las herramientas que lo leen
    # ellas mismas, y va saneado antes de dárselo (ver `sanear`).
    crudo: dict[str, Any] = field(default_factory=dict)
    # El origen sobre el que se resolvieron las rutas.
    base: str = ""

    @property
    def resumen(self) -> str:
        return f"{len(self.endpoints)} endpoints de {self.formato} en {self.origen}"


# ── Leer una especificación ────────────────────────────────────────────────


def interpretar_texto(texto: str) -> dict[str, Any] | None:
    """El documento como diccionario, venga en JSON o en YAML.

    Devuelve `None` si no es ninguna de las dos cosas, o si no parece una
    especificación: sin `paths` no hay nada que auditar, y confundir cualquier
    JSON con una especificación llenaría el informe de endpoints inventados.
    """
    texto = (texto or "").strip()
    if not texto or len(texto) > TAMANO_MAXIMO:
        return None
    datos: Any = None
    if texto.startswith(("{", "[")):
        try:
            datos = json.loads(texto)
        except ValueError:
            return None
    else:
        try:
            import yaml
        except ImportError:
            return None
        try:
            # safe_load: una especificación es dato del objetivo, y el cargador
            # completo de YAML construye objetos de Python.
            datos = yaml.safe_load(texto)
        except Exception:
            return None
    if not isinstance(datos, dict) or not isinstance(datos.get("paths"), dict):
        return None
    if not (datos.get("openapi") or datos.get("swagger")):
        return None
    return datos


def leer_fichero(ruta: str | Path) -> dict[str, Any]:
    """Una especificación que pasa el analista. Lanza si no se puede leer."""
    camino = Path(ruta)
    datos = interpretar_texto(camino.read_text(encoding="utf-8", errors="replace"))
    if datos is None:
        raise ValueError(
            f"{camino} no es una especificación OpenAPI o Swagger legible: tiene que "
            "ser JSON o YAML y llevar «openapi» o «swagger» y «paths»")
    return datos


def formato_de(datos: dict[str, Any]) -> str:
    if datos.get("openapi"):
        return f"OpenAPI {datos['openapi']}"
    return f"Swagger {datos.get('swagger')}"


# ── Convertirla en endpoints ────────────────────────────────────────────────


def _resolver(nodo: Any, raiz: dict[str, Any], visitados: frozenset[str] = frozenset()) -> Any:
    """Sigue un `$ref` dentro del propio documento, con guarda de ciclos.

    Solo referencias internas: una que apunte a otro fichero o a una URL se
    ignora, porque seguirla sería traer dato de fuera del alcance.
    """
    if not isinstance(nodo, dict):
        return nodo
    ref = nodo.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/") or ref in visitados:
        return nodo
    destino: Any = raiz
    for parte in ref[2:].split("/"):
        parte = parte.replace("~1", "/").replace("~0", "~")
        if not isinstance(destino, dict) or parte not in destino:
            return nodo
        destino = destino[parte]
    return _resolver(destino, raiz, visitados | {ref})


def _ejemplo(esquema: dict[str, Any], raiz: dict[str, Any]) -> Any:
    """Un valor plausible para un campo, a partir de su tipo.

    Se prefiere lo que diga la especificación —`example`, `default`, el primer
    `enum`—: es el valor que el desarrollador sabe que la API acepta, y con el
    que es más probable llegar a la lógica en vez de rebotar en la validación.
    """
    esquema = _resolver(esquema, raiz)
    if not isinstance(esquema, dict):
        return "crux"
    for campo in ("example", "default"):
        if campo in esquema:
            return esquema[campo]
    if isinstance(esquema.get("enum"), list) and esquema["enum"]:
        return esquema["enum"][0]
    tipo = esquema.get("type")
    if tipo == "integer":
        return 1
    if tipo == "number":
        return 1.0
    if tipo == "boolean":
        return True
    if tipo == "array":
        return [_ejemplo(esquema.get("items") or {}, raiz)]
    if tipo == "object" or "properties" in esquema:
        return {
            str(k): _ejemplo(v or {}, raiz)
            for k, v in (esquema.get("properties") or {}).items()
        }
    if esquema.get("format") in ("date", "date-time"):
        return "2026-01-01T00:00:00Z"
    return "crux"


def _cuerpo_de(operacion: dict[str, Any], raiz: dict[str, Any],
               parametros: Sequence[dict[str, Any]]) -> tuple[str, list[str], str]:
    """El cuerpo de ejemplo de una operación: (cuerpo, claves, tipo de contenido).

    OpenAPI 3 lo pone en `requestBody.content`; Swagger 2, en un parámetro
    `in: body`. Se cubren los dos porque las dos versiones siguen en uso: un
    Spring Boot de hace cinco años sirve Swagger 2.
    """
    cuerpo = _resolver(operacion.get("requestBody") or {}, raiz)
    contenido = cuerpo.get("content") if isinstance(cuerpo, dict) else None
    if isinstance(contenido, dict):
        for tipo in ("application/json", "application/x-www-form-urlencoded"):
            entrada = contenido.get(tipo)
            if not isinstance(entrada, dict):
                continue
            esquema = _resolver(entrada.get("schema") or {}, raiz)
            ejemplo = _ejemplo(esquema, raiz)
            if not isinstance(ejemplo, dict):
                continue
            claves = claves_planas(ejemplo)
            if tipo == "application/json":
                return json.dumps(ejemplo, ensure_ascii=False), claves, tipo
            from urllib.parse import urlencode

            return urlencode({k: str(v) for k, v in ejemplo.items()}), claves, tipo

    # Swagger 2: el cuerpo es un parámetro más.
    for parametro in parametros:
        if parametro.get("in") != "body":
            continue
        ejemplo = _ejemplo(parametro.get("schema") or {}, raiz)
        if isinstance(ejemplo, dict):
            return (json.dumps(ejemplo, ensure_ascii=False),
                    claves_planas(ejemplo), "application/json")
    return "", [], ""


def _bases(datos: dict[str, Any], base: str, scope: Scope | None) -> tuple[list[str], list[str]]:
    """Las bases sobre las que colgar las rutas, y los servidores descartados.

    De un servidor declarado se usa solo su ruta: el host sale del alcance, no
    del fichero. Así una especificación que declara `https://api.de-otro.com`
    no arrastra el escaneo fuera —y que lo declare se cuenta aparte—.
    """
    origen = f"{urlsplit(base).scheme}://{urlsplit(base).netloc}"
    declarados: list[str] = []
    fuera: list[str] = []

    crudos: list[str] = []
    for servidor in datos.get("servers") or []:
        if isinstance(servidor, dict) and isinstance(servidor.get("url"), str):
            crudos.append(servidor["url"])
    if datos.get("swagger"):
        ruta_base = datos.get("basePath")
        if isinstance(ruta_base, str):
            crudos.append(ruta_base)
        anfitrion = datos.get("host")
        if isinstance(anfitrion, str) and anfitrion:
            esquema = (datos.get("schemes") or ["https"])[0]
            crudos.append(f"{esquema}://{anfitrion}{ruta_base or ''}")

    for crudo in crudos:
        partes = urlsplit(crudo)
        if partes.netloc:
            absoluta = crudo if crudo.endswith("/") else crudo + "/"
            if scope is not None and not scope.allows_url(absoluta):
                if crudo not in fuera:
                    fuera.append(crudo)
                # De un servidor ajeno se conserva la ruta, que suele ser la
                # misma («/api/v2»), y se le pone el host del alcance.
                ruta = partes.path
            else:
                declarados.append(absoluta.rstrip("/") or origen)
                continue
        else:
            ruta = crudo
        candidata = (origen + "/" + ruta.strip("/")).rstrip("/") if ruta.strip("/") else origen
        if candidata not in declarados:
            declarados.append(candidata)

    return (declarados or [origen]), fuera


def interpretar(datos: dict[str, Any], base: str, *, scope: Scope | None = None,
                destructivos: bool = False, origen: str = "") -> Especificacion:
    """Los endpoints que describe la especificación, listos para auditar."""
    espec = Especificacion(
        origen=origen or base,
        formato=formato_de(datos),
        titulo=str((datos.get("info") or {}).get("title") or ""),
        crudo=datos,
        base=base,
    )
    bases, espec.servidores_fuera = _bases(datos, base, scope)

    for plantilla, entrada in (datos.get("paths") or {}).items():
        entrada = _resolver(entrada, datos)
        if not isinstance(entrada, dict) or not isinstance(plantilla, str):
            continue
        comunes = [_resolver(p, datos) for p in (entrada.get("parameters") or [])]
        for metodo in METODOS:
            operacion = entrada.get(metodo)
            if not isinstance(operacion, dict):
                continue
            if metodo.upper() in METODOS_DESTRUCTIVOS and not destructivos:
                espec.omitidos_destructivos += 1
                continue
            parametros = comunes + [_resolver(p, datos)
                                    for p in (operacion.get("parameters") or [])]
            ruta = plantilla
            query: list[str] = []
            for parametro in parametros:
                if not isinstance(parametro, dict):
                    continue
                nombre = str(parametro.get("name") or "")
                sitio = parametro.get("in")
                if not nombre:
                    continue
                if sitio == "path":
                    valor = _ejemplo(parametro.get("schema") or parametro, datos)
                    ruta = ruta.replace("{" + nombre + "}", str(valor))
                elif sitio == "query":
                    query.append(nombre)
            if "{" in ruta:
                # Un parámetro de ruta que la especificación no declara: se
                # rellena con algo plausible en vez de pedir «/pedidos/{id}»,
                # que no existe en ninguna aplicación.
                import re as _re

                ruta = _re.sub(r"\{[^}]+\}", "1", ruta)

            cuerpo, claves, tipo = _cuerpo_de(operacion, datos, parametros)
            for raiz in bases:
                url = urljoin(raiz.rstrip("/") + "/", ruta.lstrip("/"))
                if scope is not None and not scope.allows_url(url):
                    continue
                if query:
                    url = f"{url}?" + "&".join(f"{n}=1" for n in query)
                espec.endpoints.append(Endpoint(
                    url=url, metodo=metodo.upper(), params=query,
                    origen="especificacion", tipo_contenido=tipo,
                    cuerpo=cuerpo, params_cuerpo=claves,
                ))
    return espec


def sanear(datos: dict[str, Any], base: str) -> dict[str, Any]:
    """La misma especificación con un solo servidor: el del alcance.

    Las herramientas que leen una especificación —nuclei con `-im openapi`,
    wapiti con `--swagger`— sacan de ella los objetivos. Se comprobó: nuclei
    pide exactamente el servidor que declara el fichero. Pasarles el original
    sería dejar que un fichero del objetivo decida a quién se le mandan cargas
    de prueba, que es la definición de salirse del alcance.
    """
    copia = dict(datos)
    partes = urlsplit(base)
    origen = f"{partes.scheme}://{partes.netloc}"
    rutas = [urlsplit(s["url"]).path for s in (datos.get("servers") or [])
             if isinstance(s, dict) and isinstance(s.get("url"), str)]
    if datos.get("swagger"):
        if isinstance(datos.get("basePath"), str):
            rutas.append(datos["basePath"])
        copia["host"] = partes.netloc
        copia["schemes"] = [partes.scheme]
        copia["basePath"] = next((r for r in rutas if r.strip("/")), "/")
    ruta = next((r for r in rutas if r.strip("/")), "")
    copia["servers"] = [{"url": origen + "/" + ruta.strip("/") if ruta.strip("/") else origen}]
    return copia


# ── Encontrarla en la aplicación ────────────────────────────────────────────


def _cliente(policy: Policy, sesion: Any = None) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        trust_env=False,
        follow_redirects=True,
        verify=False,
        timeout=httpx.Timeout(policy.request_timeout),
        headers={"User-Agent": "crux/0.1 (authorized internal audit)",
                 "Accept": "application/json, application/yaml, text/yaml, */*",
                 **(sesion.cabeceras if sesion is not None else {})},
        cookies=sesion.cookies if sesion is not None else None,
    )


def candidatas(bases: Iterable[str]) -> list[str]:
    """Las URL donde buscar la especificación, sin repetir orígenes.

    Se limitan los orígenes porque esto son quince peticiones por cada uno: en
    un escaneo de una red con cincuenta hosts vivos serían setecientas antes de
    empezar a escanear. Para una aplicación —el caso normal— no cambia nada.
    """
    origenes: list[str] = []
    for base in bases:
        partes = urlsplit(base)
        if not partes.scheme or not partes.netloc:
            continue
        origen = f"{partes.scheme}://{partes.netloc}"
        if origen not in origenes:
            origenes.append(origen)
    return [origen + ruta
            for origen in origenes[:MAX_ORIGENES]
            for ruta in RUTAS_DE_ESPECIFICACION]


async def descubrir(scope: Scope, policy: Policy, bases: Sequence[str], *,
                    sesion: Any = None, destructivos: bool = False) -> Especificacion | None:
    """Busca la especificación en las rutas habituales y la interpreta.

    Se piden rutas conocidas de la propia aplicación: es el mismo tipo de
    petición que ya hace el probador, dentro del alcance y con la sesión del
    escaneo. La primera que sea legible gana; si no hay ninguna, se devuelve
    `None` y el escaneo sigue con lo que vea el crawler.
    """
    urls = [u for u in candidatas(bases) if scope.allows_url(u)]
    if not urls:
        return None
    async with _cliente(policy, sesion) as cliente:
        for url in urls:
            try:
                respuesta = await cliente.get(url)
            except httpx.HTTPError:
                continue
            if respuesta.status_code != 200:
                continue
            datos = interpretar_texto(respuesta.text)
            if datos is None:
                continue
            espec = interpretar(datos, url, scope=scope,
                                destructivos=destructivos, origen=url)
            if not espec.endpoints:
                continue
            if sesion is not None:
                espec.sin_autenticar = await _alcanzable_sin_sesion(policy, url)
            return espec
    return None


async def _alcanzable_sin_sesion(policy: Policy, url: str) -> bool:
    """¿La especificación se sirve también a quien no se ha autenticado?

    Importa porque es el mapa de la API: rutas internas, nombres de campos,
    parámetros de administración. Si la aplicación exige entrar para todo lo
    demás, servir esto sin entrar es una fuga.
    """
    async with _cliente(policy, None) as cliente:
        try:
            respuesta = await cliente.get(url)
        except httpx.HTTPError:
            return False
    return respuesta.status_code == 200 and interpretar_texto(respuesta.text) is not None


# ── Lo que se cuenta en el informe ──────────────────────────────────────────


def hallazgos(espec: Especificacion, *, vistos_por_el_crawler: int = 0,
              policy: Policy | None = None) -> list[Finding]:
    """Qué se analizó de la API, y lo que la propia especificación delata."""
    salida: list[Finding] = []
    detalle = [f"Especificación: {espec.origen} ({espec.formato})."]
    if espec.titulo:
        detalle.append(f"API: «{espec.titulo}».")
    detalle.append(f"Aportó {len(espec.endpoints)} endpoints con sus métodos y parámetros")
    if vistos_por_el_crawler:
        detalle.append(f", frente a los {vistos_por_el_crawler} que el recorrido con "
                       "navegador vio por su cuenta")
    detalle.append(".")
    if espec.omitidos_destructivos:
        detalle.append(
            f" Se dejaron fuera {espec.omitidos_destructivos} operaciones con métodos "
            "que modifican o borran (PUT, PATCH, DELETE): ejecutarlas en una aplicación "
            "en uso cambia datos de verdad. El perfil agresivo las incluye.")
    if policy is not None and not policy.allow_injection:
        detalle.append(
            f" Con el perfil «{policy.profile}», la especificación la prueba wapiti con "
            "sus módulos de inyección; el fuzzing de nuclei sobre ella no corre, porque "
            "fuzzear es inyectar. El perfil agresivo lo añade.")

    salida.append(Finding(
        source="crux", check_id="api-analizada",
        title=f"La API se auditó desde su especificación: {len(espec.endpoints)} endpoints",
        description="".join(detalle),
        remediation="",
        target=espec.origen,
        severity=Severity.INFO, confidence=Confidence.CERTAIN,
        tags=["cobertura", "api"],
        extra={"formato": espec.formato, "endpoints": len(espec.endpoints),
               "omitidos_destructivos": espec.omitidos_destructivos},
    ))

    if espec.sin_autenticar:
        salida.append(Finding(
            source="crux", check_id="especificacion-api-sin-autenticar",
            title="La especificación de la API se sirve sin autenticarse",
            description=(
                f"{espec.origen} responde con la especificación completa a quien no ha "
                "entrado, mientras el resto de la aplicación exige sesión. Ahí está el "
                "mapa de la API: todas las rutas, los métodos, los nombres de los campos "
                "y los parámetros de administración. No es una vulnerabilidad por sí "
                "sola, pero es el primer paso de cualquiera que mire esta aplicación."),
            remediation=(
                "Sirve la especificación solo a sesiones autenticadas, o no la publiques "
                "en producción y déjala en el entorno de desarrollo."),
            target=espec.origen,
            severity=Severity.LOW, confidence=Confidence.CERTAIN,
            cwe=["CWE-200"], owasp=["API9:2023"], tags=["api", "disclosure"],
            extra={"formato": espec.formato},
        ))

    if espec.servidores_fuera:
        salida.append(Finding(
            source="crux", check_id="api-declara-servidor-externo",
            title="La especificación declara servidores que no están en el alcance",
            description=(
                "La especificación declara como servidores de esta API: "
                + ", ".join(espec.servidores_fuera)
                + ". No se han tocado: el escaneo solo usa el host del alcance, aunque el "
                "fichero diga otra cosa. Se dice porque una aplicación interna que declara "
                "un servidor de fuera suele significar que manda datos ahí."),
            remediation=(
                "Comprueba si la aplicación habla de verdad con esos servidores y si eso "
                "está autorizado. Si no, quítalos de la especificación."),
            target=espec.origen,
            severity=Severity.INFO, confidence=Confidence.FIRM,
            tags=["api", "egress"],
            evidence=[Evidence(kind=EvidenceKind.RAW,
                               snippet="\n".join(espec.servidores_fuera))],
            extra={"servidores": espec.servidores_fuera},
        ))
    return salida
