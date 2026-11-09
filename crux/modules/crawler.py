"""Crawler con navegador real. Descubre lo que un cliente HTTP no ve.

Usa Selenium con el `chromium-driver` del sistema. No usa Playwright porque su
paquete en Kali no trae driver propio y exige Node en el equipo de cada
analista, que es la superficie que este proyecto evita (ver docs/decisiones.md).

Lo que aporta frente al probador HTTP:
- Ejecuta el JavaScript, así que ve las rutas que sólo existen tras el render.
- Entra autenticado y mantiene la sesión, volviendo a entrar si se pierde.
- Lee la API de rendimiento del navegador, que **enumera cada petición que la
  página ha hecho**, incluidas las que dispara el bundle. Eso da los endpoints
  de la API sin tener que parsear JavaScript.

Sobre el alcance: el crawler nunca navega fuera, pero una página puede pedir
recursos por su cuenta antes de que nadie pueda impedirlo. Lo que se hace es
auditarlo —toda petición fuera de alcance queda registrada y se convierte en
hallazgo— y confiar la prevención al aislamiento por namespace de red. Decirlo
claro importa: aquí hay detección, no contención.
"""

from __future__ import annotations

import contextlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Sequence
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from ..core.egress import CHROMIUM_ARGS
from ..core.policy import Policy
from ..core.scope import Scope
from .auth import (
    RegistroDeRed,
    Sesion,
    parece_desconectado,
    parece_proveedor,
    sigue_viva,
)

# Rutas que no aportan nada al análisis y sí consumen presupuesto de páginas.
RUIDO = re.compile(
    r"\.(png|jpe?g|gif|svg|ico|woff2?|ttf|eot|mp4|webm|pdf|zip)(\?|$)", re.I
)
# Enlaces que cierran la sesión: seguirlos deja al crawler fuera sin avisar.
PELIGROSOS = re.compile(r"(logout|signout|cerrar-sesion|salir|delete|eliminar)", re.I)

# Tipos de petición del registro de red que son llamadas de la aplicación a su
# API, no navegación ni recursos.
TIPOS_DE_API = ("xhr", "fetch", "eventsource", "websocket")

# Claves cuyo valor no se guarda nunca. El cuerpo de la petición de acceso
# lleva la contraseña en claro, y la superficie del escaneo se persiste: lo que
# hace falta para auditar es el nombre del parámetro, no su valor.
CLAVE_SENSIBLE = re.compile(
    r"(pass|clave|contrase|secret|token|auth|cookie|session|sesion|otp|mfa|"
    r"pin|cvv|cvc|tarjeta|card|iban|dni|nif|ssn|apikey|api_key|private)", re.I
)
TACHADO = "***"
# Un cuerpo más largo que esto no se guarda entero: no aporta más superficie y
# engorda la base de datos y el informe.
CUERPO_MAXIMO = 4096


def _tachar(valor: Any) -> Any:
    if isinstance(valor, dict):
        return {k: (TACHADO if CLAVE_SENSIBLE.search(str(k)) else _tachar(v))
                for k, v in valor.items()}
    if isinstance(valor, list):
        return [_tachar(v) for v in valor]
    return valor


# Hasta dónde se baja en un cuerpo anidado, y cuántos campos se apuntan. Un
# JSON de tres niveles con listas dentro da cientos de rutas, y a partir de un
# punto dejan de ser superficie y pasan a ser ruido.
PROFUNDIDAD_MAXIMA = 3
CAMPOS_MAXIMOS = 60


def claves_planas(valor: Any, prefijo: str = "", profundidad: int = 0) -> list[str]:
    """Los campos de un cuerpo, con su camino: `filtro.cliente`, `lineas[].sku`.

    Un `{"filtro": {"cliente": "…"}}` tiene un campo, no cero, y contarlo como
    uno solo —el de primer nivel— decía que esa llamada tenía un parámetro
    cuando en realidad el que importa está dentro.
    """
    if profundidad > PROFUNDIDAD_MAXIMA:
        return []
    claves: list[str] = []
    if isinstance(valor, dict):
        for nombre, dentro in valor.items():
            camino = f"{prefijo}.{nombre}" if prefijo else str(nombre)
            claves.append(camino)
            claves.extend(claves_planas(dentro, camino, profundidad + 1))
    elif isinstance(valor, list) and valor:
        # De una lista se mira el primer elemento: en una API los demás tienen
        # la misma forma.
        claves.extend(claves_planas(valor[0], f"{prefijo}[]", profundidad + 1))
    return claves[:CAMPOS_MAXIMOS]


def leer_cuerpo(cuerpo: str, tipo_contenido: str) -> tuple[list[str], str]:
    """Las claves que lleva un cuerpo de petición, y el cuerpo ya tachado.

    Devuelve `([], "")` para lo que no se puede leer como parámetros: una
    subida de ficheros, un cuerpo binario, un JSON mal formado. Decirlo con una
    lista vacía, y no inventar parámetros, importa: lo que entra aquí decide
    dónde van a inyectar las fases activas.
    """
    cuerpo = (cuerpo or "").strip()
    tipo = (tipo_contenido or "").lower()
    if not cuerpo or "multipart/" in tipo or "octet-stream" in tipo:
        return [], ""
    if len(cuerpo) > CUERPO_MAXIMO:
        return [], ""

    if "json" in tipo or cuerpo.startswith(("{", "[")):
        try:
            datos = json.loads(cuerpo)
        except ValueError:
            return [], ""
        claves = claves_planas(datos) if isinstance(datos, (dict, list)) else []
        return claves, json.dumps(_tachar(datos), ensure_ascii=False)

    if "x-www-form-urlencoded" in tipo or ("=" in cuerpo and "\n" not in cuerpo):
        pares = parse_qsl(cuerpo, keep_blank_values=True)
        if not pares:
            return [], ""
        return (
            [k for k, _ in pares],
            urlencode([(k, TACHADO if CLAVE_SENSIBLE.search(k) else v) for k, v in pares]),
        )

    return [], ""


@dataclass(slots=True)
class Endpoint:
    """Una ruta alcanzable, con los parámetros que admite.

    En una aplicación con interfaz, los parámetros van en la query y en los
    campos de un formulario. En la API que hay por debajo no: van en el cuerpo
    de un POST, casi siempre en JSON. Guardar solo la URL dejaba fuera justo la
    superficie donde más se inyecta, así que el endpoint lleva también el método
    real, el tipo de contenido y un cuerpo de ejemplo —el que mandó la propia
    aplicación, o uno construido a partir de la especificación—.
    """

    url: str
    metodo: str = "GET"
    params: list[str] = field(default_factory=list)
    # semilla | enlace | formulario | js | api | especificacion
    origen: str = "enlace"
    tipo_contenido: str = ""
    # Cuerpo tal como lo manda la aplicación, y las claves que lleva dentro.
    cuerpo: str = ""
    params_cuerpo: list[str] = field(default_factory=list)

    @property
    def clave(self) -> tuple[str, str, tuple[str, ...]]:
        partes = urlsplit(self.url)
        return (
            self.metodo,
            urlunsplit((partes.scheme, partes.netloc, partes.path, "", "")),
            tuple(sorted([*self.params, *self.params_cuerpo])),
        )

    @property
    def es_api(self) -> bool:
        """¿Esto lo llama el JavaScript o la especificación, no un enlace?"""
        return self.origen in ("js", "api", "especificacion")


@dataclass(slots=True)
class ResultadoCrawl:
    endpoints: list[Endpoint] = field(default_factory=list)
    formularios: list[dict[str, Any]] = field(default_factory=list)
    # Peticiones que el navegador hizo fuera del alcance. No es un detalle
    # técnico: una aplicación interna que carga un script de fuera es un
    # hallazgo por sí misma.
    fuera_de_alcance: list[str] = field(default_factory=list)
    paginas_visitadas: int = 0
    sesion: Sesion | None = None
    reautenticaciones: int = 0
    # Si la sesión se cayó y no se pudo recuperar: por qué. El recorrido se para
    # ahí; seguir daría un mapa de la aplicación vista como anónimo.
    sesion_perdida: str = ""
    # Proveedores de identidad en los que acabó el navegador. Sin sesión, es la
    # señal de que la aplicación exige entrar aunque lo haga con JavaScript,
    # donde el probador no ve ninguna redirección.
    proveedores_vistos: list[str] = field(default_factory=list)

    @property
    def urls(self) -> list[str]:
        return list(dict.fromkeys(e.url for e in self.endpoints))

    @property
    def api(self) -> list[Endpoint]:
        """Lo que no es navegación: las llamadas de la API."""
        return [e for e in self.endpoints if e.es_api]

    @property
    def con_parametros(self) -> list[Endpoint]:
        """Los que sirven para fuzzing: sin parámetros no hay dónde inyectar.

        Un POST a la API sin query pero con cuerpo JSON tiene dónde inyectar, y
        antes no entraba aquí: las fases activas lo saltaban por no llevar nada
        en la URL.
        """
        return [e for e in self.endpoints if e.params or e.params_cuerpo]


def nuevo_navegador(headless: bool = True, *, extra: Sequence[str] = (),
                    registrar_red: bool = False):
    """Chromium con toda la red de fondo apagada.

    `extra` añade argumentos —el login los usa para congelar el DNS—, y
    `registrar_red` activa el registro de rendimiento, que es de donde se lee
    la cabecera Authorization que manda una SPA.
    """
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    from selenium.webdriver.chrome.service import Service

    opciones = Options()
    opciones.binary_location = "/usr/bin/chromium"
    if headless:
        opciones.add_argument("--headless=new")
    for argumento in (*CHROMIUM_ARGS, "--no-sandbox", "--disable-dev-shm-usage",
                      "--window-size=1440,900", *extra):
        opciones.add_argument(argumento)
    # Sin imágenes: no aportan al análisis y multiplican el tráfico.
    opciones.add_experimental_option(
        "prefs", {"profile.managed_default_content_settings.images": 2}
    )
    if registrar_red:
        opciones.set_capability("goog:loggingPrefs", {"performance": "ALL"})
    return webdriver.Chrome(service=Service("/usr/bin/chromedriver"), options=opciones)


class Crawler:
    def __init__(self, scope: Scope, policy: Policy, *, sesion: Sesion | None = None,
                 reentrar: Callable[[], Sesion | None] | None = None) -> None:
        """`sesion` llega hecha: el login es de la fase 0, no del crawler.

        `reentrar` la renueva si se cae a mitad. Devuelve `None` si no se puede,
        y entonces el recorrido se detiene en lugar de seguir como anónimo.
        """
        self.scope = scope
        self.policy = policy
        self.reentrar = reentrar
        self.resultado = ResultadoCrawl(sesion=sesion)
        self.red: Any = None

    # -- recorrido ----------------------------------------------------------
    def recorrer(self, semillas: Sequence[str]) -> ResultadoCrawl:
        # Con el registro de red activado: es de donde salen el método y el
        # cuerpo de cada llamada a la API. La API de rendimiento, que es lo que
        # se usaba antes, enumera las peticiones pero no dice ni una cosa ni la
        # otra, así que un POST con JSON se apuntaba como un GET sin parámetros.
        driver = nuevo_navegador(registrar_red=True)
        self.red = RegistroDeRed(driver)
        try:
            driver.set_page_load_timeout(max(self.policy.request_timeout, 15))
            if self.resultado.sesion is not None:
                self.resultado.sesion.aplicar_a_navegador(
                    driver, next(iter(semillas), ""))
            self._recorrer_con(driver, semillas)
        finally:
            with contextlib.suppress(Exception):
                driver.quit()
        return self.resultado

    def _recorrer_con(self, driver, semillas: Sequence[str]) -> None:
        vistos: set[tuple] = set()
        pendientes: list[tuple[str, int]] = [
            (u, 0) for u in semillas if self.scope.allows_url(u)
        ]
        for url in semillas:
            self._anotar(Endpoint(url=url, origen="semilla",
                                  params=[k for k, _ in parse_qsl(urlsplit(url).query)]))

        while (pendientes and not self.resultado.sesion_perdida
               and self.resultado.paginas_visitadas < self.policy.crawl_max_pages):
            url, profundidad = pendientes.pop(0)
            if profundidad > self.policy.crawl_max_depth:
                continue
            clave = Endpoint(url=url).clave
            if clave in vistos:
                continue
            vistos.add(clave)

            if not self._navegar(driver, url):
                continue
            self.resultado.paginas_visitadas += 1

            self._auditar_peticiones(driver)
            for endpoint in self._extraer(driver, url):
                if self._anotar(endpoint) and endpoint.metodo == "GET":
                    pendientes.append((endpoint.url, profundidad + 1))

    def _navegar(self, driver, url: str) -> bool:
        if not self.scope.allows_url(url):
            return False
        try:
            driver.get(url)
        except Exception:
            return False
        # Si la sesión se ha caído, se vuelve a entrar y se repite la página:
        # seguir recorriendo como anónimo daría un mapa falso de la aplicación.
        if self.resultado.sesion is not None and self._desconectado(driver):
            nueva = self.reentrar() if self.reentrar is not None else None
            if nueva is None:
                self.resultado.sesion_perdida = (
                    f"la sesión se perdió en {url} y no se pudo volver a entrar; el "
                    "recorrido se detuvo ahí")
                return False
            self.resultado.reautenticaciones += 1
            self.resultado.sesion = nueva
            nueva.aplicar_a_navegador(driver, url)
            with contextlib.suppress(Exception):
                driver.get(url)
        return True

    def _desconectado(self, driver) -> bool:
        """¿Esta página dice que ya no hay sesión?

        Con un proveedor de identidad la señal es inequívoca: el navegador ha
        acabado en él. Sin proveedor queda la heurística de siempre.
        """
        if self.scope.es_proveedor(driver.current_url):
            return True
        if not parece_desconectado(driver.current_url, driver.page_source):
            return False
        # La heurística solo levanta la sospecha: una ruta que se llama /login
        # la dispara aunque se visite con la sesión intacta, y volvía a entrar
        # sin motivo. Si la sesión está verificada, lo decide una petición.
        viva = sigue_viva(self.resultado.sesion, self.scope)
        return viva is not True

    def _auditar_peticiones(self, driver) -> None:
        """Qué pidió el navegador por su cuenta.

        Doble uso: descubre endpoints de la API que sólo invoca el JavaScript,
        y delata recursos cargados desde fuera del alcance.

        Se espera a que la página se asiente antes de leer: los `fetch` del
        bundle salen después del evento de carga, y leer de inmediato devolvía
        la lista sin ellos —que es justo lo que esta función existe para ver—.
        """
        self._esperar_asiento(driver)
        # Los recursos de una página que no es de la aplicación no son
        # dependencias de la aplicación. Pasaba al visitar como anónimo una
        # aplicación con SSO: la redirección dejaba al navegador en la página
        # de acceso de Keycloak, y sus hojas de estilo salían como «la
        # aplicación carga recursos de fuera».
        if not self.scope.allows_url(driver.current_url):
            actual = driver.current_url
            if self.scope.es_proveedor(actual) or parece_proveedor(actual):
                host = urlsplit(actual).hostname or ""
                if host and host not in self.resultado.proveedores_vistos:
                    self.resultado.proveedores_vistos.append(host)
            return
        # Primero el registro de red, que trae método y cuerpo. Lo que salga de
        # ahí no se vuelve a apuntar desde la API de rendimiento, que lo daría
        # como un GET sin parámetros y dejaría un endpoint falso en el informe.
        ya_apuntadas = self._api_del_registro()

        try:
            recursos = driver.execute_script(
                "return performance.getEntriesByType('resource')"
                ".map(r => [r.name, r.initiatorType])"
            ) or []
        except Exception:
            return

        for nombre, iniciador in recursos:
            if not isinstance(nombre, str) or not nombre.startswith(("http://", "https://")):
                continue
            if not self.scope.allows_url(nombre):
                # Hablar con el propio proveedor de identidad —el iframe con el
                # que keycloak-js comprueba la sesión, el canje del token de una
                # SPA— es el protocolo de acceso, no una dependencia de fuera.
                if self.scope.es_proveedor(nombre) or parece_proveedor(nombre):
                    continue
                if nombre not in self.resultado.fuera_de_alcance:
                    self.resultado.fuera_de_alcance.append(nombre)
                continue
            if RUIDO.search(nombre):
                continue
            if iniciador in ("fetch", "xmlhttprequest") and nombre not in ya_apuntadas:
                partes = urlsplit(nombre)
                self._anotar(Endpoint(
                    url=nombre, origen="js",
                    params=[k for k, _ in parse_qsl(partes.query)],
                ))

    def _api_del_registro(self) -> set[str]:
        """Las llamadas a la API que hizo la página, con método y cuerpo.

        Es la diferencia entre ver que la aplicación habla con `/api/pedidos` y
        poder auditarla: el método real —un POST, un PUT, un DELETE— y los
        parámetros que van en el cuerpo, que en una API REST son casi todos.

        Devuelve las URL apuntadas, para que la lectura de la API de
        rendimiento no las duplique con el método equivocado.

        Chromium no incluye el cuerpo cuando es muy grande. Entonces el
        endpoint queda con su método y sin parámetros de cuerpo, que es la
        verdad: se sabe que hay un POST ahí, no qué lleva dentro.
        """
        vistas: set[str] = set()
        if self.red is None:
            return vistas
        with contextlib.suppress(Exception):
            self.red.leer()
        peticiones = self.red.recoger()

        for p in peticiones:
            url = p.get("url") or ""
            if not url.startswith(("http://", "https://")):
                continue
            if (p.get("tipo") or "").lower() not in TIPOS_DE_API:
                continue
            if not self.scope.allows_url(url):
                # Igual que con los recursos: hablar con el proveedor de
                # identidad es el protocolo de acceso, no una dependencia.
                if self.scope.es_proveedor(url) or parece_proveedor(url):
                    continue
                if url not in self.resultado.fuera_de_alcance:
                    self.resultado.fuera_de_alcance.append(url)
                continue

            tipo = (p.get("cabeceras") or {}).get("content-type", "")
            claves, cuerpo = leer_cuerpo(p.get("cuerpo", ""), tipo)
            self._anotar(Endpoint(
                url=url,
                metodo=(p.get("metodo") or "GET").upper(),
                params=[k for k, _ in parse_qsl(urlsplit(url).query)],
                origen="api",
                tipo_contenido=tipo.split(";")[0].strip(),
                cuerpo=cuerpo,
                params_cuerpo=claves,
            ))
            vistas.add(url)
        return vistas

    def _esperar_asiento(self, driver, intentos: int = 6) -> None:
        """Espera hasta que el número de peticiones deje de crecer."""
        import time

        anterior = -1
        for _ in range(intentos):
            try:
                actual = driver.execute_script(
                    "return performance.getEntriesByType('resource').length"
                )
            except Exception:
                return
            if actual == anterior:
                return
            anterior = actual
            time.sleep(0.25)

    def _extraer(self, driver, base: str) -> Iterable[Endpoint]:
        """Enlaces y formularios de la página ya renderizada."""
        from selenium.webdriver.common.by import By

        with contextlib.suppress(Exception):
            for ancla in driver.find_elements(By.CSS_SELECTOR, "a[href]"):
                href = ancla.get_attribute("href") or ""
                if not href or href.startswith(("javascript:", "mailto:", "tel:", "#")):
                    continue
                absoluta = urljoin(base, href)
                if RUIDO.search(absoluta) or PELIGROSOS.search(absoluta):
                    continue
                if not self.scope.allows_url(absoluta):
                    continue
                yield Endpoint(
                    url=absoluta, origen="enlace",
                    params=[k for k, _ in parse_qsl(urlsplit(absoluta).query)],
                )

        with contextlib.suppress(Exception):
            for formulario in driver.find_elements(By.TAG_NAME, "form"):
                accion = urljoin(base, formulario.get_attribute("action") or base)
                metodo = (formulario.get_attribute("method") or "GET").upper()
                if not self.scope.allows_url(accion):
                    continue
                campos = []
                for entrada in formulario.find_elements(
                    By.CSS_SELECTOR, "input[name], textarea[name], select[name]"
                ):
                    nombre = entrada.get_attribute("name")
                    if nombre:
                        campos.append(nombre)
                self.resultado.formularios.append(
                    {"accion": accion, "metodo": metodo, "campos": campos}
                )
                yield Endpoint(url=accion, metodo=metodo, params=campos, origen="formulario")

    def _anotar(self, endpoint: Endpoint) -> bool:
        """Registra el endpoint si es nuevo. Devuelve si lo era."""
        existentes = {e.clave for e in self.resultado.endpoints}
        if endpoint.clave in existentes:
            return False
        self.resultado.endpoints.append(endpoint)
        return True
