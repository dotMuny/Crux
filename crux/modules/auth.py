"""Autenticación contra la aplicación auditada.

Cubre tres modos: formulario, token o JWT en cabecera, y una sesión capturada a
mano (cookies). El formulario no tiene por qué estar en la aplicación: lo
habitual en una intranet es que la aplicación mande al navegador a un Keycloak,
un ADFS o similar, que pida ahí la clave y devuelva a la aplicación con la
sesión hecha. Crux lo recorre con un navegador real, así que sirve cualquier
proveedor que termine en un formulario de usuario y contraseña.

Lo que no puede hacer solo, y dice con su nombre cuando lo encuentra: un
segundo factor (OTP), una acción obligatoria pendiente en el proveedor
—cambiar la clave, aceptar condiciones— y Kerberos. Para esos está el modo de
cookies.

Tres reglas que este módulo sigue, aprendidas porque se incumplían:

1. **Un login fallido lo dice, y dice por qué.** Antes devolvía «no
   autenticada» sin motivo, el escaneo seguía como anónimo y el informe salía
   igual que sin credenciales, sin que nada avisara.
2. **Cada login, en un navegador limpio.** Un proveedor con SSO deja su propia
   cookie de sesión; con el mismo navegador, el segundo rol entraba como el
   primero sin ver el formulario, y la comparación de permisos salía limpia.
3. **La sesión se comprueba fuera del navegador.** Lo que importa es que las
   herramientas la puedan usar. Si la aplicación guarda el token donde no se
   puede reutilizar, se dice antes de escanear, no después.

Una sesión es un objeto de datos —cookies y cabeceras— que se aplica tanto a un
navegador como a un cliente HTTP. Nunca se escribe a disco ni se devuelve por
la API: lo que sale del proceso es su `describe()`, sin valores.
"""

from __future__ import annotations

import contextlib
import json
import re
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Iterable
from urllib.parse import urlsplit

if TYPE_CHECKING:
    from ..core.scope import Scope

# Nombres de campo habituales, ordenados de más a menos específico. Sirven para
# rellenar un formulario de acceso sin que el operador tenga que dar selectores.
CAMPOS_USUARIO = ("username", "user", "usuario", "login", "email", "correo",
                  "j_username", "UserName", "loginfmt")
CAMPOS_CLAVE = ("password", "passwd", "pass", "clave", "contrasena", "contraseña",
                "j_password", "Password", "passwordInput")

# Señales de que la sesión se ha perdido y hay que volver a entrar.
SENALES_DE_SALIDA = ("iniciar sesión", "iniciar sesion", "sign in", "log in", "acceder",
                     "authentication required", "/login", "/signin")

# Cómo dice un proveedor que algo fue mal. Tema keycloak.v2, el clásico de
# Keycloak, ADFS y genéricos. Se leen los VISIBLES: los formularios suelen
# llevar el contenedor del error siempre presente y vacío.
SELECTORES_DE_ERROR = (
    "[id^='input-error']", "#input-error", ".kc-feedback-text", ".alert-error",
    ".pf-m-danger", ".pf-v5-c-helper-text__item.pf-m-error", "#errorText",
    "#error", ".error-message", "[role='alert']",
)
# Un segundo factor. No se puede completar sin una persona.
SELECTORES_OTP = (
    "#otp", "input[name='otp']", "input[name='totp']",
    "input[autocomplete='one-time-code']", "#kc-otp-login-form",
)
# Acciones obligatorias que el proveedor exige antes de dejar entrar.
ACCIONES_OBLIGATORIAS = {
    "#kc-passwd-update-form": "cambiar la contraseña",
    "input[name='password-new']": "cambiar la contraseña",
    "#kc-update-profile-form": "completar el perfil",
    "#kc-update-email-form": "verificar el correo",
    "#kc-terms-text": "aceptar las condiciones de uso",
    "#kc-totp-settings": "configurar un segundo factor",
}

ESPERA_FORMULARIO = 20.0     # segundos hasta que aparezca el formulario
ESPERA_RESULTADO = 25.0      # segundos hasta volver a la aplicación
ESPERA_TOKEN = 5.0           # segundos para que una SPA haga su primera llamada
INSISTENCIA = 6.0            # segundos con la contraseña aún en pantalla = rechazo


class AutenticacionFallida(RuntimeError):
    """No se pudo entrar. El mensaje dice por qué y qué hacer."""


@dataclass(slots=True)
class Credenciales:
    """Cómo entrar. Solo uno de los tres modos se usa a la vez."""

    # Formulario
    url_login: str | None = None
    usuario: str | None = None
    clave: str | None = None
    selector_usuario: str | None = None      # CSS, si la heurística no acierta
    selector_clave: str | None = None
    selector_enviar: str | None = None
    # Dónde está el formulario cuando no es la propia aplicación: un Keycloak,
    # un ADFS. Casi siempre se descubre solo siguiendo la redirección; hace
    # falta declararlo cuando la redirección la hace JavaScript.
    proveedor_identidad: str | None = None

    # Token en cabecera
    cabeceras: dict[str, str] = field(default_factory=dict)

    # Sesión capturada a mano (el escape para OTP y Kerberos)
    cookies: dict[str, str] = field(default_factory=dict)

    # Texto que debe aparecer en la página para dar el acceso por bueno.
    senal_de_exito: str | None = None

    @property
    def modo(self) -> str:
        if self.url_login and self.usuario:
            return "formulario"
        if self.cabeceras:
            return "cabecera"
        if self.cookies:
            return "cookies"
        return "ninguno"


@dataclass(slots=True)
class Sesion:
    """Una sesión, viva o no, aplicable a un navegador o a un cliente HTTP."""

    nombre: str = "anónima"
    rol: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    cabeceras: dict[str, str] = field(default_factory=dict)
    autenticada: bool = False
    # Cookies que el navegador ya tenía antes de entrar. Sin esta foto no se
    # puede saber si el identificador de sesión se renovó al autenticarse.
    cookies_previas: dict[str, str] = field(default_factory=dict)
    # Por qué no se entró, en castellano y con qué hacer. Vacío si se entró.
    motivo: str = ""
    # Host del proveedor de identidad por el que pasó el login, si pasó.
    proveedor: str = ""
    # Todas las cookies del navegador, con dominio, para trasladar la sesión a
    # otro navegador: el del crawler. Incluye las del proveedor, que es lo que
    # permite a una SPA volver a entrar sola sin pasar por el formulario.
    cookies_navegador: list[dict[str, Any]] = field(default_factory=list)
    # Dónde comprobar que la sesión sigue viva, y qué se vio al comprobarlo.
    url_prueba: str = ""
    comprobacion: dict[str, Any] = field(default_factory=dict)
    # Se confirmó con peticiones fuera del navegador: con la sesión se entra y
    # sin ella no. Sin esto no se puede vigilar si caduca a mitad de escaneo.
    verificada: bool = False

    def aplicar_a_httpx(self) -> dict[str, Any]:
        return {"cookies": dict(self.cookies), "headers": dict(self.cabeceras)}

    def aplicar_a_navegador(self, driver, dominio_url: str = "") -> None:
        """Lleva la sesión a un navegador.

        Por el protocolo de depuración y no por `add_cookie`, que solo admite
        cookies del dominio en el que el navegador está en ese momento: las del
        proveedor de identidad no se podrían poner sin visitarlo.
        """
        cookies = self.cookies_navegador or [
            {"name": n, "value": v, "domain": urlsplit(dominio_url).hostname or "",
             "path": "/"}
            for n, v in self.cookies.items()
        ]
        for c in cookies:
            parametros = {k: c[k] for k in ("name", "value", "domain", "path",
                                            "secure", "httpOnly", "sameSite")
                          if c.get(k) not in (None, "")}
            with contextlib.suppress(Exception):
                driver.execute_cdp_cmd("Network.setCookie", parametros)

    def describe(self) -> dict[str, Any]:
        """Lo que se puede contar de la sesión. Nombres, nunca valores."""
        return {
            "nombre": self.nombre,
            "rol": self.rol,
            "autenticada": self.autenticada,
            "verificada": self.verificada,
            "proveedor": self.proveedor,
            "motivo": self.motivo,
            "cookies": sorted(self.cookies),
            "cabeceras": sorted(self.cabeceras),
            "comprobacion": self.comprobacion,
        }


# ── El login en un navegador ────────────────────────────────────────────────
class _Falla(Exception):
    """Interrumpe el login con un motivo. Interna: fuera se ve como `Sesion.motivo`."""


class _Red:
    """Lo que el navegador pidió, leído de su registro de rendimiento.

    `get_log` vacía el registro cada vez que se lee, así que se acumula aquí.
    Si el navegador no se creó con el registro activado, todo esto devuelve
    vacío y el login sigue funcionando: solo se pierde la captura de tokens.
    """

    def __init__(self, driver) -> None:
        self.driver = driver
        self.peticiones: list[dict[str, Any]] = []

    def leer(self) -> int:
        try:
            entradas = self.driver.get_log("performance")
        except Exception:
            return 0
        nuevas = 0
        for entrada in entradas:
            try:
                mensaje = json.loads(entrada["message"])["message"]
            except (KeyError, ValueError):
                continue
            if mensaje.get("method") not in ("Network.requestWillBeSent",
                                             "Network.requestWillBeSentExtraInfo"):
                continue
            p = mensaje.get("params", {})
            peticion = p.get("request", {})
            cabeceras = peticion.get("headers") or p.get("headers") or {}
            self.peticiones.append({
                "id": p.get("requestId"), "url": peticion.get("url", ""),
                "metodo": peticion.get("method", ""), "tipo": p.get("type", ""),
                "cabeceras": {k.lower(): v for k, v in cabeceras.items()},
                # El cuerpo es lo que hace falta para auditar una API: en un
                # POST a /api/… los parámetros van ahí, no en la URL. Chromium
                # lo da en `postData` cuando no es demasiado grande.
                "cuerpo": peticion.get("postData") or "",
                "tiene_cuerpo": bool(peticion.get("hasPostData")),
            })
            nuevas += 1
        return nuevas

    def urls_de(self, requestId: str) -> str:
        for p in self.peticiones:
            if p["id"] == requestId and p["url"]:
                return p["url"]
        return ""

    def documentos(self) -> list[str]:
        return [p["url"] for p in self.peticiones if p["tipo"] == "Document" and p["url"]]

    def recoger(self) -> list[dict[str, Any]]:
        """Devuelve lo registrado hasta ahora y lo suelta.

        Para quien lee por tandas —el crawler, una vez por página—: así sabe
        qué es nuevo y no acumula. El login, en cambio, mira `peticiones`
        entera, porque busca una cabecera que pudo aparecer en cualquier salto.
        Un recorrido de tres mil páginas guardaría cientos de miles de
        peticiones con sus cabeceras sin que nadie vuelva a mirarlas.
        """
        peticiones, self.peticiones = self.peticiones, []
        return peticiones


# El mismo lector lo usan el login —para la cabecera Authorization de una SPA—
# y el crawler —para el método y el cuerpo de cada llamada a la API—.
RegistroDeRed = _Red


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _visibles(driver, css: str) -> list:
    from selenium.webdriver.common.by import By

    vistos = []
    with contextlib.suppress(Exception):
        for e in driver.find_elements(By.CSS_SELECTOR, css):
            with contextlib.suppress(Exception):
                if e.is_displayed():
                    vistos.append(e)
    return vistos


def _buscar_campo(driver, nombres: Iterable[str], tipo: str | None = None):
    """Un campo VISIBLE por nombre, id, autocompletado o tipo, en ese orden."""
    for nombre in nombres:
        for css in (f"input[name='{nombre}']", f"input[id='{nombre}']"):
            vistos = _visibles(driver, css)
            if vistos:
                return vistos[0]
    if tipo == "password":
        vistos = _visibles(driver, "input[type='password']")
        return vistos[0] if vistos else None
    if tipo == "text":
        for css in ("input[autocomplete='username']", "input[type='email']",
                    "input[type='text']"):
            vistos = _visibles(driver, css)
            if vistos:
                return vistos[0]
    return None


def _campo_clave(driver, credenciales: Credenciales):
    if credenciales.selector_clave:
        vistos = _visibles(driver, credenciales.selector_clave)
        return vistos[0] if vistos else None
    return _buscar_campo(driver, CAMPOS_CLAVE, "password")


def _campo_usuario(driver, credenciales: Credenciales):
    if credenciales.selector_usuario:
        vistos = _visibles(driver, credenciales.selector_usuario)
        return vistos[0] if vistos else None
    return _buscar_campo(driver, CAMPOS_USUARIO, "text")


def _enviar(driver, credenciales: Credenciales, campo) -> None:
    """Pulsa el botón de envío, como haría una persona.

    Pulsar y no `form.submit()`: algunos proveedores leen el nombre del botón
    pulsado, y `submit()` además se salta los `onsubmit` que ponen el
    formulario en estado «enviando».
    """
    from selenium.webdriver.common.by import By
    from selenium.webdriver.common.keys import Keys

    if credenciales.selector_enviar:
        vistos = _visibles(driver, credenciales.selector_enviar)
        if not vistos:
            raise _Falla(f"no se encontró el botón de envío «{credenciales.selector_enviar}»")
        vistos[0].click()
        return
    formulario = None
    with contextlib.suppress(Exception):
        formulario = campo.find_element(By.XPATH, "./ancestor::form[1]")
    if formulario is not None:
        for css in ("#kc-login", "button[type='submit']", "input[type='submit']",
                    "button:not([type])"):
            botones = [b for b in formulario.find_elements(By.CSS_SELECTOR, css)
                       if b.is_displayed()]
            if botones:
                botones[0].click()
                return
        driver.execute_script(
            "arguments[0].requestSubmit ? arguments[0].requestSubmit()"
            " : arguments[0].submit()", formulario)
        return
    campo.send_keys(Keys.ENTER)


def _texto_de_error(driver) -> str:
    for css in SELECTORES_DE_ERROR:
        for e in _visibles(driver, css):
            with contextlib.suppress(Exception):
                texto = " ".join(e.text.split())
                if texto:
                    return texto[:200]
    return ""


def _comprobar_destino(driver, red: _Red, scope: Scope | None) -> str:
    """El host actual, si se puede estar en él. Si no, la falla que toca."""
    url = driver.current_url or ""
    if url.startswith("chrome-error://") or "ERR_NAME_NOT_RESOLVED" in _fuente(driver)[:3000]:
        red.leer()
        documentos = red.documentos()
        destino = _host(documentos[-1]) if documentos else _host(url)
        if scope is not None and destino and not scope.permite_para_entrar(f"http://{destino}/"):
            raise _Falla(_fuera_de_alcance(destino))
        raise _Falla(f"el navegador no pudo cargar {destino or url}: no responde o su "
                     "nombre no se resuelve")
    host = _host(url)
    if scope is not None and host and not scope.permite_para_entrar(url):
        raise _Falla(_fuera_de_alcance(host))
    return host


def _fuera_de_alcance(host: str) -> str:
    return (f"el acceso lleva a {host}, que no está en el alcance ni declarado como "
            "proveedor de identidad. Si es tu Keycloak o tu ADFS, decláralo en "
            "«Proveedor de identidad»; si es otra aplicación, añádela a los objetivos")


def _fuente(driver) -> str:
    try:
        return driver.page_source or ""
    except Exception:
        return ""


def _bloqueos(driver) -> None:
    """Lo que ningún automatismo puede atravesar, dicho con su nombre."""
    if any(_visibles(driver, css) for css in SELECTORES_OTP):
        raise _Falla(
            "el proveedor pide un segundo factor (un código de un solo uso). Crux no "
            "puede completarlo: entra a mano y usa el modo «Cookies» con la sesión "
            "capturada, o pide un usuario de auditoría sin segundo factor")
    for css, que in ACCIONES_OBLIGATORIAS.items():
        if _visibles(driver, css):
            raise _Falla(
                f"el proveedor exige {que} antes de dejar entrar a este usuario. "
                "Entra una vez a mano, complétalo y vuelve a lanzar el escaneo")
    fuente = _fuente(driver).lower()
    if "cookie not found" in fuente or "cookies are enabled" in fuente:
        raise _Falla(
            "el proveedor no recibió su propia cookie («Cookie not found»). Suele "
            "pasar cuando la URL de acceso salta directamente al formulario del "
            "proveedor: usa como URL de acceso la de la aplicación y deja que "
            "redirija ella")


def _esperar_formulario(driver, red, scope, credenciales):
    """Hasta que haya un campo de clave. O uno de usuario solo, en dos pasos."""
    limite = time.monotonic() + ESPERA_FORMULARIO
    usuario = None
    while time.monotonic() < limite:
        _comprobar_destino(driver, red, scope)
        _bloqueos(driver)
        clave = _campo_clave(driver, credenciales)
        usuario = _campo_usuario(driver, credenciales)
        if clave is not None:
            return usuario, clave
        time.sleep(0.25)
    if usuario is not None:
        return usuario, None
    raise _Falla(
        f"no apareció ningún formulario de acceso en {driver.current_url} en "
        f"{ESPERA_FORMULARIO:.0f} s. Si los campos tienen nombres poco habituales, "
        "indica sus selectores")


def _ir(driver, url: str, red: _Red, scope: Scope | None) -> None:
    """`driver.get`, con los fallos de red traducidos a lo que significan.

    Con el DNS congelado, una redirección a un host no declarado no llega a
    salir: Chromium falla al resolverlo y WebDriver lo lanza como excepción.
    Aquí se convierte en el motivo que el operador necesita leer.
    """
    from selenium.common.exceptions import WebDriverException

    try:
        driver.get(url)
    except WebDriverException as exc:
        texto = str(exc)
        if "net::ERR_" not in texto:
            raise
        red.leer()
        documentos = red.documentos()
        destino = _host(documentos[-1]) if documentos else _host(url)
        if scope is not None and destino and not scope.permite_para_entrar(f"http://{destino}/"):
            raise _Falla(_fuera_de_alcance(destino)) from None
        error = texto.split("net::", 1)[1].split()[0]
        raise _Falla(f"el navegador no pudo cargar {destino or url} ({error})") from None


def _escribir(campo, texto: str) -> None:
    campo.clear()
    campo.send_keys(texto)


def _esperar_resultado(driver, red, scope, credenciales, host_formulario: str) -> None:
    """Hasta volver a la aplicación con la sesión hecha, o hasta saber por qué no."""
    limite = time.monotonic() + ESPERA_RESULTADO
    clave_visible_desde: float | None = None
    while time.monotonic() < limite:
        host = _comprobar_destino(driver, red, scope)
        _bloqueos(driver)
        clave = _campo_clave(driver, credenciales)
        error = _texto_de_error(driver)
        if clave is not None and error:
            raise _Falla(f"el proveedor rechazó las credenciales: «{error}»")

        en_la_aplicacion = (scope.allows_url(driver.current_url) if scope is not None
                            else host == host_formulario or not host_formulario)
        if en_la_aplicacion and clave is None:
            if not credenciales.senal_de_exito:
                return
            if credenciales.senal_de_exito in _fuente(driver):
                return

        if clave is not None:
            clave_visible_desde = clave_visible_desde or time.monotonic()
            if time.monotonic() - clave_visible_desde > INSISTENCIA:
                raise _Falla(
                    "tras enviar el formulario se sigue pidiendo la contraseña. "
                    "Revisa el usuario y la clave" + (f": «{error}»" if error else ""))
        else:
            clave_visible_desde = None
        time.sleep(0.25)

    if credenciales.senal_de_exito and scope is not None and scope.allows_url(driver.current_url):
        raise _Falla(f"se volvió a la aplicación, pero no aparece «{credenciales.senal_de_exito}», "
                     "la señal de que se ha entrado")
    raise _Falla(f"en {ESPERA_RESULTADO:.0f} s el navegador no volvió a la aplicación: "
                 f"sigue en {driver.current_url}")


def _todas_las_cookies(driver) -> list[dict[str, Any]]:
    with contextlib.suppress(Exception):
        return driver.execute_cdp_cmd("Network.getAllCookies", {}).get("cookies", [])
    # Sin protocolo de depuración: al menos las del dominio actual.
    return [dict(c, domain=c.get("domain", "")) for c in driver.get_cookies()]


def _del_dominio(cookie: dict[str, Any], hosts: Iterable[str]) -> bool:
    dominio = (cookie.get("domain") or "").lstrip(".").lower()
    return any(h == dominio or h.endswith("." + dominio) for h in hosts if h)


def _hosts_auditables(scope: Scope | None, driver) -> list[str]:
    if scope is not None:
        return [h.lower() for h in scope.hosts] + [
            e.raw for e in scope.entries if e.kind == "ip"]
    return [_host(driver.current_url)]


def _capturar_token(red: _Red, scope: Scope | None, hosts: list[str]) -> tuple[str, str]:
    """La última cabecera Authorization que el navegador mandó a la aplicación.

    Es donde vive la sesión de una SPA: el token se canjea en el navegador, se
    guarda en memoria o en `sessionStorage`, y ninguna cookie lo lleva. Se
    devuelve también la URL donde se usó: es la mejor para comprobar que vale.
    """
    limite = time.monotonic() + ESPERA_TOKEN
    ultima_novedad = time.monotonic()
    while time.monotonic() < limite:
        if red.leer():
            ultima_novedad = time.monotonic()
        for p in reversed(red.peticiones):
            autorizacion = p["cabeceras"].get("authorization", "")
            url = p["url"] or red.urls_de(p["id"])
            if not autorizacion or not url:
                continue
            permitido = scope.allows_url(url) if scope is not None else _host(url) in hosts
            if permitido:
                return autorizacion, url if p["metodo"] in ("", "GET") else ""
        # Ninguna petición nueva en un rato: una aplicación de servidor, que
        # no manda tokens desde el navegador. No hay nada más que esperar.
        if time.monotonic() - ultima_novedad > 1.5:
            break
        time.sleep(0.25)
    return "", ""


def autenticar(driver, credenciales: Credenciales, *, nombre: str = "sesión",
               rol: str = "", scope: Scope | None = None) -> Sesion:
    """Obtiene una sesión a partir de unas credenciales.

    No lanza por un login que no sale: devuelve la sesión con `autenticada`
    falso y el motivo. Quien la pide decide si eso para el escaneo.
    """
    sesion = Sesion(nombre=nombre, rol=rol, cabeceras=dict(credenciales.cabeceras))

    if credenciales.modo == "cabecera":
        # Un token en cabecera no necesita navegar: ya es la sesión.
        sesion.autenticada = True
        return sesion

    if credenciales.modo == "cookies":
        sesion.cookies = dict(credenciales.cookies)
        sesion.autenticada = True
        return sesion

    if credenciales.modo != "formulario":
        return sesion

    red = _Red(driver)
    host_aplicacion = _host(credenciales.url_login or "")
    try:
        # Se visita primero la raíz de la aplicación para recoger la sesión que
        # reparte a cualquier visitante. Sin ese paso no hay con qué comparar
        # después, y la fijación de sesión —que consiste precisamente en que
        # ese identificador siga valiendo tras autenticarse— sería indetectable.
        partes = urlsplit(credenciales.url_login)
        raiz = f"{partes.scheme}://{partes.netloc}/"
        if scope is None or scope.allows_url(raiz):
            with contextlib.suppress(Exception):
                driver.get(raiz)
        sesion.cookies_previas = {
            c["name"]: c["value"] for c in _todas_las_cookies(driver)
            if _del_dominio(c, [host_aplicacion])
        }

        _ir(driver, credenciales.url_login, red, scope)
        campo_usuario, campo_clave = _esperar_formulario(driver, red, scope, credenciales)
        host_formulario = _host(driver.current_url)

        if campo_clave is None:
            # En dos pasos: el usuario primero, la clave en la pantalla siguiente.
            _escribir(campo_usuario, credenciales.usuario or "")
            _enviar(driver, credenciales, campo_usuario)
            time.sleep(0.5)
            campo_usuario, campo_clave = _esperar_formulario(driver, red, scope, credenciales)
            if campo_clave is None:
                raise _Falla("tras enviar el usuario no apareció el campo de la contraseña")
        if campo_usuario is not None and campo_usuario.get_attribute("type") != "hidden":
            with contextlib.suppress(Exception):
                if campo_usuario.is_enabled() and campo_usuario.get_attribute("readonly") is None:
                    _escribir(campo_usuario, credenciales.usuario or "")
        _escribir(campo_clave, credenciales.clave or "")
        _enviar(driver, credenciales, campo_clave)

        _esperar_resultado(driver, red, scope, credenciales, host_formulario)
    except _Falla as falla:
        sesion.motivo = str(falla)
        sesion.proveedor = _proveedor(red, scope, host_aplicacion)
        return sesion
    except Exception as exc:
        # El primer renglón basta: la traza de WebDriver es ruido para quien
        # lee el motivo, y lo que sirve es saber qué falló.
        primera = str(exc).strip().splitlines()[0] if str(exc).strip() else ""
        sesion.motivo = f"el navegador falló durante el acceso: {type(exc).__name__}: {primera}"
        return sesion

    hosts = _hosts_auditables(scope, driver)
    autorizacion, url_con_token = _capturar_token(red, scope, hosts)
    if autorizacion and "authorization" not in {k.lower() for k in sesion.cabeceras}:
        sesion.cabeceras["Authorization"] = autorizacion

    sesion.cookies_navegador = _todas_las_cookies(driver)
    sesion.cookies = {c["name"]: c["value"] for c in sesion.cookies_navegador
                      if _del_dominio(c, hosts)}
    sesion.proveedor = _proveedor(red, scope, host_aplicacion)
    sesion.url_prueba = url_con_token or driver.current_url
    sesion.autenticada = True
    return sesion


def _proveedor(red: _Red, scope: Scope | None, host_aplicacion: str) -> str:
    red.leer()
    for url in red.documentos():
        host = _host(url)
        if not host or host == host_aplicacion:
            continue
        if scope is None or scope.es_proveedor(url):
            return host
    return ""


# ── Comprobación fuera del navegador ────────────────────────────────────────
def _manda_a_entrar(respuesta, scope: Scope | None) -> bool:
    """¿Esta respuesta es «vete a autenticarte»?"""
    if respuesta.status_code in (401, 403):
        return True
    if 300 <= respuesta.status_code < 400:
        destino = respuesta.headers.get("location", "")
        if scope is not None and scope.es_proveedor(destino):
            return True
        return parece_desconectado(destino, "")
    return False


def verificar(sesion: Sesion, scope: Scope | None, *, timeout: float = 10.0) -> Sesion:
    """Pide lo mismo con y sin la sesión, fuera del navegador.

    Tres resultados posibles, y los tres se distinguen:

    - Con la sesión se entra y sin ella no: verificada. Es la única forma de
      poder vigilar después si caduca.
    - Con la sesión tampoco se entra: no vale, aunque el navegador entrase. Pasa
      cuando la aplicación guarda la sesión donde no se puede llevar a otro
      cliente. Se dice ahora: después, las herramientas irían como anónimas.
    - Las dos respuestas se parecen: no se puede confirmar. No es un fallo —una
      página pública no distingue—, pero se avisa en el escaneo.
    """
    import httpx

    url = sesion.url_prueba or (scope.urls[0] if scope is not None and scope.urls else "")
    if not url:
        return sesion
    if scope is not None and not scope.allows_url(url):
        return sesion
    sesion.url_prueba = url
    try:
        with httpx.Client(trust_env=False, verify=False, follow_redirects=False,
                          timeout=timeout) as cliente:
            anonima = cliente.get(url)
            con = cliente.get(url, cookies=sesion.cookies, headers=sesion.cabeceras)
    except httpx.HTTPError as exc:
        sesion.comprobacion = {"url": url, "error": f"{type(exc).__name__}: {exc}"}
        return sesion

    sesion.comprobacion = {
        "url": url, "sin_sesion": anonima.status_code, "con_sesion": con.status_code,
    }
    if _manda_a_entrar(con, scope):
        sesion.autenticada = False
        sesion.verificada = False
        destino = con.headers.get("location", "")
        sesion.motivo = (
            f"se entró en el navegador, pero la sesión no funciona fuera de él: {url} "
            f"responde {con.status_code}" + (f" hacia {destino}" if destino else "")
            + ". Las herramientas no podrían usarla. Si la aplicación guarda el token "
            "en el navegador, captura la cabecera Authorization a mano y usa el modo "
            "«Cabecera»")
        return sesion
    if not sesion.cookies and not sesion.cabeceras:
        sesion.autenticada = False
        sesion.motivo = (
            "se entró en el navegador, pero no dejó ninguna cookie ni ningún token "
            "que se pueda reutilizar. Las herramientas irían como anónimas")
        return sesion
    sesion.verificada = _manda_a_entrar(anonima, scope) and 200 <= con.status_code < 300
    return sesion


def sigue_viva(sesion: Sesion, scope: Scope | None, *, timeout: float = 10.0) -> bool | None:
    """¿Sigue valiendo? `None` si no se puede saber: sesión sin verificar."""
    import httpx

    if not sesion.verificada or not sesion.url_prueba:
        return None
    try:
        with httpx.Client(trust_env=False, verify=False, follow_redirects=False,
                          timeout=timeout) as cliente:
            r = cliente.get(sesion.url_prueba, cookies=sesion.cookies,
                            headers=sesion.cabeceras)
    except httpx.HTTPError:
        return None
    return not _manda_a_entrar(r, scope)


def reglas_de_resolucion(scope: Scope) -> str:
    """El DNS congelado del alcance, en el formato de Chromium.

    Con esto el navegador del login solo puede resolver lo auditable y los
    proveedores declarados, y los resuelve a las IP de la foto inicial. Un
    proveedor no declarado no es un sitio al que se llega y luego se lamenta:
    es un nombre que no resuelve, y el login lo dice.
    """
    reglas = []
    for nombre, direcciones in scope._frozen_dns.items():
        if not direcciones:
            continue
        ip = next((d for d in direcciones if d.version == 4), direcciones[0])
        reglas.append(f"MAP {nombre} {ip if ip.version == 4 else f'[{ip}]'}")
    reglas.append("MAP * ~NOTFOUND")
    return ",".join(reglas)


def entrar(credenciales: Credenciales, scope: Scope | None, *, nombre: str = "sesión",
           rol: str = "") -> Sesion:
    """Una sesión lista para usar, o una que dice por qué no lo está.

    Cada llamada usa su propio navegador, recién creado y cerrado al terminar:
    ver la regla 2 al principio del módulo.
    """
    if credenciales.modo == "formulario":
        from .crawler import nuevo_navegador

        extra = (f"--host-resolver-rules={reglas_de_resolucion(scope)}",) if scope else ()
        driver = nuevo_navegador(extra=extra, registrar_red=True)
        try:
            driver.set_page_load_timeout(30)
            sesion = autenticar(driver, credenciales, nombre=nombre, rol=rol, scope=scope)
        finally:
            with contextlib.suppress(Exception):
                driver.quit()
    else:
        sesion = autenticar(None, credenciales, nombre=nombre, rol=rol, scope=scope)
    if sesion.autenticada:
        verificar(sesion, scope)
    return sesion


def parece_desconectado(url: str, html: str) -> bool:
    """¿La respuesta indica que la sesión se ha perdido?

    Heurística deliberadamente conservadora: un falso positivo aquí hace que el
    crawler vuelva a autenticarse sin necesidad, que es barato; un falso
    negativo hace que recorra la aplicación entera como anónimo creyendo que va
    autenticado, que arruina el escaneo entero sin avisar.
    """
    minusculas = f"{url} {html[:4000]}".lower()
    return any(senal in minusculas for senal in SENALES_DE_SALIDA)


def descubrir_proveedor(url_login: str, scope: Scope, *, saltos: int = 6,
                        timeout: float = 10.0) -> str:
    """El host al que la aplicación manda a autenticarse, si es otro.

    Sigue las redirecciones de la URL de acceso sin salir del alcance: lee la
    cabecera Location y se para en el primer salto que va fuera. No contacta
    ese host —todavía no está autorizado—: solo lo nombra. Se hace antes de
    congelar el alcance, para que el proveedor entre en la foto del DNS y el
    aislamiento de red le dé ruta.

    Devuelve "" si no hay redirección fuera, o si la hace JavaScript: en ese
    caso hay que declararlo, y el login dirá exactamente a qué host quiso ir.
    """
    import httpx
    from urllib.parse import urljoin

    url = url_login
    try:
        with httpx.Client(trust_env=False, verify=False, follow_redirects=False,
                          timeout=timeout) as cliente:
            for _ in range(saltos):
                if not scope.allows_url(url):
                    return _host(url)
                r = cliente.get(url)
                if not 300 <= r.status_code < 400 or "location" not in r.headers:
                    return ""
                url = urljoin(url, r.headers["location"])
    except httpx.HTTPError:
        return ""
    return ""


def construir_alcance(targets, *, allow_public: bool = False, extra_hosts=(),
                      credenciales: Credenciales | None = None,
                      roles=()) -> Scope:
    """El alcance de un escaneo, con sus proveedores de identidad ya dentro.

    Los declarados entran tal cual. Los demás se descubren siguiendo la
    redirección de cada URL de acceso, antes de congelar: así el proveedor
    queda en la foto del DNS y en las rutas del aislamiento, y el navegador del
    login puede llegar a él. Lo que no se descubre —una redirección hecha con
    JavaScript— lo nombra el propio login cuando choca con él.
    """
    from ..core.scope import Scope

    todas = [c for c in (credenciales, *(r[2] for r in roles)) if c is not None]
    declarados = [c.proveedor_identidad for c in todas if c.proveedor_identidad]
    scope = Scope.build(targets, allow_public=allow_public, extra_hosts=extra_hosts,
                        proveedores_identidad=declarados)
    descubiertos = []
    for c in todas:
        if c.modo != "formulario" or not c.url_login or not scope.allows_url(c.url_login):
            continue
        host = descubrir_proveedor(c.url_login, scope)
        if host and not scope.es_proveedor(host) and host not in descubiertos:
            descubiertos.append(host)
    if not descubiertos:
        return scope
    return Scope.build(targets, allow_public=allow_public, extra_hosts=extra_hosts,
                       proveedores_identidad=[*declarados, *descubiertos])


# ── Reconocer el baile de autenticación ─────────────────────────────────────
# Rutas que solo existen en un proveedor de identidad. Bastan para reconocer el
# host aunque la URL no lleve los parámetros del protocolo: el iframe de
# comprobación de sesión de keycloak-js, los recursos de su página de acceso.
RUTAS_DE_PROVEEDOR = re.compile(
    r"/realms/[^/]+/(protocol/(openid-connect|saml)|login-actions)/"
    r"|/adfs/(ls|oauth2)/|/idp/profile/saml2/|/oauth2/v2\.0/authorize",
    re.I,
)


def es_redireccion_de_acceso(destino: str, origen: str) -> bool:
    """¿Es `destino` un proveedor pidiendo que te autentiques para volver a `origen`?

    Una aplicación protegida por Keycloak responde a un anónimo con una
    redirección a otro host. Para el probador eso era «redirección hacia un
    destino externo», y salía como redirección abierta en el informe de cada
    aplicación con SSO. No lo es: el destino lo fija la configuración, no la
    petición.

    No basta con que la URL «parezca» de un proveedor: lo que lo distingue de
    una redirección abierta de verdad es que el parámetro de vuelta apunta a la
    propia aplicación. Una redirección a `https://malo/authorize?client_id=x&
    redirect_uri=https://malo/` sigue siendo una redirección abierta, y se
    sigue marcando.
    """
    from urllib.parse import parse_qs

    try:
        partes = urlsplit(destino)
    except ValueError:
        return False
    q = parse_qs(partes.query)
    vuelta = _host(origen)
    if not vuelta:
        return False

    def vuelve(*parametros: str) -> bool:
        return any(_host(v) == vuelta for p in parametros for v in q.get(p, []))

    if "client_id" in q and "redirect_uri" in q:          # OAuth 2 y OpenID Connect
        return vuelve("redirect_uri")
    if q.get("wa", [""])[0].startswith("wsignin"):         # WS-Federation (ADFS)
        return vuelve("wreply", "wtrealm")
    if "service" in q and partes.path.lower().rstrip("/").endswith("/login"):   # CAS
        return vuelve("service")
    if "SAMLRequest" in q:                                 # SAML, redirección HTTP
        # La vuelta va dentro de la petición, comprimida y en base64.
        import base64
        import zlib

        try:
            xml = zlib.decompress(base64.b64decode(q["SAMLRequest"][0]), -15).decode()
        except Exception:
            return False
        acs = re.search(r'AssertionConsumerServiceURL="([^"]+)"', xml)
        return bool(acs) and _host(html_desescapar(acs.group(1))) == vuelta
    return False


def html_desescapar(texto: str) -> str:
    import html

    return html.unescape(texto)


def parece_proveedor(url: str) -> bool:
    """¿Esta URL es de un proveedor de identidad, por su ruta?"""
    try:
        return bool(RUTAS_DE_PROVEEDOR.search(urlsplit(url).path))
    except ValueError:
        return False
