"""Autenticación contra la aplicación auditada.

Cubre los tres casos que el usuario declaró: formulario con cookie de sesión,
token o JWT en cabecera, y aplicaciones sin autenticación. No cubre SSO
corporativo, por decisión explícita: redirigir a un IdP y seguir el baile de
SAML automáticamente es un proyecto en sí mismo, y el caso se resuelve
inyectando una sesión capturada a mano.

Una sesión es un objeto de datos —cookies y cabeceras— que se puede aplicar
tanto a un navegador de Selenium como a un cliente httpx. Eso permite que el
crawler navegue autenticado y que los módulos de comprobación repitan las
mismas peticiones sin arrastrar el navegador.
"""

from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit
from typing import Any, Iterable

# Nombres de campo habituales, ordenados de más a menos específico. Sirven para
# rellenar un formulario de acceso sin que el operador tenga que dar selectores.
CAMPOS_USUARIO = ("username", "user", "usuario", "login", "email", "correo", "j_username")
CAMPOS_CLAVE = ("password", "passwd", "pass", "clave", "contrasena", "contraseña", "j_password")

# Señales de que la sesión se ha perdido y hay que volver a entrar.
SENALES_DE_SALIDA = ("iniciar sesión", "iniciar sesion", "sign in", "log in", "acceder",
                     "authentication required", "/login", "/signin")


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

    # Token en cabecera
    cabeceras: dict[str, str] = field(default_factory=dict)

    # Sesión capturada a mano (el escape para SSO)
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
    """Una sesión viva, aplicable a un navegador o a un cliente HTTP."""

    nombre: str = "anónima"
    rol: str = ""
    cookies: dict[str, str] = field(default_factory=dict)
    cabeceras: dict[str, str] = field(default_factory=dict)
    autenticada: bool = False
    # Cookies que el navegador ya tenía antes de entrar. Sin esta foto no se
    # puede saber si el identificador de sesión se renovó al autenticarse.
    cookies_previas: dict[str, str] = field(default_factory=dict)

    def aplicar_a_httpx(self) -> dict[str, Any]:
        return {"cookies": dict(self.cookies), "headers": dict(self.cabeceras)}

    def aplicar_a_navegador(self, driver, dominio_url: str) -> None:
        """Inyecta las cookies en el navegador.

        Hay que estar ya en el dominio para poder escribirlas: el navegador
        rechaza una cookie de un origen en el que no está.
        """
        driver.get(dominio_url)
        for nombre, valor in self.cookies.items():
            driver.add_cookie({"name": nombre, "value": valor, "path": "/"})

    def describe(self) -> dict[str, Any]:
        return {
            "nombre": self.nombre,
            "rol": self.rol,
            "autenticada": self.autenticada,
            "cookies": sorted(self.cookies),
            "cabeceras": sorted(self.cabeceras),
        }


def _buscar_campo(driver, nombres: Iterable[str], tipo: str | None = None):
    """Encuentra un campo por nombre, id o tipo, en ese orden de preferencia."""
    from selenium.webdriver.common.by import By

    for nombre in nombres:
        for como, valor in ((By.NAME, nombre), (By.ID, nombre)):
            elementos = driver.find_elements(como, valor)
            if elementos:
                return elementos[0]
    if tipo:
        elementos = driver.find_elements(By.CSS_SELECTOR, f"input[type='{tipo}']")
        if elementos:
            return elementos[0]
    return None


def autenticar(driver, credenciales: Credenciales, *, nombre: str = "sesión",
               rol: str = "") -> Sesion:
    """Obtiene una sesión viva a partir de unas credenciales."""
    from selenium.webdriver.common.by import By

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

    # Se visita primero la raíz de la aplicación para recoger la sesión que
    # reparte a cualquier visitante. Sin ese paso no hay con qué comparar
    # después, y la fijación de sesión —que consiste precisamente en que ese
    # identificador siga valiendo tras autenticarse— sería indetectable.
    partes = urlsplit(credenciales.url_login)
    with contextlib.suppress(Exception):
        driver.get(f"{partes.scheme}://{partes.netloc}/")
    driver.get(credenciales.url_login)
    sesion.cookies_previas = {c["name"]: c["value"] for c in driver.get_cookies()}
    campo_usuario = (
        driver.find_element(By.CSS_SELECTOR, credenciales.selector_usuario)
        if credenciales.selector_usuario
        else _buscar_campo(driver, CAMPOS_USUARIO, "text")
    )
    campo_clave = (
        driver.find_element(By.CSS_SELECTOR, credenciales.selector_clave)
        if credenciales.selector_clave
        else _buscar_campo(driver, CAMPOS_CLAVE, "password")
    )
    if campo_usuario is None or campo_clave is None:
        raise RuntimeError(
            f"no se encontró el formulario de acceso en {credenciales.url_login}. "
            "Pasa --selector-usuario y --selector-clave si los campos tienen "
            "nombres poco habituales."
        )

    campo_usuario.clear()
    campo_usuario.send_keys(credenciales.usuario or "")
    campo_clave.clear()
    campo_clave.send_keys(credenciales.clave or "")

    if credenciales.selector_enviar:
        driver.find_element(By.CSS_SELECTOR, credenciales.selector_enviar).click()
    else:
        campo_clave.submit()

    # Sin espera explícita el navegador aún está en la página de acceso cuando
    # leemos las cookies, y la sesión parece no haberse creado.
    time.sleep(1.0)

    sesion.cookies = {c["name"]: c["value"] for c in driver.get_cookies()}
    if credenciales.senal_de_exito:
        sesion.autenticada = credenciales.senal_de_exito in driver.page_source
    else:
        # Sin señal declarada: se da por buena si hay cookies nuevas y la página
        # ya no parece un formulario de acceso.
        sesion.autenticada = bool(sesion.cookies) and not parece_desconectado(
            driver.current_url, driver.page_source
        )
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
