"""Entrar en una aplicación que delega el acceso en Keycloak, y que se note.

Este fichero existe por una queja concreta: «con usuario y contraseña me sale
lo mismo que sin ellos». Detrás había cuatro fallos que se sumaban:

1. La sesión solo la usaba el crawler. Sondas, comprobaciones pasivas, nuclei
   y wapiti iban como anónimos aunque el login hubiera ido bien.
2. Un login fallido no decía nada: el escaneo seguía como anónimo y terminaba
   «bien».
3. Con un proveedor de SSO, todos los roles entraban con el mismo navegador, y
   el segundo pasaba como el primero sin ver el formulario.
4. El proveedor vive en otro host. Declararlo como host extra lo volvía
   auditable: el crawler acabaría escaneando el Keycloak corporativo.

Las pruebas corren contra `tests/fixtures/keycloak`, que reproduce el flujo de
Keycloak sin red: el formulario en otro host, su cookie de sesión, el código de
autorización, el segundo factor y la sesión SSO.
"""

from __future__ import annotations

import asyncio
import json
import logging

import pytest

from crux.adapters.base import ScanContext
from crux.adapters.nuclei import secretos_de_sesion
from crux.adapters.wapiti import argumentos_de_sesion
from crux.core.policy import get_policy
from crux.core.scope import Scope
from crux.modules.auth import (
    AutenticacionFallida, Credenciales, Sesion, construir_alcance, descubrir_proveedor,
    entrar, reglas_de_resolucion,
)

logging.getLogger("werkzeug").setLevel(logging.ERROR)


@pytest.fixture(scope="module")
def lab():
    from tests.fixtures.keycloak import levantar

    laboratorio = levantar()
    yield laboratorio
    laboratorio.parar()


def credenciales(base: str, usuario="ana", clave="ana-clave", **extra) -> Credenciales:
    return Credenciales(url_login=base + "/", usuario=usuario, clave=clave, **extra)


def alcance(base: str, *, idp: str | None = None) -> Scope:
    return Scope.build([base + "/"], proveedores_identidad=[idp] if idp else [])


# ── El proveedor de identidad en el alcance ─────────────────────────────────
class TestProveedorEnElAlcance:
    def test_se_puede_ir_a_el_para_entrar(self, lab):
        scope = alcance(lab.app, idp=lab.idp)
        assert scope.permite_para_entrar(lab.idp + "/realms/crux/protocol/openid-connect/auth")

    def test_pero_no_se_audita(self, lab):
        """Un Keycloak corporativo da servicio a cien aplicaciones."""
        scope = alcance(lab.app, idp=lab.idp)
        assert not scope.allows_url(lab.idp + "/")
        assert not scope.allows_host("127.0.0.2")

    def test_ni_aunque_comparta_ip_con_un_objetivo(self):
        """Un mismo proxy inverso sirviendo la aplicación y el Keycloak."""
        scope = Scope.build(["127.0.0.1/32"], proveedores_identidad=["localhost"])
        assert scope.allows_host("127.0.0.1")
        assert not scope.allows_host("localhost")

    def test_entra_en_el_dns_congelado(self, lab):
        """Es lo que le da ruta y nombre dentro del aislamiento de red."""
        reglas = reglas_de_resolucion(alcance(lab.app, idp=lab.idp))
        assert "MAP 127.0.0.2 127.0.0.2" in reglas
        assert reglas.endswith("MAP * ~NOTFOUND")

    def test_se_descubre_siguiendo_la_redireccion(self, lab):
        assert descubrir_proveedor(lab.app + "/", alcance(lab.app)) == "127.0.0.2"

    def test_y_entra_solo_en_el_alcance(self, lab):
        scope = construir_alcance([lab.app + "/"], credenciales=credenciales(lab.app))
        assert scope.proveedores_identidad == ["127.0.0.2"]

    def test_un_proveedor_publico_se_rechaza(self):
        """«Solo para entrar» no cambia que el tráfico saldría de la red interna."""
        scope = Scope.build(["127.0.0.1"], proveedores_identidad=["8.8.8.8"])
        assert scope.proveedores_identidad == []
        assert any("pública" in why for _, why in scope.rejected)


# ── Entrar ──────────────────────────────────────────────────────────────────
class TestEntrar:
    def test_app_de_servidor(self, lab):
        sesion = entrar(credenciales(lab.app), alcance(lab.app, idp=lab.idp))
        assert sesion.autenticada and sesion.verificada, sesion.motivo
        assert "APPSESSION" in sesion.cookies
        assert sesion.proveedor == "127.0.0.2"
        # Comprobado fuera del navegador: sin sesión, a Keycloak; con ella, dentro.
        assert sesion.comprobacion["sin_sesion"] == 302
        assert sesion.comprobacion["con_sesion"] == 200

    def test_solo_se_guardan_las_cookies_de_la_aplicacion(self, lab):
        """Las del proveedor van al navegador del crawler, no a las herramientas."""
        sesion = entrar(credenciales(lab.app), alcance(lab.app, idp=lab.idp))
        assert "KEYCLOAK_IDENTITY" not in sesion.cookies
        assert any(c["name"] == "KEYCLOAK_IDENTITY" for c in sesion.cookies_navegador)

    def test_spa_con_el_token_en_cabecera(self, lab):
        """keycloak-js: el token vive en el navegador y ninguna cookie lo lleva."""
        sesion = entrar(credenciales(lab.spa), alcance(lab.spa, idp=lab.idp))
        assert sesion.autenticada and sesion.verificada, sesion.motivo
        assert sesion.cabeceras["Authorization"].startswith("Bearer ey")
        assert sesion.url_prueba.endswith("/api/yo")
        assert sesion.comprobacion["sin_sesion"] == 401

    def test_en_dos_pasos(self, lab):
        """Usuario en una pantalla, contraseña en la siguiente."""
        cred = Credenciales(
            url_login=f"{lab.idp}/realms/dospasos/protocol/openid-connect/auth?"
                      f"client_id=app&response_type=code&state=x&redirect_uri={lab.app}/callback",
            usuario="ana", clave="ana-clave")
        scope = Scope.build([lab.app + "/"], proveedores_identidad=[lab.idp])
        sesion = entrar(cred, scope)
        assert sesion.autenticada, sesion.motivo

    def test_cada_rol_entra_como_quien_es(self, lab):
        """Con un navegador compartido, «admin» entraba como «ana»: el proveedor
        reconocía su propia cookie de SSO y no enseñaba el formulario."""
        scope = alcance(lab.app, idp=lab.idp)
        antes = len(lab.estado.entradas)
        entrar(credenciales(lab.app), scope, nombre="ana")
        entrar(credenciales(lab.app, "admin", "admin-clave"), scope, nombre="admin")
        assert lab.estado.entradas[antes:] == ["ana", "admin"]


# ── No entrar, y decir por qué ──────────────────────────────────────────────
class TestDecirPorQue:
    def _motivo(self, lab, base, idp=True, **kw) -> str:
        sesion = entrar(credenciales(base, **kw), alcance(base, idp=lab.idp if idp else None))
        assert not sesion.autenticada
        return sesion.motivo

    def test_clave_mala(self, lab):
        motivo = self._motivo(lab, lab.app, clave="MALA")
        assert "rechazó las credenciales" in motivo
        assert "Invalid username or password" in motivo

    def test_segundo_factor(self, lab):
        motivo = self._motivo(lab, lab.app, usuario="otp", clave="otp-clave")
        assert "segundo factor" in motivo and "Cookies" in motivo

    def test_accion_obligatoria(self, lab):
        motivo = self._motivo(lab, lab.app, usuario="cambio", clave="cambio-clave")
        assert "cambiar la contraseña" in motivo

    def test_proveedor_sin_declarar_ni_se_toca(self, lab):
        """La SPA salta al proveedor con JavaScript: no se puede descubrir antes.
        Con el DNS congelado el navegador no llega a contactarlo."""
        antes = len(lab.estado.entradas)
        motivo = self._motivo(lab, lab.spa, idp=False)
        assert "127.0.0.2" in motivo and "Proveedor de identidad" in motivo
        assert len(lab.estado.entradas) == antes


# ── La sesión llega a las herramientas ──────────────────────────────────────
class TestLasHerramientasLaReciben:
    def _contexto(self, tmp_path, base: str, sesion: Sesion) -> ScanContext:
        return ScanContext(policy=get_policy("safe-active"), workdir=tmp_path,
                           scope=alcance(base), sesion=sesion)

    def test_nuclei_por_fichero_y_con_puerto(self, tmp_path, lab):
        """nuclei compara el dominio con el puerto. Con `127.0.0.1` a secas no
        mandaba la sesión a `127.0.0.1:8443`, y corría anónimo sin avisar."""
        ctx = self._contexto(tmp_path, lab.app, Sesion(cookies={"APPSESSION": "x"},
                                                       autenticada=True))
        fichero = secretos_de_sesion(ctx)
        datos = json.loads(fichero.read_text())
        dominios = datos["static"][0]["domains"]
        assert lab.app.split("//")[1] in dominios
        assert (fichero.stat().st_mode & 0o777) == 0o600
        assert fichero in ctx.secretos

    def test_wapiti_por_fichero_sin_la_cookie_en_argv(self, tmp_path, lab):
        ctx = self._contexto(tmp_path, lab.app, Sesion(cookies={"APPSESSION": "secreta"},
                                                       autenticada=True))
        argv = argumentos_de_sesion(ctx)
        assert "-c" in argv
        assert not any("secreta" in a for a in argv)
        assert f"{lab.app}/logout" in argv

    def test_wapiti_lee_el_fichero(self, tmp_path, lab):
        pytest.importorskip("wapitiCore")
        from wapitiCore.net.jsoncookie import JsonCookie

        ctx = self._contexto(tmp_path, lab.app, Sesion(cookies={"APPSESSION": "s"},
                                                       autenticada=True))
        argv = argumentos_de_sesion(ctx)
        tarro = JsonCookie()
        tarro.load(argv[argv.index("-c") + 1])
        assert [c.name for c in tarro.cookiejar(lab.app.split("//")[1])] == ["APPSESSION"]

    def test_sin_sesion_no_hay_nada(self, tmp_path, lab):
        ctx = self._contexto(tmp_path, lab.app, None)
        assert secretos_de_sesion(ctx) is None
        assert argumentos_de_sesion(ctx) == []


# ── El escaneo entero ───────────────────────────────────────────────────────
class TestElEscaneo:
    def _escanear(self, lab, tmp_path, cred):
        from crux.core.scan import run_web_scan

        return asyncio.run(run_web_scan(
            [lab.app + "/"], profile="safe-active", project_name="kc",
            db=tmp_path / "kc.db", only=[], credenciales=cred))

    def test_con_sesion_se_ve_lo_de_dentro(self, lab, tmp_path):
        """La cookie `preferencias` solo existe tras entrar. Si las sondas no
        llevaran la sesión, su falta de HttpOnly no aparecería nunca."""
        anonimo = self._escanear(lab, tmp_path, None)
        dentro = self._escanear(lab, tmp_path, credenciales(lab.app))
        def cookies(o):
            return {f.title for f in o.findings if f.check_id == "cookie-missing-flags"}
        assert not any("preferencias" in t for t in cookies(anonimo))
        assert any("preferencias" in t for t in cookies(dentro))

    def test_un_login_fallido_para_el_escaneo(self, lab, tmp_path):
        with pytest.raises(AutenticacionFallida, match="rechazó las credenciales"):
            self._escanear(lab, tmp_path, credenciales(lab.app, clave="MALA"))

    def test_la_sesion_queda_descrita_sin_valores(self, lab, tmp_path):
        from crux.core.models import Scan
        from crux.core.store import session_scope

        o = self._escanear(lab, tmp_path, credenciales(lab.app))
        with session_scope(tmp_path / "kc.db") as s:
            descripcion = s.get(Scan, o.scan_id).coverage["sesion"]
        assert descripcion["autenticada"] and descripcion["verificada"]
        assert descripcion["cookies"] == ["APPSESSION", "preferencias"]
        texto = json.dumps(descripcion)
        assert "ana-clave" not in texto
        # Nombres de cookie sí; ningún campo que lleve su valor.
        assert not any("valor" in k or "value" in k for k in descripcion)

    def test_se_nota_cuando_caduca(self):
        """La vigilancia entera descansa en esto: distinguir una sesión viva de
        una caducada con una petición, sin navegador."""
        import time

        from tests.fixtures.keycloak import levantar
        from crux.modules.auth import sigue_viva

        corto = levantar(caducidad_sesion=5)
        try:
            scope = alcance(corto.app, idp=corto.idp)
            sesion = entrar(credenciales(corto.app), scope)
            assert sigue_viva(sesion, scope) is True
            time.sleep(6)
            assert sigue_viva(sesion, scope) is False
            assert sigue_viva(entrar(credenciales(corto.app), scope), scope) is True
        finally:
            corto.parar()

    def test_una_sesion_sin_verificar_no_se_da_por_viva(self):
        """`None`, no `True`: sin saber cómo responde sin sesión, una respuesta
        200 no demuestra nada."""
        from crux.modules.auth import sigue_viva

        assert sigue_viva(Sesion(autenticada=True, verificada=False), None) is None

    def test_una_sesion_que_caduca_se_renueva_o_se_avisa(self, tmp_path):
        """Keycloak da tokens de cinco minutos. Un escaneo de veinte no puede
        dar por hecho que la sesión del principio sigue valiendo al final."""
        from crux.core.scan import _Vigilancia

        vigilancia = _Vigilancia()
        vigilancia.perdidas.append(("nuclei", "la sesión caducó mientras se ejecutaba"))
        avisos = vigilancia.avisos(Sesion(autenticada=True, verificada=True))
        assert [a.check_id for a in avisos] == ["sesion-perdida"]
        assert "nuclei" in avisos[0].title


# ── Falsos positivos de un escaneo anónimo con SSO ─────────────────────────
APP = "http://facturas.intra:8080/panel"


def _saml(acs: str) -> str:
    import base64
    import zlib
    from urllib.parse import quote

    xml = (f'<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
           f'AssertionConsumerServiceURL="{acs}" ID="x" Version="2.0"/>')
    c = zlib.compressobj(wbits=-15)
    crudo = c.compress(xml.encode()) + c.flush()
    return quote(base64.b64encode(crudo).decode())


class TestRedireccionDeAcceso:
    """Mandar a un anónimo a su Keycloak no es una redirección abierta. Salía
    como tal en el informe de cada aplicación con SSO."""

    @pytest.mark.parametrize("destino", [
        # Keycloak, OpenID Connect
        "http://sso.intra/realms/corp/protocol/openid-connect/auth?client_id=facturas"
        "&response_type=code&redirect_uri=http%3A%2F%2Ffacturas.intra%3A8080%2Fcallback",
        # Entra ID y cualquier OAuth 2
        "https://login.microsoftonline.com/t/oauth2/v2.0/authorize?client_id=x"
        "&redirect_uri=http://facturas.intra:8080/signin-oidc",
        # ADFS, WS-Federation
        "https://adfs.intra/adfs/ls/?wa=wsignin1.0&wtrealm=http://facturas.intra:8080/",
        # CAS
        "https://cas.intra/cas/login?service=http%3A%2F%2Ffacturas.intra%3A8080%2F",
        # SAML con la vuelta dentro de la petición
        "https://sso.intra/idp/profile/SAML2/Redirect/SSO?SAMLRequest="
        + _saml("http://facturas.intra:8080/saml/acs"),
    ])
    def test_se_reconoce(self, destino):
        from crux.modules.auth import es_redireccion_de_acceso

        assert es_redireccion_de_acceso(destino, APP)

    @pytest.mark.parametrize("destino", [
        # Con forma de proveedor, pero devuelve a otro sitio: eso SÍ es abierta.
        "https://malo.example/authorize?client_id=x&redirect_uri=https://malo.example/",
        "https://adfs.intra/adfs/ls/?wa=wsignin1.0&wreply=https://malo.example/",
        "https://sso.intra/saml?SAMLRequest=" + _saml("https://malo.example/acs"),
        "https://sso.intra/saml?SAMLRequest=basura",
        # Una redirección cualquiera
        "https://malo.example/",
        "http://sso.intra/realms/corp/protocol/openid-connect/auth",
    ])
    def test_lo_que_no_vuelve_a_la_aplicacion_no(self, destino):
        from crux.modules.auth import es_redireccion_de_acceso

        assert not es_redireccion_de_acceso(destino, APP)

    def test_la_comprobacion_pasiva_la_respeta(self):
        from crux.modules.passive import check_out_of_scope_redirect
        from crux.modules.probe import ProbeResult

        def sonda(destino):
            return ProbeResult(url=APP, final_url=APP, status=302,
                               redirect_chain=[destino],
                               error=f"redirect hacia {destino}, fuera del alcance: no se sigue")

        keycloak = ("http://sso.intra/realms/corp/protocol/openid-connect/auth?client_id=f"
                    "&redirect_uri=http://facturas.intra:8080/cb")
        assert list(check_out_of_scope_redirect(sonda(keycloak))) == []
        # El control: una redirección abierta de verdad se sigue marcando.
        abierta = list(check_out_of_scope_redirect(sonda("https://malo.example/")))
        assert [f.check_id for f in abierta] == ["open-redirect"]

    def test_un_escaneo_anonimo_lo_dice_en_vez_de_inventar(self, lab, tmp_path):
        from crux.core.scan import run_web_scan

        o = asyncio.run(run_web_scan([lab.app + "/"], profile="safe-active",
                                     project_name="anon", db=tmp_path / "a.db", only=[]))
        ids = {f.check_id for f in o.findings}
        assert "open-redirect" not in ids
        assert "recurso-externo-cargado" not in ids
        aviso = next(f for f in o.findings if f.check_id == "escaneo-sin-sesion")
        assert "127.0.0.2" in aviso.title
