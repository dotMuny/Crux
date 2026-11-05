"""Control de acceso: lo que el módulo afirma y, sobre todo, lo que calla."""

from __future__ import annotations

import pytest

from crux.core.severity import Severity
from crux.modules.auth import Sesion
from crux.modules.authz import (
    Comparacion, ComparadorDeRoles, Respuesta,
    comprobar_fijacion_de_sesion, equivalentes,
)
from crux.core.policy import get_policy
from crux.core.scope import Scope


def resp(estado=200, texto="<html>contenido</html>", sesion="x"):
    return Respuesta(estado=estado, texto=texto, longitud=len(texto), sesion=sesion)


@pytest.fixture
def comparador():
    sesiones = [
        Sesion(nombre="anónima", autenticada=False),
        Sesion(nombre="luis", rol="user", cookies={"S": "l"}, autenticada=True),
        Sesion(nombre="ana", rol="admin", cookies={"S": "a"}, autenticada=True),
    ]
    return ComparadorDeRoles(
        Scope.build(["http://127.0.0.1:8999/"]), get_policy("safe-active"), sesiones
    )


class TestEquivalencia:
    def test_dos_respuestas_identicas(self):
        assert equivalentes(resp(), resp()) == 1.0

    def test_estados_distintos_no_son_equivalentes(self):
        assert equivalentes(resp(200), resp(403)) == 0.0

    def test_los_tokens_volatiles_no_cuentan(self):
        """Casi toda aplicación mete un CSRF distinto en cada respuesta; si eso
        rompiera la comparación, no se detectaría nunca nada."""
        a = resp(texto='<input name="csrf_token" value="aaaa1111">contenido')
        b = resp(texto='<input name="csrf_token" value="bbbb2222">contenido')
        assert equivalentes(a, b) > 0.92


class TestInterpretacion:
    def test_una_ruta_publica_no_es_un_hallazgo(self, comparador):
        """La portada responde igual a todo el mundo porque debe hacerlo."""
        c = Comparacion(url="http://127.0.0.1:8999/")
        c.respuestas = {"anónima": resp(), "luis": resp(), "ana": resp()}
        assert comparador.evaluar([c], publicas=["http://127.0.0.1:8999/"]) == []

    def test_una_ruta_con_identificador_nunca_es_publica(self, comparador):
        """Que la portada enlace /invoice/1001 no vuelve pública esa factura;
        enlazarla es parte del fallo."""
        url = "http://127.0.0.1:8999/invoice/1001"
        c = Comparacion(url=url)
        c.respuestas = {"anónima": resp(), "luis": resp(), "ana": resp()}
        hallazgos = comparador.evaluar([c], publicas=[url])
        assert [f.check_id for f in hallazgos] == ["acceso-sin-autenticar"]

    def test_autorizacion_rota_solo_en_rutas_que_declaran_privilegio(self, comparador):
        """El desarrollador llamó «admin» a la ruta: ésa es la política."""
        privilegiada = Comparacion(url="http://127.0.0.1:8999/admin/export")
        privilegiada.respuestas = {"anónima": resp(302, ""), "luis": resp(), "ana": resp()}
        corriente = Comparacion(url="http://127.0.0.1:8999/perfil")
        corriente.respuestas = {"anónima": resp(302, ""), "luis": resp(), "ana": resp()}

        ids = {f.check_id for f in comparador.evaluar([privilegiada, corriente])}
        assert ids == {"autorizacion-rota-entre-roles"}

    def test_si_el_rol_bajo_recibe_un_403_no_hay_hallazgo(self, comparador):
        c = Comparacion(url="http://127.0.0.1:8999/admin/export")
        c.respuestas = {"anónima": resp(302, ""), "luis": resp(403, "prohibido"),
                        "ana": resp()}
        assert comparador.evaluar([c]) == []


class TestFijacionDeSesion:
    def test_un_identificador_que_no_cambia(self):
        sesion = Sesion(nombre="luis", autenticada=True,
                        cookies_previas={"SESSIONID": "abc123"},
                        cookies={"SESSIONID": "abc123"})
        hallazgos = comprobar_fijacion_de_sesion(sesion, "http://h/")
        assert len(hallazgos) == 1
        assert hallazgos[0].severity is Severity.HIGH
        assert hallazgos[0].cwe == ["CWE-384"]

    def test_un_identificador_renovado_no_se_marca(self):
        sesion = Sesion(nombre="luis", autenticada=True,
                        cookies_previas={"SESSIONID": "antes"},
                        cookies={"SESSIONID": "despues"})
        assert comprobar_fijacion_de_sesion(sesion, "http://h/") == []

    def test_las_cookies_que_no_son_de_sesion_se_ignoran(self):
        """El idioma o el consentimiento NO deben cambiar al entrar: exigirlo
        marcaría como fallo el comportamiento correcto."""
        sesion = Sesion(nombre="luis", autenticada=True,
                        cookies_previas={"idioma": "es", "cookie_consent": "1"},
                        cookies={"idioma": "es", "cookie_consent": "1"})
        assert comprobar_fijacion_de_sesion(sesion, "http://h/") == []

    def test_sin_sesion_autenticada_no_se_afirma_nada(self):
        sesion = Sesion(nombre="x", autenticada=False,
                        cookies_previas={"SESSIONID": "a"}, cookies={"SESSIONID": "a"})
        assert comprobar_fijacion_de_sesion(sesion, "http://h/") == []
