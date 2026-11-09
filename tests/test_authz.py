"""Control de acceso: lo que el módulo afirma y, sobre todo, lo que calla."""

from __future__ import annotations

import pytest

from crux.core.severity import Severity
from crux.modules.auth import Sesion
from crux.core.severity import Confidence
from crux.modules.authz import (
    Comparacion, ComparadorDeRoles, Operacion, Respuesta,
    aviso_de_operaciones_omitidas, comprobar_fijacion_de_sesion, equivalentes,
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


class TestOperacionesDeLaApi:
    """La misma ruta, en una API, son varias operaciones con permisos distintos."""

    def _comp(self, url, metodo, respuestas):
        c = Comparacion(url=url, metodo=metodo)
        c.respuestas = respuestas
        return c

    def test_las_de_escritura_no_se_repiten_sin_permiso(self, comparador):
        """Comparar es repetir la petición con cada sesión: un POST crea algo."""
        operaciones = [
            Operacion(url="http://127.0.0.1:8999/api/facturas", metodo="GET"),
            Operacion(url="http://127.0.0.1:8999/api/facturas", metodo="POST"),
            Operacion(url="http://127.0.0.1:8999/api/facturas/1", metodo="DELETE"),
        ]
        assert [o.metodo for o in comparador.operaciones_comparables(operaciones)] == ["GET"]

    def test_con_perfil_agresivo_entran_las_de_escritura_menos_delete(self, comparador):
        """DELETE no, con ningún perfil: se repetiría con la sesión con privilegio."""
        comparador.policy = get_policy("aggressive")
        operaciones = [
            Operacion(url="http://127.0.0.1:8999/api/x", metodo="POST"),
            Operacion(url="http://127.0.0.1:8999/api/x", metodo="PUT"),
            Operacion(url="http://127.0.0.1:8999/api/x", metodo="PATCH"),
            Operacion(url="http://127.0.0.1:8999/api/x/1", metodo="DELETE"),
        ]
        metodos = {o.metodo for o in comparador.operaciones_comparables(operaciones)}
        assert metodos == {"POST", "PUT", "PATCH"}

    def test_lo_que_no_se_comparo_se_dice(self, comparador):
        todas = [Operacion(url="http://x/1", metodo="POST"),
                 Operacion(url="http://x/1", metodo="GET")]
        avisos = aviso_de_operaciones_omitidas(todas, todas[1:], comparador.policy)
        assert [f.check_id for f in avisos] == ["autorizacion-no-comprobada"]
        assert "POST" in avisos[0].description

    def test_la_api_que_responde_lo_mismo_a_cada_usuario_es_publica(self, comparador):
        """Una comprobación de vida contesta igual a todos: no es un fallo."""
        c = self._comp("http://127.0.0.1:8999/api/datos", "GET",
                       {"anónima": resp(), "luis": resp(), "ana": resp()})
        assert comparador.evaluar_api([c]) == []

    def test_la_api_que_contesta_distinto_a_cada_usuario_si_lo_es(self, comparador):
        """Si a cada rol le da datos distintos, el anónimo recibió los de alguien."""
        c = self._comp("http://127.0.0.1:8999/api/facturas", "GET", {
            "anónima": resp(texto="<html>facturas de luis</html>"),
            "luis": resp(texto="<html>facturas de luis</html>"),
            "ana": resp(texto="<html>facturas de ana, otra cosa muy distinta</html>"),
        })
        hallazgos = comparador.evaluar_api([c])
        assert [f.check_id for f in hallazgos] == ["api-sin-autenticar"]
        assert hallazgos[0].confidence == Confidence.FIRM

    def test_con_un_solo_rol_se_dice_que_es_tentativo(self):
        sesiones = [Sesion(nombre="anónima", autenticada=False),
                    Sesion(nombre="ana", rol="admin", cookies={"S": "a"}, autenticada=True)]
        comparador = ComparadorDeRoles(
            Scope.build(["http://127.0.0.1:8999/"]), get_policy("safe-active"), sesiones)
        c = Comparacion(url="http://127.0.0.1:8999/api/facturas", metodo="GET")
        c.respuestas = {"anónima": resp(), "ana": resp()}
        hallazgos = comparador.evaluar_api([c])
        assert [f.confidence for f in hallazgos] == [Confidence.TENTATIVE]

    def test_con_un_solo_rol_lo_que_suele_ser_publico_se_calla(self, comparador):
        sesiones = [Sesion(nombre="anónima", autenticada=False),
                    Sesion(nombre="ana", cookies={"S": "a"}, autenticada=True)]
        uno = ComparadorDeRoles(
            Scope.build(["http://127.0.0.1:8999/"]), get_policy("safe-active"), sesiones)
        for ruta in ("/api/health", "/api/version", "/login", "/openapi.json"):
            c = Comparacion(url=f"http://127.0.0.1:8999{ruta}", metodo="GET")
            c.respuestas = {"anónima": resp(), "ana": resp()}
            assert uno.evaluar_api([c]) == [], ruta

    def test_protegida_para_leer_y_abierta_para_escribir(self, comparador):
        """El control existe y está puesto en un método y no en el otro."""
        lectura = self._comp("http://127.0.0.1:8999/api/facturas/1", "GET",
                             {"luis": resp(403, "prohibido")})
        escritura = self._comp("http://127.0.0.1:8999/api/facturas/1", "PUT",
                               {"luis": resp(200, "actualizada")})
        hallazgos = comparador.evaluar_metodos([lectura, escritura])
        assert [f.check_id for f in hallazgos] == ["control-de-acceso-por-metodo"]
        assert hallazgos[0].severity == Severity.HIGH

    def test_lo_contrario_es_el_comportamiento_correcto(self, comparador):
        """Leer permitido y escribir denegado es lo que debe pasar."""
        lectura = self._comp("http://127.0.0.1:8999/api/facturas/1", "GET",
                             {"luis": resp(200, "factura")})
        escritura = self._comp("http://127.0.0.1:8999/api/facturas/1", "PUT",
                               {"luis": resp(403, "prohibido")})
        assert comparador.evaluar_metodos([lectura, escritura]) == []

    def test_el_metodo_sale_en_el_hallazgo(self, comparador):
        """Sin el método, «la ruta /api/x» no dice qué se probó."""
        c = self._comp("http://127.0.0.1:8999/admin/api/x", "POST",
                       {"anónima": resp(403, ""), "luis": resp(), "ana": resp()})
        hallazgos = comparador.evaluar([c])
        assert "POST http://127.0.0.1:8999/admin/api/x" in hallazgos[0].description

    def test_un_fichero_de_un_directorio_oculto_no_es_un_fallo_de_permisos(self, comparador):
        """`/.git/config` casa con «config», y que se sirva ya tiene su hallazgo."""
        c = self._comp("http://127.0.0.1:8999/.git/config", "GET",
                       {"anónima": resp(302, ""), "luis": resp(), "ana": resp()})
        assert comparador.evaluar([c]) == []

    def test_una_ruta_de_api_con_identificador_la_lleva_la_regla_de_siempre(self, comparador):
        """Y no se cuenta dos veces: `evaluar_api` no la toca."""
        c = self._comp("http://127.0.0.1:8999/api/facturas/1001", "GET",
                       {"anónima": resp(), "luis": resp(), "ana": resp()})
        por_url = comparador.evaluar([c], publicas=[c.url])
        assert [f.check_id for f in por_url] == ["acceso-sin-autenticar"]
        assert comparador.evaluar_api([c]) == []
