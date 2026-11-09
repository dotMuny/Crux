"""GraphQL: un endpoint, cien operaciones, y ninguna herramienta que las vea.

Para wapiti y nuclei, `POST /graphql` es un campo de texto llamado «query».
Lo que se comprueba aquí es que el esquema se lee bien, que la consulta que se
construye es válida, y que lo que se afirma se afirma con una prueba —el error
del motor de base de datos— y no por parecido.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from crux.core.policy import get_policy
from crux.core.scope import Scope
from crux.core.severity import Severity
from crux.modules import graphql

BASE = "http://127.0.0.1:8999"
URL = f"{BASE}/graphql"

ESQUEMA = {
    "queryType": {"name": "Query"},
    "mutationType": {"name": "Mutation"},
    "types": [
        {"name": "Factura", "kind": "OBJECT", "fields": [
            {"name": "id", "args": [], "type": {"name": "ID", "kind": "SCALAR"}},
            {"name": "total", "args": [], "type": {"name": "String", "kind": "SCALAR"}},
        ]},
        {"name": "Query", "kind": "OBJECT", "fields": [
            {"name": "facturas",
             "args": [{"name": "cliente", "type": {"name": "String", "kind": "SCALAR"}},
                      {"name": "pagina", "type": {"name": "Int", "kind": "SCALAR"}}],
             "type": {"name": None, "kind": "LIST",
                      "ofType": {"name": "Factura", "kind": "OBJECT"}}},
            {"name": "version", "args": [],
             "type": {"name": "String", "kind": "SCALAR"}},
        ]},
        {"name": "Mutation", "kind": "OBJECT", "fields": [
            {"name": "borrarFactura",
             "args": [{"name": "id", "type": {"name": "ID", "kind": "SCALAR"}}],
             "type": {"name": "Boolean", "kind": "SCALAR"}},
        ]},
    ],
}


class TestLeerElEsquema:
    def test_separa_consultas_de_mutaciones(self):
        operaciones = graphql.operaciones_del_esquema(ESQUEMA)
        assert [o.nombre for o in operaciones if o.clase == "consulta"] == [
            "facturas", "version"]
        assert [o.nombre for o in operaciones if o.clase == "mutacion"] == [
            "borrarFactura"]

    def test_atraviesa_listas_para_encontrar_un_campo_que_pedir(self):
        """Pedir un objeto sin decir qué campos se quieren es un error de sintaxis."""
        facturas = graphql.operaciones_del_esquema(ESQUEMA)[0]
        assert facturas.campo_de_salida == "id"

    def test_un_escalar_no_necesita_seleccion(self):
        version = graphql.operaciones_del_esquema(ESQUEMA)[1]
        assert version.campo_de_salida == ""

    def test_distingue_los_argumentos_de_texto(self):
        facturas = graphql.operaciones_del_esquema(ESQUEMA)[0]
        assert [a.nombre for a in facturas.argumentos if a.es_texto] == ["cliente"]

    def test_la_consulta_que_se_construye_es_valida(self):
        facturas = graphql.operaciones_del_esquema(ESQUEMA)[0]
        assert graphql.consulta_de(facturas, {"cliente": "ana"}) == (
            'query { facturas(cliente: "ana") { id } }')
        version = graphql.operaciones_del_esquema(ESQUEMA)[1]
        assert graphql.consulta_de(version, {}) == "query { version }"

    def test_un_esquema_vacio_no_inventa_operaciones(self):
        assert graphql.operaciones_del_esquema({"types": []}) == []


class TestReconocerElServidor:
    def test_una_respuesta_con_datos_lo_es(self):
        assert graphql._es_graphql({"data": {"__typename": "Query"}})

    def test_una_respuesta_con_errores_tambien(self):
        """Un endpoint que exige sesión contesta un error de GraphQL: ya dice que lo hay."""
        assert graphql._es_graphql({"errors": [{"message": "no autenticado"}]})

    def test_un_json_cualquiera_no(self):
        assert not graphql._es_graphql({"ok": True})
        assert not graphql._es_graphql([1, 2])
        assert not graphql._es_graphql(None)


class TestLoQueSeCuenta:
    def _servicio(self, **extra) -> graphql.Servicio:
        servicio = graphql.Servicio(url=URL, **extra)
        servicio.operaciones = graphql.operaciones_del_esquema(ESQUEMA)
        return servicio

    def test_el_inventario_sale_siempre(self):
        ids = [f.check_id for f in graphql.hallazgos(self._servicio())]
        assert ids == ["graphql-inventario"]

    def test_el_inventario_lista_las_operaciones(self):
        """Es lo que sustituye al fuzzer que no se escribe: para ir a mano."""
        inventario = graphql.hallazgos(self._servicio())[0]
        assert "facturas(cliente: String, pagina: Int)" in inventario.description
        assert "borrarFactura(id: ID)" in inventario.description
        assert inventario.severity == Severity.INFO

    def test_dice_que_las_mutaciones_no_se_prueban(self):
        inventario = graphql.hallazgos(self._servicio())[0]
        assert "mutaciones no se prueban" in inventario.description

    def test_con_perfil_pasivo_dice_que_no_comprobo_nada(self):
        inventario = graphql.hallazgos(
            self._servicio(), argumentos_sin_probar=1,
            policy=get_policy("passive"))[0]
        assert "inventario, no una comprobación" in inventario.description

    def test_la_introspeccion_abierta_es_un_hallazgo(self):
        ids = [f.check_id for f in graphql.hallazgos(self._servicio(introspeccion=True))]
        assert "graphql-introspeccion-abierta" in ids

    def test_los_lotes_pesan_mas_que_la_introspeccion(self):
        """Saltarse un límite de intentos es peor que publicar el esquema."""
        hallazgos = {f.check_id: f for f in
                     graphql.hallazgos(self._servicio(lotes=True, introspeccion=True))}
        assert (hallazgos["graphql-lotes-permitidos"].severity
                > hallazgos["graphql-introspeccion-abierta"].severity)

    def test_responder_sin_sesion_es_lo_mas_grave_del_servicio(self):
        hallazgos = graphql.hallazgos(self._servicio(sin_sesion=True))
        sin_sesion = next(f for f in hallazgos if f.check_id == "graphql-sin-autenticar")
        assert sin_sesion.severity == Severity.HIGH


@pytest.mark.necesita_objetivo
class TestContraLaAplicacionDePruebas:
    @pytest.fixture
    def scope(self) -> Scope:
        return Scope.build([f"{BASE}/"])

    def _descubrir(self, scope, perfil="safe-active") -> graphql.Servicio:
        servicio = asyncio.run(graphql.descubrir(
            scope, get_policy(perfil), [f"{BASE}/"]))
        assert servicio is not None, "no se encontró el endpoint GraphQL"
        return servicio

    def test_encuentra_el_endpoint_y_lee_el_esquema(self, scope):
        servicio = self._descubrir(scope)
        assert servicio.url == URL
        assert servicio.introspeccion
        assert [o.nombre for o in servicio.consultas] == ["facturas", "usuario"]
        assert [o.nombre for o in servicio.mutaciones] == ["borrarFactura"]

    def test_detecta_que_acepta_lotes(self, scope):
        assert self._descubrir(scope).lotes

    def test_el_perfil_pasivo_no_manda_ninguna_sonda(self, scope):
        """Sin sondas activas solo se mira lo que el navegador ya vio usarse."""
        assert asyncio.run(graphql.descubrir(
            scope, get_policy("passive"), [f"{BASE}/"])) is None

    def test_lo_que_el_navegador_vio_se_examina_con_cualquier_perfil(self, scope):
        servicio = asyncio.run(graphql.descubrir(
            scope, get_policy("passive"), [f"{BASE}/"], vistos=[URL]))
        assert servicio is not None and servicio.introspeccion

    def test_encuentra_la_inyeccion_en_un_argumento(self, scope):
        """El argumento está dentro del texto de la consulta: nadie más llega ahí."""
        servicio = self._descubrir(scope)
        hallazgos, sin_probar = asyncio.run(
            graphql.probar_argumentos(servicio, get_policy("safe-active")))
        assert sin_probar == 0
        assert [f.check_id for f in hallazgos] == ["graphql-inyeccion-sql"]
        assert hallazgos[0].param == "facturas.cliente"
        assert hallazgos[0].severity == Severity.CRITICAL

    def test_no_se_prueban_las_mutaciones(self, scope):
        """Una mutación cambia datos, y esto corre contra la aplicación de verdad."""
        servicio = self._descubrir(scope)
        hallazgos, _ = asyncio.run(
            graphql.probar_argumentos(servicio, get_policy("aggressive")))
        assert all("borrar" not in (f.param or "") for f in hallazgos)

    def test_el_perfil_pasivo_no_prueba_nada_y_lo_dice(self, scope):
        servicio = self._descubrir(scope)
        hallazgos, sin_probar = asyncio.run(
            graphql.probar_argumentos(servicio, get_policy("passive")))
        assert hallazgos == []
        assert sin_probar == 2    # cliente y el id de usuario

    def test_las_sugerencias_de_campo_se_leen(self, scope):
        """El atajo conocido cuando la introspección está cerrada."""
        import httpx

        respuesta = httpx.post(URL, json={"query": "{usuariox}"}, timeout=10)
        mensaje = json.dumps(respuesta.json())
        assert "Did you mean" in mensaje
        servicio = graphql.Servicio(url=URL)
        asyncio.run(self._sugerencias(servicio))
        assert servicio.campos_insinuados

    @staticmethod
    async def _sugerencias(servicio: graphql.Servicio) -> None:
        async with graphql._cliente(get_policy("safe-active")) as cliente:
            servicio.campos_insinuados = await graphql._sugerencias(cliente, servicio.url)
