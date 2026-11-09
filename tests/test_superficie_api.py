"""La API que hay por debajo de la interfaz: captura, especificación, herramientas.

Lo que se comprueba aquí es por qué un escaneo de una aplicación con API salía
casi vacío: se veían las URL de las llamadas, pero no su método ni su cuerpo,
que es donde una API REST recibe los parámetros. Y lo que la interfaz no llega
a pulsar, no se veía en absoluto.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from crux.adapters.base import ScanContext
from crux.adapters.nuclei import NucleiApiAdapter
from crux.adapters.wapiti import WapitiAdapter
from crux.core.policy import get_policy
from crux.core.scope import Scope
from crux.modules import api
from crux.modules.crawler import Endpoint, leer_cuerpo

BASE = "http://127.0.0.1:8999"

ESPEC = {
    "openapi": "3.0.1",
    "info": {"title": "Pedidos"},
    "servers": [{"url": "/api/v2"}],
    "paths": {
        "/pedidos": {
            "get": {"parameters": [{"name": "estado", "in": "query",
                                    "schema": {"type": "string"}}]},
            "post": {"requestBody": {"content": {"application/json": {
                "schema": {"$ref": "#/components/schemas/Pedido"}}}}},
            "delete": {},
        },
        "/pedidos/{id}": {
            "get": {"parameters": [{"name": "id", "in": "path",
                                    "schema": {"type": "integer"}}]},
        },
        "/informes/{anio}/{mes}": {"get": {}},
    },
    "components": {"schemas": {"Pedido": {"type": "object", "properties": {
        "cliente": {"type": "string"},
        "total": {"type": "number"},
        "nota": {"type": "string", "example": "urgente"},
    }}}},
}


@pytest.fixture
def scope() -> Scope:
    return Scope.build([f"{BASE}/"])


def _por_metodo(espec: api.Especificacion, metodo: str) -> list[Endpoint]:
    return [e for e in espec.endpoints if e.metodo == metodo]


class TestLeerLaEspecificacion:
    def test_saca_rutas_metodos_y_parametros(self, scope):
        espec = api.interpretar(ESPEC, f"{BASE}/openapi.json", scope=scope)
        assert espec.formato == "OpenAPI 3.0.1"
        assert espec.titulo == "Pedidos"
        urls = {(e.metodo, e.url) for e in espec.endpoints}
        assert ("GET", f"{BASE}/api/v2/pedidos?estado=1") in urls
        assert ("POST", f"{BASE}/api/v2/pedidos") in urls

    def test_el_cuerpo_del_post_lleva_los_campos_del_esquema(self, scope):
        espec = api.interpretar(ESPEC, f"{BASE}/openapi.json", scope=scope)
        post = _por_metodo(espec, "POST")[0]
        assert post.params_cuerpo == ["cliente", "total", "nota"]
        assert post.tipo_contenido == "application/json"
        # El ejemplo que declara la especificación se usa tal cual: es el valor
        # que el desarrollador sabe que la API acepta.
        assert json.loads(post.cuerpo)["nota"] == "urgente"

    def test_un_post_con_cuerpo_cuenta_como_endpoint_con_parametros(self, scope):
        """Antes no: sin query se saltaba, y es donde más se inyecta."""
        from crux.modules.crawler import ResultadoCrawl

        espec = api.interpretar(ESPEC, f"{BASE}/openapi.json", scope=scope)
        resultado = ResultadoCrawl(endpoints=list(espec.endpoints))
        post = _por_metodo(espec, "POST")[0]
        assert post in resultado.con_parametros

    def test_rellena_los_parametros_de_ruta(self, scope):
        espec = api.interpretar(ESPEC, f"{BASE}/openapi.json", scope=scope)
        urls = {e.url for e in espec.endpoints}
        assert f"{BASE}/api/v2/pedidos/1" in urls
        # Sin declarar tampoco se queda la plantilla: «/informes/{anio}/{mes}»
        # no existe en ninguna aplicación.
        assert f"{BASE}/api/v2/informes/1/1" in urls
        assert not any("{" in u for u in urls)

    def test_los_metodos_que_borran_no_entran_sin_permiso(self, scope):
        espec = api.interpretar(ESPEC, f"{BASE}/openapi.json", scope=scope)
        assert _por_metodo(espec, "DELETE") == []
        assert espec.omitidos_destructivos == 1

        agresivo = api.interpretar(ESPEC, f"{BASE}/openapi.json", scope=scope,
                                   destructivos=True)
        assert len(_por_metodo(agresivo, "DELETE")) == 1

    def test_un_servidor_de_fuera_del_alcance_no_arrastra_el_escaneo(self, scope):
        """La especificación es dato del objetivo: no decide a quién se escanea."""
        datos = dict(ESPEC, servers=[{"url": "https://api.de-otro.com/api/v2"}])
        espec = api.interpretar(datos, f"{BASE}/openapi.json", scope=scope)
        assert espec.servidores_fuera == ["https://api.de-otro.com/api/v2"]
        assert all(e.url.startswith(BASE) for e in espec.endpoints)
        assert any(h.check_id == "api-declara-servidor-externo"
                   for h in api.hallazgos(espec))

    def test_un_servidor_del_alcance_se_respeta(self, scope):
        datos = dict(ESPEC, servers=[{"url": f"{BASE}/api/v3"}])
        espec = api.interpretar(datos, f"{BASE}/openapi.json", scope=scope)
        assert espec.servidores_fuera == []
        assert any(e.url.startswith(f"{BASE}/api/v3/") for e in espec.endpoints)

    def test_swagger_2_tambien(self, scope):
        datos = {
            "swagger": "2.0", "host": "127.0.0.1:8999", "basePath": "/api",
            "schemes": ["http"],
            "paths": {"/clientes": {"post": {"parameters": [
                {"name": "cuerpo", "in": "body", "schema": {"type": "object",
                 "properties": {"nombre": {"type": "string"}}}}]}}},
        }
        espec = api.interpretar(datos, f"{BASE}/swagger.json", scope=scope)
        assert espec.formato == "Swagger 2.0"
        post = _por_metodo(espec, "POST")[0]
        assert post.url == f"{BASE}/api/clientes"
        assert post.params_cuerpo == ["nombre"]


class TestQueEsUnaEspecificacion:
    def test_un_json_cualquiera_no_lo_es(self):
        """Confundirlos llenaría el informe de endpoints inventados."""
        assert api.interpretar_texto(json.dumps({"usuarios": [1, 2]})) is None
        assert api.interpretar_texto(json.dumps({"paths": {}})) is None
        assert api.interpretar_texto('{"openapi": "3.0.0"}') is None

    def test_yaml_tambien_vale(self):
        datos = api.interpretar_texto(
            "openapi: 3.0.0\npaths:\n  /x:\n    get: {}\n")
        assert datos is not None and "/x" in datos["paths"]

    def test_lo_que_no_se_puede_leer_se_dice(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp) / "no-es.json"
            ruta.write_text("{esto no es json")
            with pytest.raises(ValueError, match="no es una especificación"):
                api.leer_fichero(ruta)


class TestSanearParaLasHerramientas:
    """nuclei y wapiti sacan los objetivos del fichero que se les da."""

    def test_deja_un_solo_servidor_el_del_alcance(self):
        datos = dict(ESPEC, servers=[{"url": "https://api.de-otro.com/api/v2"},
                                     {"url": "/api/v2"}])
        saneada = api.sanear(datos, f"{BASE}/openapi.json")
        assert saneada["servers"] == [{"url": f"{BASE}/api/v2"}]

    def test_en_swagger_2_cambia_host_y_esquema(self):
        datos = {"swagger": "2.0", "host": "api.de-otro.com", "basePath": "/api",
                 "schemes": ["https"], "paths": {}}
        saneada = api.sanear(datos, f"{BASE}/swagger.json")
        assert saneada["host"] == "127.0.0.1:8999"
        assert saneada["schemes"] == ["http"]
        assert saneada["basePath"] == "/api"

    def test_no_toca_las_rutas(self):
        saneada = api.sanear(ESPEC, f"{BASE}/openapi.json")
        assert set(saneada["paths"]) == set(ESPEC["paths"])


class TestCuerpoDeLaPeticion:
    def test_json_da_sus_claves(self):
        claves, cuerpo = leer_cuerpo('{"q": "ana", "pagina": 2}', "application/json")
        assert claves == ["q", "pagina"]
        assert json.loads(cuerpo) == {"q": "ana", "pagina": 2}

    def test_los_valores_sensibles_no_se_guardan(self):
        """El cuerpo del acceso lleva la contraseña, y la superficie se persiste."""
        claves, cuerpo = leer_cuerpo(
            '{"usuario": "ana", "password": "s3creto", "datos": {"token": "abc"}}',
            "application/json")
        assert claves == ["usuario", "password", "datos"]
        guardado = json.loads(cuerpo)
        assert guardado["usuario"] == "ana"
        assert guardado["password"] == "***"
        assert guardado["datos"]["token"] == "***"
        assert "s3creto" not in cuerpo and "abc" not in cuerpo

    def test_formulario_urlencoded(self):
        claves, cuerpo = leer_cuerpo("usuario=ana&clave=s3creto",
                                     "application/x-www-form-urlencoded")
        assert claves == ["usuario", "clave"]
        assert "s3creto" not in cuerpo and "ana" in cuerpo

    def test_lo_que_no_son_parametros_se_dice_con_una_lista_vacia(self):
        """Inventar parámetros decide mal dónde van a inyectar las fases activas."""
        assert leer_cuerpo("--limite\r\nContenido", "multipart/form-data; boundary=x") == ([], "")
        assert leer_cuerpo("{roto", "application/json") == ([], "")
        assert leer_cuerpo("", "application/json") == ([], "")
        assert leer_cuerpo("\x00\x01binario", "application/octet-stream") == ([], "")

    def test_un_cuerpo_enorme_no_se_guarda(self):
        assert leer_cuerpo(json.dumps({"x": "a" * 9000}), "application/json") == ([], "")


class TestLoQueRecibenLasHerramientas:
    def _ctx(self, perfil: str = "safe-active", **descubierto) -> ScanContext:
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
        workdir.mkdir(parents=True, exist_ok=True)
        return ScanContext(
            scope=Scope.build([f"{BASE}/"]),
            policy=get_policy(perfil),
            workdir=workdir,
            discovered={"urls": [f"{BASE}/"], **descubierto},
        )

    def _espec_en_disco(self, ctx: ScanContext) -> Path:
        ruta = ctx.workdir / "openapi.json"
        ruta.write_text(json.dumps(api.sanear(ESPEC, f"{BASE}/openapi.json")))
        return ruta

    def test_wapiti_recibe_la_especificacion_y_los_puntos_de_arranque(self):
        ctx = self._ctx()
        ruta = self._espec_en_disco(ctx)
        ctx.discovered["api"] = {
            "especificacion": str(ruta),
            "endpoints": [{"url": f"{BASE}/api/v2/pedidos", "metodo": "POST"}],
        }
        argv = WapitiAdapter().build_argv(ctx)
        assert "--swagger" in argv and str(ruta) in argv
        # Su crawler no ejecuta JavaScript: sin esto, en una SPA no llega a
        # ninguna llamada de la API.
        assert argv[argv.index("-s") + 1] == f"{BASE}/api/v2/pedidos"

    def test_wapiti_no_arranca_en_una_url_fuera_del_alcance(self):
        ctx = self._ctx()
        ctx.discovered["api"] = {
            "especificacion": "",
            "endpoints": [{"url": "http://127.0.0.2:9/api/x", "metodo": "GET"}],
        }
        assert "-s" not in (WapitiAdapter().build_argv(ctx) or [])

    def test_nuclei_lee_la_especificacion_en_su_propio_modo(self):
        ctx = self._ctx("aggressive")
        ruta = self._espec_en_disco(ctx)
        ctx.discovered["api"] = {"especificacion": str(ruta), "endpoints": []}
        argv = NucleiApiAdapter().build_argv(ctx)
        assert argv[argv.index("-im") + 1] == "openapi"
        assert argv[argv.index("-l") + 1] == str(ruta)
        assert "-dast" in argv

    def test_sin_especificacion_no_hay_segunda_pasada(self):
        assert NucleiApiAdapter().build_argv(self._ctx("aggressive")) is None

    def test_fuzzear_es_inyectar_asi_que_pide_permiso(self):
        ctx = self._ctx("safe-active")
        ruta = self._espec_en_disco(ctx)
        ctx.discovered["api"] = {"especificacion": str(ruta), "endpoints": []}
        assert NucleiApiAdapter().build_argv(ctx) is None

    def test_las_dos_pasadas_no_se_pisan_los_ficheros(self):
        """Compartir el fichero de resultados duplicaría los hallazgos."""
        from crux.adapters.nuclei import NucleiAdapter

        ctx = self._ctx("aggressive")
        assert (ctx.artifact(f"{NucleiAdapter.name}-results.jsonl")
                != ctx.artifact(f"{NucleiApiAdapter.name}-results.jsonl"))


@pytest.mark.necesita_objetivo
class TestContraLaAplicacionDePruebas:
    """Contra la aplicación de pruebas, que publica una especificación y una API."""

    def test_la_especificacion_se_encuentra_sin_que_nadie_la_pase(self, scope):
        import asyncio

        espec = asyncio.run(api.descubrir(scope, get_policy("safe-active"),
                                          [f"{BASE}/"]))
        assert espec is not None
        assert espec.origen == f"{BASE}/openapi.json"
        rutas = {(e.metodo, e.url) for e in espec.endpoints}
        assert ("POST", f"{BASE}/api/buscar") in rutas
        assert ("GET", f"{BASE}/api/facturas?cliente=1") in rutas
        # El DELETE de la especificación no entra sin perfil agresivo.
        assert not any(m == "DELETE" for m, _ in rutas)

    def test_el_parametro_del_cuerpo_llega_a_las_fases_activas(self, scope):
        """`q` solo existe dentro del JSON de un POST: antes no había dónde probar."""
        import asyncio

        espec = asyncio.run(api.descubrir(scope, get_policy("safe-active"),
                                          [f"{BASE}/"]))
        buscar = next(e for e in espec.endpoints if e.url.endswith("/api/buscar"))
        assert buscar.params_cuerpo == ["q"]
        assert json.loads(buscar.cuerpo) == {"q": "ana"}

    def test_el_navegador_captura_el_metodo_y_el_cuerpo(self, scope):
        """La página /panel llama a su API desde JavaScript, como una SPA."""
        from crux.modules.crawler import Crawler

        resultado = Crawler(scope, get_policy("safe-active")).recorrer([f"{BASE}/panel"])
        api_vista = {(e.metodo, e.url.split("?")[0]): e for e in resultado.api}
        assert ("GET", f"{BASE}/api/facturas") in api_vista
        post = api_vista.get(("POST", f"{BASE}/api/buscar"))
        assert post is not None, "el POST se perdía: se apuntaba como GET sin parámetros"
        assert post.params_cuerpo == ["q", "clave"]
        assert post.tipo_contenido == "application/json"
        # Y el valor sensible no se guarda, aunque la clave sí.
        assert json.loads(post.cuerpo) == {"q": "ana", "clave": "***"}

    def test_un_parametro_que_solo_vive_en_el_cuerpo_se_audita(self, tmp_path):
        """La prueba de que todo esto sirve para algo.

        `q` solo existe dentro del JSON de `POST /api/buscar`: no hay enlace, no
        hay formulario, no está en ninguna URL. Antes del análisis de la API no
        se auditaba, y el informe de una aplicación así salía casi vacío.
        """
        import asyncio

        from crux.core.scan import run_web_scan

        resultado = asyncio.run(run_web_scan(
            [f"{BASE}/"], profile="aggressive", project_name="api",
            db=tmp_path / "api.db", only=["wapiti"], con_crawler=False,
        ))
        inyecciones = [f for f in resultado.findings
                       if "sql" in f.check_id and "/api/buscar" in f.target]
        assert inyecciones, "no se llegó al parámetro del cuerpo del POST"
        assert any(f.param == "q" for f in inyecciones)
        assert any(f.check_id == "api-analizada" for f in resultado.findings)
