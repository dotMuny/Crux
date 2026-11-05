"""Comprobaciones que envían cargas. Lo que prueban y lo que no tocan."""

from __future__ import annotations

import asyncio

import pytest

from crux.core.policy import get_policy
from crux.core.scope import Scope
from crux.modules.activos import (
    MARCADOR, PARAMS_DE_REDIRECCION, _sustituir, comprobar_redireccion_abierta,
)

BASE = "http://127.0.0.1:8999"


@pytest.fixture
def scope():
    return Scope.build([f"{BASE}/"])


class TestSeleccionDeParametros:
    @pytest.mark.parametrize("nombre", [
        "next", "url", "redirect", "redirect_uri", "return_to", "dest",
        "continue", "target", "callback", "NEXT", "ReturnUrl",
    ])
    def test_se_prueban_los_que_parecen_destino(self, nombre):
        assert PARAMS_DE_REDIRECCION.match(nombre)

    @pytest.mark.parametrize("nombre", ["name", "q", "id", "format", "owner", "page"])
    def test_no_se_toca_lo_que_no_lo_parece(self, nombre):
        """Enviar una URL externa en cada parámetro sería fuzzing a ciegas y
        ruido para el objetivo."""
        assert not PARAMS_DE_REDIRECCION.match(nombre)

    def test_la_sustitucion_conserva_el_resto_de_la_query(self):
        url = _sustituir(f"{BASE}/go?next=/inicio&lang=es", "next", MARCADOR)
        assert "lang=es" in url and "crux-redirect-probe.invalid" in url

    def test_el_parametro_se_anade_si_no_estaba(self):
        assert "next=" in _sustituir(f"{BASE}/go", "next", MARCADOR)


class TestRedireccionAbierta:
    def test_el_perfil_pasivo_no_envia_nada(self, scope):
        """En pasivo no se manda una sola carga, aunque haya candidatos."""
        eps = [{"url": f"{BASE}/go?next=/x", "params": ["next"]}]
        resultado = asyncio.run(
            comprobar_redireccion_abierta(scope, get_policy("passive"), eps)
        )
        assert resultado == []

    def test_se_detecta_el_destino_arbitrario(self, scope):
        eps = [{"url": f"{BASE}/go?next=/mis-facturas", "params": ["next"]}]
        hallazgos = asyncio.run(
            comprobar_redireccion_abierta(scope, get_policy("safe-active"), eps)
        )
        assert len(hallazgos) == 1
        hallazgo = hallazgos[0]
        assert hallazgo.check_id == "open-redirect"
        assert hallazgo.param == "next"
        assert hallazgo.cwe == ["CWE-601"]

    def test_un_parametro_que_no_redirige_no_da_hallazgo(self, scope):
        eps = [{"url": f"{BASE}/greet?name=x", "params": ["name"]}]
        assert asyncio.run(
            comprobar_redireccion_abierta(scope, get_policy("safe-active"), eps)
        ) == []

    def test_no_se_sale_del_alcance_ni_para_comprobarlo(self, scope):
        """El marcador usa un dominio reservado por RFC 2606: no resuelve, no
        existe y no puede ser de nadie. Y la redirección no se sigue."""
        assert MARCADOR.endswith(("/comprobacion",))
        assert ".invalid" in MARCADOR
        assert not scope.allows_url(MARCADOR)

    def test_un_endpoint_fuera_de_alcance_se_descarta(self, scope):
        eps = [{"url": "http://otro-host:9999/go?next=/x", "params": ["next"]}]
        assert asyncio.run(
            comprobar_redireccion_abierta(scope, get_policy("safe-active"), eps)
        ) == []
