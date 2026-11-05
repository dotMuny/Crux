"""Lo que la API acepta y lo que rechaza al lanzar un escaneo.

La cola se sustituye por un doble: lo que se comprueba aquí es la puerta de
entrada —qué combinaciones de credenciales, roles y aislamiento tienen sentido
y qué se le devuelve a quien pide una que no—, no el escaneo.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from crux.web.routes.api import router


class ColaFalsa:
    """Registra lo que se le encola y devuelve algo con la forma de un trabajo."""

    def __init__(self) -> None:
        self.recibido: dict[str, Any] | None = None

    def enviar(self, targets, **kwargs):
        self.recibido = {"targets": list(targets), **kwargs}
        credenciales = kwargs.get("credenciales")
        roles = kwargs.get("roles") or []
        cola = self

        class _Trabajo:
            def como_dict(self) -> dict[str, Any]:
                return {
                    "id": "aaaa",
                    "targets": cola.recibido["targets"],
                    "tipo": kwargs.get("tipo", "web"),
                    "autenticacion": (
                        credenciales.modo if credenciales is not None else "ninguna"
                    ),
                    "roles": [n for n, _, _ in roles],
                    "sandbox": kwargs.get("sandbox", False),
                    "estado": "en-cola",
                }

        return _Trabajo()


@pytest.fixture
def cliente():
    app = FastAPI()
    app.include_router(router, prefix="/api")
    app.state.cola = ColaFalsa()
    with TestClient(app) as c:
        yield c


ACCESO = {"url_login": "http://10.20.4.9/login", "usuario": "ana", "clave": "s3cr3t"}


def test_el_acceso_por_formulario_llega_a_la_cola(cliente):
    r = cliente.post("/api/jobs", json={
        "targets": ["http://10.20.4.9/"], "credenciales": ACCESO,
    })
    assert r.status_code == 202
    credenciales = cliente.app.state.cola.recibido["credenciales"]
    assert credenciales.modo == "formulario"
    assert credenciales.clave == "s3cr3t"


def test_la_respuesta_no_devuelve_la_contrasena(cliente):
    r = cliente.post("/api/jobs", json={
        "targets": ["http://10.20.4.9/"], "credenciales": ACCESO,
        "roles": [
            {"nombre": "ana", "rol": "admin", "credenciales": ACCESO},
            {"nombre": "luis", "rol": "user",
             "credenciales": {**ACCESO, "usuario": "luis", "clave": "otra"}},
        ],
    })
    assert r.status_code == 202
    assert "s3cr3t" not in r.text and "otra" not in r.text
    assert json.loads(r.text)["autenticacion"] == "formulario"


def test_unas_credenciales_que_no_dicen_como_entrar_se_rechazan(cliente):
    """Un objeto de credenciales vacío no es «sin autenticar»: es una petición
    a medio rellenar, y aceptarla escanearía sin sesión sin decirlo."""
    r = cliente.post("/api/jobs", json={
        "targets": ["http://10.20.4.9/"], "credenciales": {"usuario": "ana"},
    })
    assert r.status_code == 400
    assert "cómo entrar" in r.json()["detail"]


def test_un_solo_rol_se_acepta_con_aviso(cliente):
    """Con un rol no hay comparación posible. Se dice, igual que en la línea de
    órdenes, en vez de ejecutar una fase que no puede dar resultado."""
    r = cliente.post("/api/jobs", json={
        "targets": ["http://10.20.4.9/"], "credenciales": ACCESO,
        "roles": [{"nombre": "ana", "rol": "admin", "credenciales": ACCESO}],
    })
    assert r.status_code == 202
    assert any("un solo rol" in a for a in r.json()["avisos"])


def test_dos_roles_no_avisan(cliente):
    r = cliente.post("/api/jobs", json={
        "targets": ["http://10.20.4.9/"], "credenciales": ACCESO,
        "roles": [
            {"nombre": "ana", "rol": "admin", "credenciales": ACCESO},
            {"nombre": "luis", "rol": "user",
             "credenciales": {**ACCESO, "usuario": "luis", "clave": "otra"}},
        ],
    })
    assert r.json()["avisos"] == []
    assert [n for n, _, _ in cliente.app.state.cola.recibido["roles"]] == ["ana", "luis"]


def test_un_rol_sin_forma_de_entrar_se_rechaza(cliente):
    r = cliente.post("/api/jobs", json={
        "targets": ["http://10.20.4.9/"], "credenciales": ACCESO,
        "roles": [{"nombre": "ana", "rol": "admin", "credenciales": {}}],
    })
    assert r.status_code == 400
    assert "ana" in r.json()["detail"]


@pytest.mark.parametrize("campo,valor", [
    ("credenciales", ACCESO),
    ("roles", [{"nombre": "ana", "rol": "admin", "credenciales": ACCESO}]),
    ("sandbox", True),
])
def test_lo_que_es_de_red_no_aplica_al_codigo(cliente, campo, valor):
    """Aceptarlo en silencio haría creer que se autenticó o que se aisló algo.
    El análisis de código no usa la red en ningún momento."""
    r = cliente.post("/api/jobs", json={
        "targets": ["tests/fixtures/vulncode"], "tipo": "code", campo: valor,
    })
    assert r.status_code == 400
    assert "no usa la red" in r.json()["detail"]


def test_el_aislamiento_se_comprueba_antes_de_encolar(cliente, monkeypatch):
    """Si el equipo no puede aislar, se dice en la respuesta.

    Encolar y fallar después obligaría a ir a buscar el motivo al historial de
    un trabajo que nunca arrancó. Y es 409, no 400: la petición es correcta, es
    el equipo el que no puede cumplirla.
    """
    import crux.core.sandbox as sandbox

    monkeypatch.setattr(sandbox, "comprobar_disponible", lambda: (False, "falta nft"))
    r = cliente.post("/api/jobs", json={
        "targets": ["http://10.20.4.9/"], "sandbox": True,
    })
    assert r.status_code == 409
    assert "falta nft" in r.json()["detail"]
    assert cliente.app.state.cola.recibido is None


def test_el_estado_del_aislamiento_se_puede_consultar(cliente):
    """La interfaz lo pregunta para no ofrecer una casilla que va a fallar."""
    r = cliente.get("/api/sandbox")
    assert r.status_code == 200
    assert set(r.json()) == {"disponible", "motivo"}
