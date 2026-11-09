"""Panel, superficie y borrado: lo que la interfaz lee y lo que deja limpiar.

Estos tests hablan con la API de verdad, sobre una base temporal. El truco es
mover `paths.db_path` y soltar el motor global: las rutas usan `session_scope()`
sin argumento, así que sin esto escribirían en la base real del analista.
"""

from __future__ import annotations

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import select

from crux.core import paths, store
from crux.core.scan import run_web_scan
from crux.web.routes.api import router

OBJETIVO = "http://127.0.0.1:8999/"
pytestmark = pytest.mark.necesita_objetivo  # lanza escaneos reales


@pytest.fixture
def cliente(tmp_path, monkeypatch):
    base = tmp_path / "api.db"
    monkeypatch.setattr(paths, "db_path", lambda: base)
    monkeypatch.setattr(paths, "data_dir", lambda: tmp_path)
    monkeypatch.setattr(paths, "runs_dir", lambda: tmp_path / "runs")
    monkeypatch.setattr(paths, "reports_dir", lambda: tmp_path / "reports")
    (tmp_path / "runs").mkdir()
    (tmp_path / "reports").mkdir()
    store._engine = None
    store._Session = None
    # La aplicación real crea el esquema al arrancar (ver web/app.py); aquí se
    # monta solo el router, así que hay que hacerlo a mano.
    store.init_db()

    app = FastAPI()
    app.include_router(router, prefix="/api")
    try:
        with TestClient(app) as c:
            yield c
    finally:
        store._engine = None
        store._Session = None


def escanear(perfil="safe-active", proyecto="p"):
    """Un escaneo real contra el fixture, sin navegador ni adaptadores."""
    return asyncio.run(run_web_scan(
        [OBJETIVO], profile=perfil, project_name=proyecto, only=[], con_crawler=False,
    ))


# ── Superficie ──────────────────────────────────────────────────────────────
def test_la_superficie_incluye_rutas_sin_hallazgos(cliente):
    """Lo que de verdad cambia la vista: una ruta sondeada sin hallazgos
    también es superficie de ataque, y antes no existía en el grafo."""
    outcome = escanear()
    datos = cliente.get(f"/api/scans/{outcome.scan_id}/surface").json()

    assert datos["resumen"]["superficie_registrada"], "la superficie debe guardarse"
    rutas = [n["data"] for n in datos["nodes"] if n["data"]["tipo"] == "ruta"]
    assert rutas, "tiene que haber rutas"
    assert any(r["sin_hallazgos"] for r in rutas), (
        "alguna ruta sondeada no tiene hallazgos y debe salir igualmente"
    )
    assert datos["resumen"]["rutas"] >= datos["resumen"]["rutas_sin_hallazgos"] > 0


def test_cada_nodo_trae_su_detalle(cliente):
    """Pulsar un nodo no debe costar otra vuelta al servidor."""
    outcome = escanear()
    datos = cliente.get(f"/api/scans/{outcome.scan_id}/surface").json()

    por_tipo = {n["data"]["tipo"]: n["data"] for n in datos["nodes"]}
    assert {"host", "servicio", "ruta", "hallazgo"} <= set(por_tipo)
    rutas = [n["data"] for n in datos["nodes"] if n["data"]["tipo"] == "ruta"]
    assert all(r["detalle"]["url"].startswith("http") for r in rutas)
    # Una ruta sondeada trae su estado. Una que está en el grafo solo porque un
    # hallazgo la nombra —la especificación de la API, el endpoint GraphQL— no se
    # sondeó, y poner un estado ahí sería inventárselo.
    assert any(r["detalle"]["status"] is not None for r in rutas)
    hallazgo = por_tipo["hallazgo"]["detalle"]
    assert hallazgo["titulo"] and hallazgo["origen"] and hallazgo["severidad"]


def test_un_escaneo_viejo_sin_superficie_lo_dice(cliente):
    """Una base anterior a la columna no tiene superficie que enseñar. La
    interfaz debe poder decirlo en vez de dar a entender que no se halló nada."""
    from crux.core.models import Scan
    from crux.core.store import session_scope

    outcome = escanear()
    with session_scope() as s:
        s.get(Scan, outcome.scan_id).surface = {}

    datos = cliente.get(f"/api/scans/{outcome.scan_id}/surface").json()
    assert datos["resumen"]["superficie_registrada"] is False
    # Los hallazgos siguen dibujándose: lo que se pierde son las rutas vacías.
    assert any(n["data"]["tipo"] == "hallazgo" for n in datos["nodes"])


def test_un_escaneo_que_no_existe_da_404(cliente):
    assert cliente.get("/api/scans/9999/surface").status_code == 404


# ── Panel ───────────────────────────────────────────────────────────────────
def test_el_panel_cuenta_lo_que_queda_por_mirar(cliente):
    outcome = escanear()
    proyecto = cliente.get("/api/projects").json()[0]
    datos = cliente.get(f"/api/projects/{proyecto['id']}/metrics").json()

    r = datos["resumen"]
    assert r["hallazgos"] == len(outcome.findings)
    # Nadie ha triado nada todavía: está todo sin mirar y todo abierto.
    assert r["pendientes"] == r["hallazgos"] == r["abiertos"]
    assert r["ultimo"]["id"] == outcome.scan_id
    assert datos["por_herramienta"], "debe decir qué lo encontró"
    assert datos["cobertura"]["tareas"], "y qué se ejecutó"


def test_triar_baja_los_pendientes(cliente):
    escanear()
    proyecto = cliente.get("/api/projects").json()[0]
    escaneo = cliente.get("/api/scans").json()[0]
    hallazgos = cliente.get(f"/api/scans/{escaneo['id']}/findings").json()

    antes = cliente.get(f"/api/projects/{proyecto['id']}/metrics").json()["resumen"]
    cliente.patch(
        f"/api/projects/{proyecto['id']}/findings/{hallazgos[0]['fingerprint']}",
        json={"status": "false_positive", "note": ""},
    )
    despues = cliente.get(f"/api/projects/{proyecto['id']}/metrics").json()["resumen"]
    assert despues["pendientes"] == antes["pendientes"] - 1
    assert despues["abiertos"] == antes["abiertos"] - 1


def test_el_triaje_se_puede_deshacer(cliente):
    """Marcar algo por error tiene que poder deshacerse. Volver a «new» es un
    cambio de estado como cualquier otro, no un caso aparte."""
    escanear()
    proyecto = cliente.get("/api/projects").json()[0]
    escaneo = cliente.get("/api/scans").json()[0]
    huella = cliente.get(f"/api/scans/{escaneo['id']}/findings").json()[0]["fingerprint"]
    ruta = f"/api/projects/{proyecto['id']}/findings/{huella}"

    cliente.patch(ruta, json={"status": "confirmed", "note": "me lo creo"})
    assert cliente.patch(ruta, json={"status": "new", "note": ""}).json()["status"] == "new"

    hallazgos = cliente.get(f"/api/scans/{escaneo['id']}/findings").json()
    actual = next(h for h in hallazgos if h["fingerprint"] == huella)
    assert actual["status"] == "new" and actual["note"] == ""


def test_el_panel_compara_con_el_escaneo_anterior(cliente):
    escanear()
    escanear()
    proyecto = cliente.get("/api/projects").json()[0]
    cambio = cliente.get(f"/api/projects/{proyecto['id']}/metrics").json()["cambio"]
    assert cambio is not None
    assert cambio["nuevos"] == 0 and cambio["persistentes"] > 0


def test_sin_escaneo_anterior_no_hay_con_que_comparar(cliente):
    escanear()
    proyecto = cliente.get("/api/projects").json()[0]
    assert cliente.get(f"/api/projects/{proyecto['id']}/metrics").json()["cambio"] is None


def test_un_proyecto_que_no_existe_da_404(cliente):
    assert cliente.get("/api/projects/9999/metrics").status_code == 404


# ── Borrado ─────────────────────────────────────────────────────────────────
def test_borrar_un_escaneo_se_lleva_sus_hallazgos(cliente):
    outcome = escanear()
    (paths.runs_dir() / f"scan-{outcome.scan_id:06d}").mkdir(exist_ok=True)
    (paths.runs_dir() / f"scan-{outcome.scan_id:06d}" / "nuclei.json").write_text("[]")

    r = cliente.delete(f"/api/scans/{outcome.scan_id}")
    assert r.status_code == 200
    assert r.json()["borrados"] == [outcome.scan_id]
    assert cliente.get("/api/scans").json() == []
    assert cliente.get(f"/api/scans/{outcome.scan_id}/findings").status_code == 404
    assert not (paths.runs_dir() / f"scan-{outcome.scan_id:06d}").exists()


def test_borrar_conserva_el_triaje_que_sigue_sirviendo(cliente):
    """El juicio vive por huella y entre escaneos. Borrar el escaneo viejo no
    puede hacer que un falso positivo vuelva a aparecer como nuevo."""
    primero = escanear()
    segundo = escanear()
    proyecto = cliente.get("/api/projects").json()[0]
    huella = cliente.get(f"/api/scans/{segundo.scan_id}/findings").json()[0]["fingerprint"]
    cliente.patch(
        f"/api/projects/{proyecto['id']}/findings/{huella}",
        json={"status": "false_positive", "note": "ruido"},
    )

    cliente.delete(f"/api/scans/{primero.scan_id}")

    hallazgos = cliente.get(f"/api/scans/{segundo.scan_id}/findings").json()
    actual = next(h for h in hallazgos if h["fingerprint"] == huella)
    assert actual["status"] == "false_positive"
    assert actual["note"] == "ruido"


def test_borrarlo_todo_limpia_los_juicios_sin_hallazgo(cliente):
    """Un juicio sin ningún hallazgo detrás ya no le sirve a nadie, y dejarlo
    ensucia el recuento del panel para siempre."""
    outcome = escanear()
    proyecto = cliente.get("/api/projects").json()[0]
    huella = cliente.get(f"/api/scans/{outcome.scan_id}/findings").json()[0]["fingerprint"]
    cliente.patch(
        f"/api/projects/{proyecto['id']}/findings/{huella}",
        json={"status": "confirmed", "note": ""},
    )

    r = cliente.post("/api/scans/delete", json={"ids": [outcome.scan_id]})
    assert r.json()["triajes_huerfanos"] > 0
    assert cliente.get(f"/api/projects/{proyecto['id']}/metrics").json()["triaje"] == {}


def test_borrar_en_lote(cliente):
    a, b = escanear(), escanear()
    r = cliente.post("/api/scans/delete", json={"ids": [a.scan_id, b.scan_id, 9999]})
    assert sorted(r.json()["borrados"]) == sorted([a.scan_id, b.scan_id])
    assert r.json()["no_encontrados"] == [9999]


def test_borrar_lo_que_no_existe_da_404(cliente):
    assert cliente.post("/api/scans/delete", json={"ids": [9999]}).status_code == 404


def test_el_almacenamiento_dice_donde_esta_todo(cliente):
    """La interfaz responde a «¿dónde se guardan los escaneos?» sin mandar a
    nadie al README: en disco, no en el navegador."""
    escanear()
    datos = cliente.get("/api/storage").json()
    assert datos["escaneos"] == 1 and datos["hallazgos"] > 0
    assert {p["nombre"] for p in datos["piezas"]} == {
        "base de datos", "salidas de herramientas", "informes",
    }
    assert next(p for p in datos["piezas"] if p["nombre"] == "base de datos")["bytes"] > 0


def test_wapiti_cuelga_sus_hallazgos_de_un_host(tmp_path):
    """wapiti informa de «/search», no de la URL entera.

    Un objetivo sin host no se puede colgar de ningún servicio: en el grafo
    aparecía como un host llamado «/search» y en el panel como un objetivo
    aparte. El origen es el que se le pasó a ejecutar, así que completarlo no
    inventa nada.
    """
    from crux.adapters.wapiti import _absoluto

    class Ctx:
        urls = ["http://10.20.4.9:8080/app/"]

    assert _absoluto("/search", Ctx()) == "http://10.20.4.9:8080/search"
    assert _absoluto("search", Ctx()) == "http://10.20.4.9:8080/search"
    # Lo que ya es absoluto no se toca, y sin objetivo no hay nada que añadir.
    assert _absoluto("http://otro/x", Ctx()) == "http://otro/x"
    assert _absoluto("", Ctx()) == ""

    class SinUrls:
        urls: list[str] = []

    assert _absoluto("/search", SinUrls()) == "/search"


def test_el_grafo_no_pierde_ningun_hallazgo(cliente):
    """El resumen decía 13 y el grafo dibujaba 11.

    Un hallazgo cuyo objetivo llega sin host —hay herramientas que informan de
    «/search» y no de la URL entera— no se puede colgar de ningún servicio, y
    se estaba descartando en silencio. Desaparecían justo los dos más graves,
    que eran los de wapiti. Que no se sepa dónde vive un hallazgo no es motivo
    para no enseñarlo.
    """
    from crux.core.models import FindingRecord
    from crux.core.store import session_scope

    outcome = escanear()
    with session_scope() as s:
        fila = s.scalars(
            select(FindingRecord).where(FindingRecord.scan_id == outcome.scan_id)
        ).first()
        fila.target = "/search"
        huella = fila.fingerprint

    datos = cliente.get(f"/api/scans/{outcome.scan_id}/surface").json()
    dibujados = [n["data"] for n in datos["nodes"] if n["data"]["tipo"] == "hallazgo"]
    assert len(dibujados) == datos["resumen"]["hallazgos"], (
        "el grafo tiene que dibujar tantos hallazgos como dice tener"
    )
    assert datos["resumen"]["hallazgos_sin_ubicar"] == 1
    suelto = next(n for n in dibujados if n["fingerprint"] == huella)
    assert suelto["detalle"]["objetivo"] == "/search"
    # Y cuelga de algo que explica por qué está aparte.
    padres = [e["data"]["source"] for e in datos["edges"]
              if e["data"]["target"] == f"f{suelto['finding_id']}"]
    assert padres == ["sin-host"]
