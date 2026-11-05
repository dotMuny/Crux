"""El ciclo de vida de un hallazgo entre escaneos.

Es la mitad del diseño que no se ve en una sola ejecución: qué es nuevo, qué
sigue ahí, qué se corrigió, y qué juicio humano se respeta.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import select

from crux.core.findings import FindingStatus
from crux.core.models import FindingState
from crux.core.scan import run_web_scan
from crux.core.store import session_scope

OBJETIVO = "http://127.0.0.1:8999/"
pytestmark = pytest.mark.necesita_objetivo  # lanza escaneos reales


def escanear(db, perfil="safe-active", proyecto="p"):
    """Escaneo sin adaptadores externos: aquí se prueba el ciclo, no la detección."""
    return asyncio.run(
        # Sin navegador: aquí se prueba el ciclo de triaje, no la detección,
        # y el crawler multiplica por diez lo que tarda la suite.
        run_web_scan([OBJETIVO], profile=perfil, project_name=proyecto, db=db,
                     only=[], con_crawler=False)
    )


@pytest.fixture
def db(tmp_path):
    return tmp_path / "triaje.db"


def test_el_segundo_escaneo_no_repite_todo_como_nuevo(db):
    primero = escanear(db)
    assert primero.new == len(primero.findings) and primero.recurring == 0

    segundo = escanear(db)
    assert segundo.new == 0
    assert segundo.recurring == len(segundo.findings)


def test_el_falso_positivo_sobrevive_al_reescaneo(db):
    escanear(db)
    with session_scope(db) as s:
        estado = s.scalars(select(FindingState)).first()
        estado.status = FindingStatus.FALSE_POSITIVE
        estado.note = "confirmado con el equipo"
        fp = estado.fingerprint

    escanear(db)
    with session_scope(db) as s:
        estado = s.scalar(select(FindingState).where(FindingState.fingerprint == fp))
        assert estado.status is FindingStatus.FALSE_POSITIVE
        assert estado.note == "confirmado con el equipo"


def test_cambiar_de_perfil_no_inventa_correcciones(db):
    """El fallo más peligroso que tuvo esta herramienta.

    El sondeo CORS solo se hace si el perfil autoriza sondeo activo. Al pasar a
    perfil pasivo el hallazgo desaparecía, y el barrido lo marcaba corregido sin
    haberlo vuelto a comprobar. Decirle a un equipo que una vulnerabilidad está
    resuelta cuando no se probó es peor que no decir nada.
    """
    escanear(db, "safe-active")
    with session_scope(db) as s:
        cors = s.scalar(
            select(FindingState).where(FindingState.check_id == "cors-reflects-any-origin")
        )
        assert cors is not None, "el escaneo activo debería detectar el CORS permisivo"

    pasivo = escanear(db, "passive")
    assert pasivo.fixed == 0, "no se corrigió nada: solo se comprobó menos"

    with session_scope(db) as s:
        cors = s.scalar(
            select(FindingState).where(FindingState.check_id == "cors-reflects-any-origin")
        )
        assert cors.status is not FindingStatus.FIXED


def test_al_volver_al_perfil_completo_el_hallazgo_es_recurrente(db):
    escanear(db, "safe-active")
    escanear(db, "passive")
    vuelta = escanear(db, "safe-active")
    assert vuelta.new == 0, "no debe reaparecer como nuevo: nunca se fue"
    assert vuelta.recurring == len(vuelta.findings)


def test_el_estado_guarda_quien_produjo_el_hallazgo(db):
    """Sin origen ni comprobación no se puede distinguir 'ya no está porque se
    arregló' de 'ya no está porque no se buscó'."""
    escanear(db)
    with session_scope(db) as s:
        for estado in s.scalars(select(FindingState)):
            assert estado.source, "falta el origen"
            assert estado.check_id, "falta la comprobación"


def test_una_regresion_deja_de_estar_corregida(db):
    """Si algo se dio por corregido y vuelve a aparecer, no puede seguir
    marcado como resuelto."""
    escanear(db)
    with session_scope(db) as s:
        estado = s.scalars(select(FindingState)).first()
        estado.status = FindingStatus.FIXED
        fp = estado.fingerprint

    escanear(db)
    with session_scope(db) as s:
        estado = s.scalar(select(FindingState).where(FindingState.fingerprint == fp))
        assert estado.status is FindingStatus.NEW
