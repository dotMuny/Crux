"""Diferencias entre escaneos: lo que cambió y lo que no se miró."""

from __future__ import annotations

import asyncio

import pytest

from crux.core.diff import comparar
from crux.core.scan import run_web_scan
from crux.core.severity import Severity

OBJETIVO = "http://127.0.0.1:8999/"


def escanear(db, perfil="safe-active", proyecto="p"):
    return asyncio.run(run_web_scan([OBJETIVO], profile=perfil, project_name=proyecto,
                                    db=db, only=[], con_crawler=False))


@pytest.fixture
def db(tmp_path):
    return tmp_path / "diff.db"


def test_dos_escaneos_iguales_no_dan_cambios(db):
    a = escanear(db)
    b = escanear(db)
    d = comparar(a.scan_id, b.scan_id, db=db)
    assert d.nuevos == [] and d.corregidos == []
    assert len(d.persistentes) == len(b.findings)
    assert not d.hay_regresion


def test_lo_que_no_se_comprobo_no_cuenta_como_corregido(db):
    """La distinción que evita cantar victoria.

    El sondeo CORS sólo se hace en perfiles que autorizan sondeo activo. Al
    pasar a pasivo, su hallazgo desaparece — pero no se ha arreglado nada.
    """
    a = escanear(db, "safe-active")
    b = escanear(db, "passive")
    d = comparar(a.scan_id, b.scan_id, db=db)

    sin_comprobar = {f["check_id"] for f in d.sin_comprobar}
    corregidos = {f["check_id"] for f in d.corregidos}
    assert "cors-reflects-any-origin" in sin_comprobar
    assert "cors-reflects-any-origin" not in corregidos


def test_no_se_comparan_proyectos_distintos(db):
    """Comparar hallazgos de dos aplicaciones distintas no significa nada."""
    a = escanear(db, proyecto="uno")
    b = escanear(db, proyecto="otro")
    with pytest.raises(ValueError, match="proyectos distintos"):
        comparar(a.scan_id, b.scan_id, db=db)


def test_un_escaneo_inexistente_se_rechaza(db):
    escanear(db)
    with pytest.raises(ValueError, match="no existe"):
        comparar(1, 999, db=db)


def test_un_hallazgo_nuevo_es_regresion(db):
    """Se simula inyectando una fila que el primer escaneo no tenía."""
    from crux.core.models import FindingRecord
    from crux.core.store import session_scope

    a = escanear(db)
    b = escanear(db)
    with session_scope(db) as s:
        fila = s.scalars(
            __import__("sqlalchemy").select(FindingRecord)
            .where(FindingRecord.scan_id == b.scan_id)
        ).first()
        s.add(FindingRecord(
            scan_id=b.scan_id, project_id=fila.project_id,
            fingerprint="0" * 32, source="passive", check_id="inventado",
            title="hallazgo nuevo", target="http://127.0.0.1:8999/x",
            severity=Severity.HIGH,
        ))

    d = comparar(a.scan_id, b.scan_id, db=db)
    assert [f["check_id"] for f in d.nuevos] == ["inventado"]
    assert d.hay_regresion


def test_el_escaneo_guarda_lo_que_comprobo(db):
    """Sin esa constancia el diff no podría distinguir corregido de no mirado."""
    from crux.core.models import Scan
    from crux.core.store import session_scope

    a = escanear(db)
    with session_scope(db) as s:
        cobertura = s.get(Scan, a.scan_id).coverage
    assert "passive" in cobertura["origenes"]
    assert "missing-security-headers" in cobertura["comprobaciones"]
