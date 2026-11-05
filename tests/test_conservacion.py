"""Ningún hallazgo se pierde en silencio.

Este fichero existe por un fallo concreto: el grafo de superficie decía tener
trece hallazgos y dibujaba once, y los dos que faltaban eran los dos más
graves del escaneo. Nada lo avisaba. En una auditoría eso no es un defecto de
interfaz —es un informe que da por limpio lo que nadie miró—, y el mismo
patrón estaba repetido en los cinco adaptadores: si la herramienta corría pero
su salida no se podía leer, el adaptador devolvía cero hallazgos y la tarea
quedaba en «hecha».

La regla que se prueba aquí es una: **reducir está permitido, perder no**.
Colapsar dos avisos de la misma comprobación es correcto. Que la cuenta no
cuadre, o que algo desaparezca sin dejar constancia, no lo es.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from crux.adapters.base import ScanContext
from crux.adapters.gitleaks import GitleaksAdapter
from crux.adapters.nuclei import NucleiAdapter
from crux.adapters.semgrep import SemgrepAdapter
from crux.adapters.trivy import TrivyAdapter
from crux.adapters.wapiti import WapitiAdapter
from crux.core.policy import get_policy
from crux.core.runner import ToolRun
from crux.core.scan import run_web_scan
from crux.core.severity import Severity

OBJETIVO = "http://127.0.0.1:8999/"
pytestmark = pytest.mark.necesita_objetivo  # lanza escaneos reales


def contexto(tmp_path, **extra):
    return ScanContext(
        policy=get_policy("aggressive"), workdir=tmp_path, ruta=tmp_path, **extra
    )


def ejecucion(tmp_path, texto: str = "") -> ToolRun:
    salida = tmp_path / "stdout"
    salida.write_text(texto)
    return ToolRun(tool="x", argv=[], exit_code=0, stdout_path=salida,
                   stderr_path=tmp_path / "stderr", duration=0.1)


# ── Salida ilegible: cada adaptador tiene que decirlo ───────────────────────
ADAPTADORES = [
    (WapitiAdapter, "wapiti.json"),
    (GitleaksAdapter, "gitleaks.json"),
    (TrivyAdapter, "trivy.json"),
]


@pytest.mark.parametrize("clase,fichero", ADAPTADORES)
def test_un_informe_corrupto_sale_en_el_escaneo(clase, fichero, tmp_path):
    """Lo que no se puede leer no es lo mismo que lo que no existe.

    Si la herramienta se quedó sin espacio a mitad de escribir, o cambió de
    formato entre versiones, el escaneo tiene que decirlo. Antes devolvía cero
    hallazgos y la tarea quedaba en «hecha · 0 hallazgos».
    """
    (tmp_path / fichero).write_text('{"vulnerabilities": {"SQL Inj')  # truncado

    hallazgos = list(clase().parse(ejecucion(tmp_path), contexto(tmp_path)))
    avisos = [f for f in hallazgos if f.check_id == "salida-ilegible"]
    assert len(avisos) == 1, f"{clase.__name__} se calló una salida ilegible"
    assert avisos[0].severity >= Severity.MEDIUM
    assert avisos[0].extra["bytes"] > 0


@pytest.mark.parametrize("clase,fichero", ADAPTADORES)
def test_un_informe_que_no_existe_sale_en_el_escaneo(clase, fichero, tmp_path):
    """La herramienta corrió y no dejó informe: tampoco es «no hay nada»."""
    hallazgos = list(clase().parse(ejecucion(tmp_path), contexto(tmp_path)))
    avisos = [f for f in hallazgos if f.check_id == "salida-ilegible"]
    assert len(avisos) == 1
    assert fichero.split(".")[0] in avisos[0].description or "informe" in avisos[0].title


def test_semgrep_avisa_de_una_salida_que_no_es_json(tmp_path):
    """semgrep escribe por la salida estándar, no a un fichero."""
    hallazgos = list(SemgrepAdapter().parse(
        ejecucion(tmp_path, "Traceback (most recent call last):\n  boom"),
        contexto(tmp_path),
    ))
    assert [f for f in hallazgos if f.check_id == "salida-ilegible"]


def test_una_salida_vacia_no_inventa_un_aviso(tmp_path):
    """Un informe vacío sí puede significar «no hay nada»: no se avisa.

    Importa tanto como lo anterior. Un aviso que salta siempre deja de leerse,
    y entonces el día que signifique algo tampoco se leerá.
    """
    (tmp_path / "gitleaks.json").write_text("")
    hallazgos = list(GitleaksAdapter().parse(ejecucion(tmp_path), contexto(tmp_path)))
    assert not [f for f in hallazgos if f.check_id == "salida-ilegible"]


def test_nuclei_cuenta_las_lineas_que_no_pudo_leer(tmp_path):
    bueno = json.dumps({"template-id": "x", "info": {"name": "n", "severity": "low"},
                        "matched-at": "http://127.0.0.1:8999/"})
    (tmp_path / "nuclei-results.jsonl").write_text(bueno + "\n{roto\n{tambien-roto\n")

    hallazgos = list(NucleiAdapter().parse(ejecucion(tmp_path), contexto(tmp_path)))
    aviso = next(f for f in hallazgos if f.check_id == "salida-ilegible")
    assert aviso.extra["ilegibles"] == 2


def test_nuclei_cuenta_los_resultados_que_no_pudo_atribuir(tmp_path):
    """Un resultado sin plantilla no se puede atribuir a ninguna comprobación,
    así que no se puede enseñar: pero sí se puede contar."""
    (tmp_path / "nuclei-results.jsonl").write_text(
        json.dumps({"info": {"name": "sin plantilla"}}) + "\n"
    )
    hallazgos = list(NucleiAdapter().parse(ejecucion(tmp_path), contexto(tmp_path)))
    aviso = next(f for f in hallazgos if f.check_id == "salida-ilegible")
    assert aviso.extra["sin_traducir"] == 1


# ── Conservación de punta a punta ──────────────────────────────────────────
@pytest.fixture
def db(tmp_path):
    return tmp_path / "conservacion.db"


def test_la_cuenta_de_hallazgos_cuadra(db):
    """Lo que se guarda más lo que se redujo tiene que ser lo que se produjo.

    Y cada reducción tiene su nombre: colapso por huella o absorción por otro
    mejor explicado. Una diferencia sin nombre es un hallazgo perdido.
    """
    outcome = asyncio.run(run_web_scan(
        [OBJETIVO], profile="safe-active", project_name="p", db=db,
        only=[], con_crawler=False,
    ))

    from crux.core.models import Scan
    from crux.core.store import session_scope

    with session_scope(db) as s:
        conteo = s.get(Scan, outcome.scan_id).coverage["conteo"]

    assert conteo["producidos"] == (
        conteo["colapsados_por_huella"]
        + conteo["absorbidos_por_otro_mejor"]
        + conteo["guardados"]
    )
    assert "descuadre" not in conteo
    assert conteo["guardados"] == len(outcome.findings)


def test_lo_guardado_es_exactamente_lo_que_devuelve_el_escaneo(db):
    """El CLI enseña `outcome.findings` y la web lee la base. Si no coinciden,
    dos personas mirando el mismo escaneo ven cosas distintas."""
    from crux.core.models import FindingRecord
    from crux.core.store import session_scope
    from sqlalchemy import select

    outcome = asyncio.run(run_web_scan(
        [OBJETIVO], profile="safe-active", project_name="p", db=db,
        only=[], con_crawler=False,
    ))
    with session_scope(db) as s:
        en_base = {
            f.fingerprint for f in s.scalars(
                select(FindingRecord).where(FindingRecord.scan_id == outcome.scan_id)
            )
        }
    assert en_base == {f.fingerprint for f in outcome.findings}


def test_una_absorcion_sin_quien_la_cubra_se_denuncia(db, monkeypatch):
    """La comprobación que de verdad vale.

    Contar las bajas no demuestra nada: una baja indebida también se cuenta, y
    la resta sigue cuadrando. Fue el agujero de la primera versión de esta
    comprobación, y es el mismo razonamiento perezoso que dejó pasar lo de los
    trece hallazgos dibujados como once.

    Lo que se comprueba ahora es que el hallazgo que *supuestamente* cubre al
    absorbido siga en el informe. Aquí se simula una absorción que dice estar
    cubierta por algo que no existe.
    """
    import crux.core.scan as scan_mod

    original = scan_mod._absorb

    def absorbe_sin_cubrir(findings):
        conservados, absorbidos = original(findings)
        if len(conservados) > 1:
            victima = conservados.pop()
            absorbidos.append((victima, ("no-existe", "http://127.0.0.1:8999")))
        return conservados, absorbidos

    monkeypatch.setattr(scan_mod, "_absorb", absorbe_sin_cubrir)
    outcome = asyncio.run(run_web_scan(
        [OBJETIVO], profile="safe-active", project_name="p", db=db,
        only=[], con_crawler=False,
    ))

    # El hallazgo absorbido no vuelve —no se puede—, pero su ausencia deja de
    # ser invisible, que es lo único que se puede garantizar.
    descuadres = [f for f in outcome.findings if f.check_id == "descuadre-de-hallazgos"]
    assert len(descuadres) == 1
    assert descuadres[0].severity >= Severity.HIGH
    assert descuadres[0].extra["absorbidos_sin_quien_los_cubra"] == 1


def test_una_absorcion_legitima_no_denuncia_nada(db):
    """Y al revés: el escaneo normal absorbe y no se queja.

    Sin esto, el aviso anterior podría estar saltando siempre y el test de
    arriba pasaría igual sin probar nada.
    """
    outcome = asyncio.run(run_web_scan(
        [OBJETIVO], profile="safe-active", project_name="p", db=db,
        only=[], con_crawler=False,
    ))
    assert not [f for f in outcome.findings if f.check_id == "descuadre-de-hallazgos"]
