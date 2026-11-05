"""Comparación entre dos escaneos del mismo proyecto.

La parte delicada no es restar conjuntos de hallazgos: es no mentir sobre los
que desaparecen. Un hallazgo que estaba y ya no está puede haberse corregido o
puede no haberse vuelto a mirar —otro perfil, una herramienta ausente, un
adaptador que falló—, y las dos cosas se parecen mucho desde fuera.

Por eso cada escaneo guarda qué comprobó, y el diff separa explícitamente lo
que se corrigió de lo que simplemente dejó de analizarse.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select

from .models import FindingRecord, Scan
from .severity import Severity
from .store import session_scope

# Orígenes cuya cobertura se conoce comprobación a comprobación; para una
# herramienta externa sólo se sabe si se ejecutó.
ORIGENES_PROPIOS = frozenset({"passive", "probe", "authz", "jwt", "activos"})


@dataclass(slots=True)
class CambioDeSeveridad:
    fingerprint: str
    titulo: str
    objetivo: str
    antes: Severity
    ahora: Severity

    @property
    def empeora(self) -> bool:
        return self.ahora > self.antes


@dataclass(slots=True)
class Diferencia:
    scan_antes: int
    scan_ahora: int
    nuevos: list[dict[str, Any]] = field(default_factory=list)
    corregidos: list[dict[str, Any]] = field(default_factory=list)
    persistentes: list[dict[str, Any]] = field(default_factory=list)
    sin_comprobar: list[dict[str, Any]] = field(default_factory=list)
    cambios: list[CambioDeSeveridad] = field(default_factory=list)

    @property
    def resumen(self) -> dict[str, int]:
        return {
            "nuevos": len(self.nuevos),
            "corregidos": len(self.corregidos),
            "persistentes": len(self.persistentes),
            "sin_comprobar": len(self.sin_comprobar),
            "empeoran": sum(1 for c in self.cambios if c.empeora),
        }

    @property
    def hay_regresion(self) -> bool:
        return bool(self.nuevos) or any(c.empeora for c in self.cambios)


def _como_dict(fila: FindingRecord) -> dict[str, Any]:
    return {
        "fingerprint": fila.fingerprint,
        "source": fila.source,
        "check_id": fila.check_id,
        "title": fila.title,
        "target": fila.target,
        "severity": Severity(fila.severity).label,
    }


def _se_comprobo(fila: FindingRecord, cobertura: dict[str, Any]) -> bool:
    """¿El escaneo nuevo llegó a buscar esto?"""
    origenes = set(cobertura.get("origenes") or [])
    comprobaciones = set(cobertura.get("comprobaciones") or [])
    if fila.source not in origenes:
        return False
    if fila.source in ORIGENES_PROPIOS and comprobaciones:
        return fila.check_id in comprobaciones
    return True


def comparar(antes: int, ahora: int, db=None) -> Diferencia:
    """Compara dos escaneos por identificador."""
    with session_scope(db) as sesion:
        scan_antes = sesion.get(Scan, antes)
        scan_ahora = sesion.get(Scan, ahora)
        if scan_antes is None or scan_ahora is None:
            raise ValueError("alguno de los dos escaneos no existe")
        if scan_antes.project_id != scan_ahora.project_id:
            raise ValueError(
                "los escaneos son de proyectos distintos: comparar sus hallazgos "
                "no significaría nada"
            )

        filas_antes = {
            f.fingerprint: f for f in sesion.scalars(
                select(FindingRecord).where(FindingRecord.scan_id == antes))
        }
        filas_ahora = {
            f.fingerprint: f for f in sesion.scalars(
                select(FindingRecord).where(FindingRecord.scan_id == ahora))
        }
        cobertura = scan_ahora.coverage or {}

        diff = Diferencia(scan_antes=antes, scan_ahora=ahora)

        for huella, fila in filas_ahora.items():
            if huella not in filas_antes:
                diff.nuevos.append(_como_dict(fila))
                continue
            previo = filas_antes[huella]
            diff.persistentes.append(_como_dict(fila))
            if previo.severity != fila.severity:
                diff.cambios.append(CambioDeSeveridad(
                    fingerprint=huella, titulo=fila.title, objetivo=fila.target,
                    antes=Severity(previo.severity), ahora=Severity(fila.severity),
                ))

        for huella, fila in filas_antes.items():
            if huella in filas_ahora:
                continue
            # Aquí está la distinción que importa.
            if _se_comprobo(fila, cobertura):
                diff.corregidos.append(_como_dict(fila))
            else:
                diff.sin_comprobar.append(_como_dict(fila))

        orden = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        for lista in (diff.nuevos, diff.corregidos, diff.persistentes, diff.sin_comprobar):
            lista.sort(key=lambda d: orden.get(d["severity"], 9))
        return diff
