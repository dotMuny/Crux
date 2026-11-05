"""Esquema de la base local (SQLite). Un fichero por analista, sin servidor.

Nota de diseño: el estado de triaje **no** vive en la fila del hallazgo, sino en
`FindingState`, indexado por `(project_id, fingerprint)`. Así, marcar algo como
falso positivo o riesgo aceptado sobrevive a los reescaneos: la fila de `Finding`
es la observación de *un* escaneo, y `FindingState` es el juicio humano sobre esa
clase de hallazgo, que se mantiene.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    JSON,
    DateTime,
    Enum as SAEnum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from .findings import FindingStatus
from .severity import Confidence, Severity


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    type_annotation_map = {dict[str, Any]: JSON, list[str]: JSON, list[Any]: JSON}


class ScanKind(enum.StrEnum):
    WEB = "web"
    CODE = "code"


class RunStatus(enum.StrEnum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    CANCELLED = "cancelled"
    SKIPPED = "skipped"


def _enum(enum_class) -> SAEnum:
    """Columna de enum que devuelve el enum, no una cadena.

    Tipar la columna como String y anotarla como Mapped[MiEnum] no convierte
    nada al leer: vuelve un `str`. Con StrEnum las comparaciones por `==` siguen
    funcionando, así que el fallo no se nota — hasta que alguien escribe `is` y
    la condición es silenciosamente falsa. `native_enum=False` guarda el valor
    como texto (portable y legible en la base) y reconstruye el miembro al leer.
    """
    return SAEnum(
        enum_class,
        native_enum=False,
        length=32,
        values_callable=lambda e: [m.value for m in e],
    )


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class Project(Base, TimestampMixin):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(primary_key=True)
    slug: Mapped[str] = mapped_column(String(96), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(Text, default="")

    scans: Mapped[list["Scan"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    targets: Mapped[list["Target"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )


class Target(Base, TimestampMixin):
    """Un objetivo del inventario: una URL base, un host o un repositorio."""

    __tablename__ = "targets"
    __table_args__ = (UniqueConstraint("project_id", "raw", name="uq_target_per_project"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    raw: Mapped[str] = mapped_column(String(600))
    kind: Mapped[str] = mapped_column(String(16), default="web")  # web | host | repo
    scheme: Mapped[str | None] = mapped_column(String(8), default=None)
    host: Mapped[str | None] = mapped_column(String(255), default=None)
    port: Mapped[int | None] = mapped_column(Integer, default=None)
    base_path: Mapped[str] = mapped_column(String(600), default="/")
    # Huella tecnológica acumulada por el módulo `probe`: servidor, framework, versiones.
    fingerprint_data: Mapped[dict[str, Any]] = mapped_column(default=dict)

    project: Mapped[Project] = relationship(back_populates="targets")


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    kind: Mapped[ScanKind] = mapped_column(_enum(ScanKind))
    profile: Mapped[str] = mapped_column(String(32))
    status: Mapped[RunStatus] = mapped_column(_enum(RunStatus), default=RunStatus.PENDING)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    # Alcance resuelto y congelado al arrancar: objetivos, CIDRs e IPs ya resueltas.
    scope: Mapped[dict[str, Any]] = mapped_column(default=dict)
    # Versión de cada herramienta usada: sin esto un escaneo no es reproducible.
    tool_versions: Mapped[dict[str, Any]] = mapped_column(default=dict)
    # Qué se comprobó, que no es lo mismo que qué se encontró. Sin esto, un
    # diff entre dos escaneos no puede distinguir «esto se arregló» de «esto
    # no se volvió a mirar».
    coverage: Mapped[dict[str, Any]] = mapped_column(default=dict)
    # La superficie que el escaneo descubrió: URLs sondeadas y endpoints del
    # recorrido, con hallazgos o sin ellos. Se guarda porque la superficie de
    # ataque es lo que existe, no solo lo que está roto: una ruta sin hallazgos
    # también es sitio por donde se entra, y sin esto el grafo solo sabía
    # dibujar el árbol de los fallos.
    surface: Mapped[dict[str, Any]] = mapped_column(default=dict)
    error: Mapped[str | None] = mapped_column(Text, default=None)

    project: Mapped[Project] = relationship(back_populates="scans")
    tasks: Mapped[list["Task"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )
    findings: Mapped[list["FindingRecord"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class Task(Base, TimestampMixin):
    """Una unidad de trabajo del escaneo: una herramienta o un módulo propio."""

    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(120))
    tool: Mapped[str] = mapped_column(String(64))
    status: Mapped[RunStatus] = mapped_column(_enum(RunStatus), default=RunStatus.PENDING)
    # argv exacto ejecutado: es la prueba auditable de qué se lanzó contra el objetivo.
    argv: Mapped[list[str]] = mapped_column(default=list)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    exit_code: Mapped[int | None] = mapped_column(Integer, default=None)
    stdout_path: Mapped[str | None] = mapped_column(String(600), default=None)
    stderr_path: Mapped[str | None] = mapped_column(String(600), default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)
    progress: Mapped[float] = mapped_column(Float, default=0.0)

    scan: Mapped[Scan] = relationship(back_populates="tasks")


class FindingRecord(Base):
    """Observación de un hallazgo en un escaneo concreto."""

    __tablename__ = "findings"
    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_project_fp", "project_id", "fingerprint"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"))
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    fingerprint: Mapped[str] = mapped_column(String(32))

    source: Mapped[str] = mapped_column(String(32), index=True)
    check_id: Mapped[str] = mapped_column(String(200))
    title: Mapped[str] = mapped_column(String(400))
    description: Mapped[str] = mapped_column(Text, default="")
    remediation: Mapped[str] = mapped_column(Text, default="")

    # Severity es IntEnum y se guarda como entero: permite ORDER BY y rangos en SQL.
    severity: Mapped[Severity] = mapped_column(Integer, default=Severity.INFO)
    confidence: Mapped[Confidence] = mapped_column(Integer, default=Confidence.FIRM)
    cvss_vector: Mapped[str | None] = mapped_column(String(120), default=None)
    cvss_score: Mapped[float | None] = mapped_column(Float, default=None)

    target: Mapped[str] = mapped_column(String(600))
    param: Mapped[str | None] = mapped_column(String(200), default=None)
    cwe: Mapped[list[str]] = mapped_column(default=list)
    owasp: Mapped[list[str]] = mapped_column(default=list)
    references: Mapped[list[str]] = mapped_column(default=list)
    tags: Mapped[list[str]] = mapped_column(default=list)
    extra: Mapped[dict[str, Any]] = mapped_column(default=dict)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    scan: Mapped[Scan] = relationship(back_populates="findings")
    evidence: Mapped[list["EvidenceRecord"]] = relationship(
        back_populates="finding", cascade="all, delete-orphan"
    )


class FindingState(Base):
    """Juicio humano sobre una clase de hallazgo, persistente entre escaneos.

    Clave `(project_id, fingerprint)`. Es lo que hace que un falso positivo
    marcado hoy siga marcado en el escaneo de la semana que viene.
    """

    __tablename__ = "finding_states"
    __table_args__ = (
        UniqueConstraint("project_id", "fingerprint", name="uq_state_per_project"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id", ondelete="CASCADE"))
    fingerprint: Mapped[str] = mapped_column(String(32), index=True)
    # Quién produjo el hallazgo. Sin esto no se puede distinguir "ya no aparece
    # porque se corrigió" de "ya no aparece porque esta vez no se comprobó".
    source: Mapped[str] = mapped_column(String(32), default="")
    check_id: Mapped[str] = mapped_column(String(200), default="")
    status: Mapped[FindingStatus] = mapped_column(_enum(FindingStatus), default=FindingStatus.NEW)
    note: Mapped[str] = mapped_column(Text, default="")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    # Escaneo en el que se dejó de observar: alimenta el estado "corregido".
    last_scan_id: Mapped[int | None] = mapped_column(Integer, default=None)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )


class EvidenceRecord(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    kind: Mapped[str] = mapped_column(String(16))
    request: Mapped[str | None] = mapped_column(Text, default=None)
    response: Mapped[str | None] = mapped_column(Text, default=None)
    snippet: Mapped[str | None] = mapped_column(Text, default=None)
    path: Mapped[str | None] = mapped_column(String(600), default=None)
    meta: Mapped[dict[str, Any]] = mapped_column(default=dict)

    finding: Mapped[FindingRecord] = relationship(back_populates="evidence")


class Artifact(Base, TimestampMixin):
    """Fichero producido por un escaneo: informe, SBOM, captura, salida cruda."""

    __tablename__ = "artifacts"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(32))
    path: Mapped[str] = mapped_column(String(600))
    sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    meta: Mapped[dict[str, Any]] = mapped_column(default=dict)


class AuditEvent(Base):
    """Registro de decisiones sensibles: alcance aceptado, objetivos públicos
    permitidos a mano, herramientas ejecutadas. Es lo que se le muestra a
    cumplimiento cuando pregunta qué se tocó y con qué permiso."""

    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    scan_id: Mapped[int | None] = mapped_column(Integer, default=None, index=True)
    actor: Mapped[str] = mapped_column(String(120), default="")
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[dict[str, Any]] = mapped_column(default=dict)
