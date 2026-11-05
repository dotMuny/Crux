"""Contrato de los adaptadores de herramienta.

Un adaptador hace tres cosas y nada más: decide el argv a partir del contexto,
declara su política de egress, y traduce la salida a `Finding`. Toda la ejecución
la hace el `Runner`, de modo que no hay forma de que un adaptador se salte la
validación de egress.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Iterable

from ..core.egress import EgressPolicy
from ..core.findings import Finding
from ..core.policy import Policy
from ..core.runner import Runner, ToolMissing, ToolRun, tool_version
from ..core.scope import Scope


@dataclass(slots=True)
class ScanContext:
    """Todo lo que un adaptador necesita saber del escaneo en curso.

    Sirve a los dos pilares. Un escaneo web lleva `scope` y no lleva `ruta`; uno
    de código, al revés. No se inventa un alcance de red falso para analizar un
    repositorio: decir que el objetivo es 127.0.0.1 cuando no se toca la red
    sería mentir en el registro de auditoría.
    """

    policy: Policy
    workdir: Path
    scope: Scope | None = None
    # Raíz del código a analizar, en los escaneos del pilar de código.
    ruta: Path | None = None
    project_id: int | None = None
    scan_id: int | None = None
    # Resultados de fases anteriores que otros adaptadores pueden aprovechar:
    # URLs del crawler, parámetros descubiertos, huella tecnológica.
    discovered: dict[str, Any] = field(default_factory=dict)

    @property
    def urls(self) -> list[str]:
        """URLs a atacar: las del alcance más las que haya descubierto el crawler."""
        crawled = self.discovered.get("urls") or []
        propias = self.scope.urls if self.scope is not None else []
        return list(dict.fromkeys([*propias, *crawled]))

    @property
    def raiz(self) -> Path:
        """Raíz del código. Lanza si se pide en un escaneo que no es de código."""
        if self.ruta is None:
            raise RuntimeError(
                "este adaptador analiza código y el escaneo no tiene ruta de origen"
            )
        return self.ruta

    def artifact(self, name: str) -> Path:
        return self.workdir / name


class SalidaIlegible(Exception):
    """La herramienta corrió pero su salida no se pudo leer."""


class Adapter(ABC):
    """Base de todo adaptador de herramienta externa."""

    name: ClassVar[str]
    binary: ClassVar[str]
    kind: ClassVar[str] = "web"               # "web" | "code"
    egress: ClassVar[EgressPolicy] = EgressPolicy()
    version_argv: ClassVar[tuple[str, ...]] = ("--version",)
    # Si la herramienta devuelve códigos distintos de 0 en ejecuciones normales
    # (nikto y wapiti lo hacen), se listan aquí para no tratarlo como fallo.
    ok_exit_codes: ClassVar[tuple[int, ...]] = (0,)

    def available(self) -> bool:
        import shutil

        return shutil.which(self.binary) is not None

    # ── Leer la salida sin perderla en silencio ────────────────────────────
    def leer_json(self, origen: Path | str, *, vacio: Any = None) -> tuple[Any, Finding | None]:
        """Lee el informe de la herramienta. Devuelve `(datos, aviso)`.

        Por qué existe. Los cinco adaptadores hacían lo mismo: si el fichero no
        estaba o no se podía interpretar, `return` y a otra cosa. El escaneo
        terminaba bien, la tarea quedaba en «hecha · 0 hallazgos», y quien leía
        el informe entendía «la herramienta no encontró nada» cuando lo cierto
        era «no se pudo leer lo que encontró». Es el mismo error que dibujar
        once hallazgos y decir trece, y en una auditoría cuesta lo mismo: se
        da por limpio algo que nadie miró.

        Ahora la imposibilidad de leer la salida es un hallazgo sobre el propio
        escaneo, que sale en el informe, en la interfaz y en el recuento.
        """
        import json

        ruta = Path(origen) if not isinstance(origen, str) else None
        if ruta is not None:
            if not ruta.exists():
                return vacio, self.aviso_de_salida(
                    f"{self.name} no dejó su informe en {ruta.name}",
                    "La herramienta se ejecutó pero no escribió el fichero de "
                    "resultados que se le pidió. Lo que haya encontrado no está "
                    "en este escaneo.",
                )
            texto = ruta.read_text(encoding="utf-8", errors="replace")
            donde = ruta.name
        else:
            texto = str(origen)
            donde = "la salida estándar"

        if not texto.strip():
            # Un informe vacío es legítimo —puede no haber hallazgos—, así que
            # no se avisa: lo que no es legítimo es no poder interpretarlo.
            return vacio, None
        try:
            return json.loads(texto), None
        except json.JSONDecodeError as exc:
            return vacio, self.aviso_de_salida(
                f"No se pudo interpretar la salida de {self.name}",
                f"El contenido de {donde} no es JSON válido ({exc}). "
                f"Son {len(texto)} bytes que esta herramienta produjo y que "
                "este escaneo no ha podido leer, así que sus hallazgos —si los "
                "hubiera— faltan del informe.",
                detalle={"bytes": len(texto), "fichero": donde,
                         "error": str(exc), "inicio": texto[:200]},
            )

    def aviso_de_salida(self, titulo: str, descripcion: str,
                        detalle: dict[str, Any] | None = None) -> Finding:
        """Hallazgo sobre el escaneo, no sobre el objetivo.

        Severidad media y no informativa a propósito: no saber si una
        herramienta encontró algo es un agujero de cobertura, y un agujero de
        cobertura que pasa desapercibido es justo lo que convierte un informe
        en una mentira cómoda.
        """
        from ..core.severity import Confidence, Severity

        return Finding(
            source=self.name,
            check_id="salida-ilegible",
            title=titulo,
            description=descripcion,
            remediation=(
                f"Repite el escaneo. Si vuelve a pasar, ejecuta {self.binary} a "
                "mano con los mismos argumentos (están en el registro de tareas "
                "de este escaneo) y mira qué devuelve: suele ser una versión de "
                "la herramienta que cambió su formato de salida, o que se quedó "
                "sin espacio o sin tiempo a mitad de escribir."
            ),
            target=self.name,
            severity=Severity.MEDIUM,
            confidence=Confidence.CERTAIN,
            tags=["cobertura"],
            extra=detalle or {},
        )

    def version(self) -> str | None:
        return tool_version(self.binary, (self.binary, *self.version_argv))

    @abstractmethod
    def build_argv(self, ctx: ScanContext) -> list[str] | None:
        """argv a ejecutar, o None si con este contexto no hay nada que hacer."""

    @abstractmethod
    def parse(self, run: ToolRun, ctx: ScanContext) -> Iterable[Finding]:
        """Traduce la salida de la herramienta a hallazgos normalizados."""

    async def execute(self, ctx: ScanContext, runner: Runner) -> list[Finding]:
        """Flujo estándar: argv → validación de egress → ejecución → parseo."""
        argv = self.build_argv(ctx)
        if not argv:
            return []
        run = await runner.run(
            tool=self.name,
            argv=argv,
            egress=self.egress,
            timeout=ctx.policy.task_timeout,
        )
        if run.exit_code not in self.ok_exit_codes and not run.stdout.strip():
            # Sin salida y con código inesperado: no hay nada que parsear, y
            # tragárselo en silencio escondería un fallo de configuración.
            raise RuntimeError(
                f"{self.name} terminó con código {run.exit_code} y sin salida. "
                f"stderr: {run.stderr.strip()[:500] or '(vacío)'}"
            )
        return list(self.parse(run, ctx))


_REGISTRY: dict[str, type[Adapter]] = {}


def register(cls: type[Adapter]) -> type[Adapter]:
    """Decorador de registro, para que el CLI y la UI descubran los adaptadores."""
    _REGISTRY[cls.name] = cls
    return cls


def all_adapters() -> dict[str, type[Adapter]]:
    return dict(_REGISTRY)


def get_adapter(name: str) -> Adapter:
    return _REGISTRY[name]()


__all__ = [
    "Adapter",
    "ScanContext",
    "ToolMissing",
    "ToolRun",
    "all_adapters",
    "get_adapter",
    "register",
]
