"""Ejecución de herramientas externas, siempre bajo política de egress.

Ninguna parte del sistema lanza un subproceso directamente: todo pasa por aquí,
que es el único sitio donde se valida el argv y se construye el entorno. Así la
garantía de egress se comprueba en un solo punto en lugar de confiar en que cada
adaptador se acuerde.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import signal
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Final, Mapping, Sequence

from .egress import EgressPolicy, clean_env

# Cuánta salida se guarda en memoria además del fichero. Las herramientas de
# descubrimiento pueden escupir cientos de MB; el fichero es la fuente, esto es
# solo para diagnóstico rápido.
_MAX_INLINE_OUTPUT = 4 * 1024 * 1024


class ToolMissing(RuntimeError):
    """El binario no está instalado. `crux doctor` lo reporta antes de escanear."""


@dataclass(slots=True)
class ToolRun:
    """Resultado de una ejecución. Es la entrada de `Adapter.parse`."""

    tool: str
    argv: list[str]
    exit_code: int | None
    stdout_path: Path
    stderr_path: Path
    duration: float
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out

    def text(self) -> str:
        """Salida estándar completa, leyéndola del fichero si hiciera falta."""
        if self.stdout:
            return self.stdout
        try:
            return self.stdout_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def lines(self) -> list[str]:
        return [line for line in self.text().splitlines() if line.strip()]


@dataclass(slots=True)
class Runner:
    """Lanza herramientas. Un `Runner` por escaneo, con su directorio de salidas."""

    workdir: Path
    # Callback de auditoría: recibe (acción, detalle) y lo persiste quien lo pase.
    audit: Callable[[str, dict[str, object]], None] | None = None
    _counter: int = field(default=0, repr=False)

    def __post_init__(self) -> None:
        self.workdir.mkdir(parents=True, exist_ok=True)

    def resolve_binary(self, binary: str) -> str:
        path = shutil.which(binary)
        if path is None:
            raise ToolMissing(
                f"{binary!r} no está en el PATH. Ejecuta `crux doctor` para ver qué falta."
            )
        return path

    async def run(
        self,
        *,
        tool: str,
        argv: Sequence[str],
        egress: EgressPolicy,
        timeout: float | int = 0,
        cwd: Path | None = None,
        env_extra: Mapping[str, str] | None = None,
        stdin: bytes | None = None,
    ) -> ToolRun:
        """Ejecuta una herramienta. El argv se valida **antes** de resolver el binario.

        Ese orden es deliberado: una violación de política debe fallar igual esté
        la herramienta instalada o no, para que los tests la detecten en cualquier
        máquina.
        """
        argv = list(argv)
        egress.check(tool, argv)
        binary = self.resolve_binary(argv[0])

        self._counter += 1
        stem = f"{self._counter:03d}-{tool}"
        stdout_path = self.workdir / f"{stem}.out"
        stderr_path = self.workdir / f"{stem}.err"

        if self.audit is not None:
            self.audit("tool.exec", {"tool": tool, "argv": argv})

        started = time.monotonic()
        with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
            process = await asyncio.create_subprocess_exec(
                binary,
                *argv[1:],
                stdout=out,
                stderr=err,
                stdin=asyncio.subprocess.PIPE if stdin else asyncio.subprocess.DEVNULL,
                env=clean_env(env_extra),
                cwd=str(cwd) if cwd else None,
                # Sesión propia para poder matar al proceso y a todos sus hijos:
                # varias de estas herramientas lanzan subprocesos a su vez.
                start_new_session=True,
            )
            timed_out = False
            try:
                if stdin:
                    await asyncio.wait_for(
                        process.communicate(stdin), timeout=timeout or None
                    )
                else:
                    await asyncio.wait_for(process.wait(), timeout=timeout or None)
            except asyncio.TimeoutError:
                timed_out = True
                await self._terminate(process)

        duration = time.monotonic() - started
        run = ToolRun(
            tool=tool,
            argv=argv,
            exit_code=process.returncode,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            duration=duration,
            timed_out=timed_out,
        )
        run.stdout = _read_capped(stdout_path)
        run.stderr = _read_capped(stderr_path)
        return run

    async def _terminate(self, process: asyncio.subprocess.Process) -> None:
        """SIGTERM al grupo, y SIGKILL si no se va en 5 segundos."""
        if process.returncode is not None:
            return
        try:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            process.terminate()
        try:
            await asyncio.wait_for(process.wait(), timeout=5)
        except asyncio.TimeoutError:
            try:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                process.kill()
            await process.wait()

    def run_sync(self, **kwargs: object) -> ToolRun:
        """Envoltorio síncrono, para el CLI."""
        return asyncio.run(self.run(**kwargs))  # type: ignore[arg-type]


def _read_capped(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            data = handle.read(_MAX_INLINE_OUTPUT)
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


# Flag de versión de cada herramienta. No todas usan `--version`, y acertar
# importa: con el flag equivocado algunas imprimen su ayuda o su arte ASCII.
VERSION_FLAGS: Final[dict[str, tuple[str, ...]]] = {
    "nuclei": ("-version",),
    "nikto": ("-Version",),
    "dalfox": ("version",),
    "wafw00f": ("-v",),
    "sqlmap": ("--version",),
    "wapiti": ("--version",),
}

_ANSI = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")
# Una línea de versión creíble: contiene algo con forma de `1.2` o `v1.2.3`.
_VERSION_LINE = re.compile(r"v?\d+\.\d+(\.\d+)?")


def version_flags(binary: str) -> tuple[str, ...]:
    return VERSION_FLAGS.get(binary, ("--version",))


def tool_version(binary: str, argv: Sequence[str], *, timeout: float = 10.0) -> str | None:
    """Versión de una herramienta, para dejarla registrada en `Scan.tool_versions`.

    Se ejecuta en síncrono y sin política de egress porque son invocaciones de
    `--version` que no tocan la red; aun así usa el entorno saneado.

    Varias herramientas imprimen un banner ASCII o códigos de color antes del
    número, así que se limpia el ANSI y se busca la primera línea que de verdad
    parezca una versión, en lugar de quedarse con la primera línea no vacía.
    """
    import subprocess

    path = shutil.which(binary)
    if path is None:
        return None
    try:
        completed = subprocess.run(  # noqa: S603 - argv fijo, sin shell
            [path, *argv[1:]],
            capture_output=True,
            timeout=timeout,
            env=clean_env(),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None

    text = _ANSI.sub("", (completed.stdout or completed.stderr).decode("utf-8", errors="replace"))
    lines = [" ".join(line.split()) for line in text.splitlines() if line.strip()]
    for line in lines:
        if _VERSION_LINE.search(line):
            return line[:200]
    return lines[0][:200] if lines else None
