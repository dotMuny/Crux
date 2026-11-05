"""Cola de trabajos propia: asyncio sobre el registro que ya está en SQLite.

No hay Redis ni Celery porque no hacen falta. Crux es mono-usuario y corre en
el Kali del analista: un worker en proceso con un semáforo cubre el caso, y
evita pedirle a cada persona que levante y mantenga un servidor extra.

Lo durable vive en la base —`Scan` y `Task` ya lo registran todo—; esta cola
solo gestiona lo efímero: qué se está ejecutando ahora, por dónde va, y quién
está mirando. Si el proceso muere, el escaneo se pierde pero el registro no.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import secrets
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Sequence

from .sandbox import SandboxDeRed, SandboxNoDisponible, comprobar_disponible
from .scan import ScanOutcome, run_code_scan, run_web_scan
from .scope import Scope, ScopeError
from ..modules.auth import AutenticacionFallida, construir_alcance
from .worker import (
    resumen_de,
    serializar_credenciales,
    serializar_roles,
)

# Un analista, una máquina: más de un escaneo simultáneo solo reparte el mismo
# ancho de banda entre dos objetivos y dificulta interpretar el ritmo.
MAX_CONCURRENTES = 2

# Fases tras las que ya no llega nada más: la transmisión se cierra al verlas.
# Se enumeran en un sitio porque añadir un modo de fallo y olvidarse de esta
# lista deja al cliente esperando hasta el siguiente latido.
FASES_FINALES = (
    "hecho", "error", "cancelado",
    "alcance-rechazado", "ruta-invalida", "aislamiento-imposible",
    "autenticacion-fallida",
)

# Cuántos eventos se guardan por trabajo, para que quien se conecte tarde a la
# transmisión vea lo que ya ha pasado.
HISTORIAL = 400


@dataclass(slots=True)
class Evento:
    ts: float
    fase: str
    mensaje: str
    progreso: float

    def como_dict(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "fase": self.fase,
            "mensaje": self.mensaje,
            "progreso": round(self.progreso, 4),
        }


@dataclass(slots=True)
class Trabajo:
    """Un escaneo en curso o terminado dentro de este proceso.

    Sirve a los dos pilares: `targets` son URLs cuando el tipo es «web» y una
    sola ruta de disco cuando es «code».
    """

    id: str
    targets: list[str]
    profile: str
    project: str
    tipo: str = "web"            # web | code
    # Con qué sesión se escaneó. Solo el modo y los nombres de los roles: ni
    # usuario, ni contraseña, ni cabecera. Esto se devuelve por la API, y una
    # credencial que sale por la API ya no es una credencial.
    autenticacion: str = "ninguna"
    roles: list[str] = field(default_factory=list)
    # Aislamiento de red real. Solo aplica a los escaneos web: el análisis de
    # código no usa la red en ningún momento, así que no hay nada que confinar.
    sandbox: bool = False
    estado: str = "en-cola"          # en-cola | ejecutando | hecho | fallido | cancelado
    scan_id: int | None = None
    fase: str = ""
    mensaje: str = "esperando turno"
    progreso: float = 0.0
    error: str | None = None
    creado: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    terminado: datetime | None = None
    resumen: dict[str, Any] = field(default_factory=dict)
    eventos: list[Evento] = field(default_factory=list, repr=False)
    _suscriptores: list[asyncio.Queue] = field(default_factory=list, repr=False)
    _tarea: asyncio.Task | None = field(default=None, repr=False)

    @property
    def activo(self) -> bool:
        return self.estado in ("en-cola", "ejecutando")

    def como_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "targets": self.targets,
            "profile": self.profile,
            "project": self.project,
            "tipo": self.tipo,
            "autenticacion": self.autenticacion,
            "roles": list(self.roles),
            "sandbox": self.sandbox,
            "estado": self.estado,
            "scan_id": self.scan_id,
            "fase": self.fase,
            "mensaje": self.mensaje,
            "progreso": round(self.progreso, 4),
            "error": self.error,
            "creado": self.creado.isoformat(),
            "terminado": self.terminado.isoformat() if self.terminado else None,
            "resumen": self.resumen,
        }

    def publicar(self, fase: str, mensaje: str, progreso: float) -> None:
        """Registra el avance y lo reparte a quien esté mirando."""
        self.fase, self.mensaje, self.progreso = fase, mensaje, progreso
        evento = Evento(time.time(), fase, mensaje, progreso)
        self.eventos.append(evento)
        del self.eventos[:-HISTORIAL]
        for cola in list(self._suscriptores):
            try:
                cola.put_nowait(evento.como_dict())
            except asyncio.QueueFull:
                # Un cliente que no consume no debe frenar el escaneo.
                pass


class ColaDeTrabajos:
    """Ejecuta escaneos en segundo plano dentro del proceso de la web."""

    def __init__(self, db=None, max_concurrentes: int = MAX_CONCURRENTES) -> None:
        self.db = db
        self._trabajos: dict[str, Trabajo] = {}
        self._semaforo = asyncio.Semaphore(max_concurrentes)

    # -- consultas ----------------------------------------------------------
    def listar(self) -> list[Trabajo]:
        return sorted(self._trabajos.values(), key=lambda t: t.creado, reverse=True)

    def obtener(self, job_id: str) -> Trabajo | None:
        return self._trabajos.get(job_id)

    @property
    def activos(self) -> list[Trabajo]:
        return [t for t in self._trabajos.values() if t.activo]

    # -- ciclo de vida ------------------------------------------------------
    def enviar(
        self,
        targets: Sequence[str],
        *,
        profile: str = "safe-active",
        project: str = "default",
        allow_public: bool = False,
        extra_hosts: Sequence[str] = (),
        only: Sequence[str] | None = None,
        con_crawler: bool = True,
        tipo: str = "web",
        credenciales: Any = None,
        roles: Sequence[tuple[str, str, Any]] = (),
        sandbox: bool = False,
    ) -> Trabajo:
        """Encola un escaneo. Devuelve de inmediato; el trabajo corre aparte."""
        if tipo not in ("web", "code"):
            raise ValueError(f"tipo de escaneo desconocido: {tipo!r}")
        if sandbox and tipo != "web":
            raise ValueError(
                "el aislamiento de red solo aplica a los escaneos web; el "
                "análisis de código no usa la red"
            )
        trabajo = Trabajo(
            id=secrets.token_hex(6),
            targets=list(targets),
            profile=profile,
            project=project,
            tipo=tipo,
            autenticacion=credenciales.modo if credenciales is not None else "ninguna",
            roles=[nombre for nombre, _, _ in roles],
            sandbox=sandbox,
        )
        self._trabajos[trabajo.id] = trabajo
        extra: dict[str, Any] = (
            {"only": only}
            if tipo == "code" else
            {"allow_public": allow_public, "extra_hosts": list(extra_hosts),
             "only": only, "con_crawler": con_crawler,
             "credenciales": credenciales, "roles": list(roles)}
        )
        trabajo._tarea = asyncio.create_task(self._ejecutar(trabajo, **extra))
        return trabajo

    async def _ejecutar(self, trabajo: Trabajo, **kwargs: Any) -> None:
        async with self._semaforo:
            if trabajo.estado == "cancelado":
                return
            trabajo.estado = "ejecutando"
            trabajo.publicar(
                "inicio",
                "arrancando el análisis de código" if trabajo.tipo == "code"
                else "arrancando el escaneo",
                0.0,
            )
            try:
                if trabajo.tipo == "code":
                    # El análisis de código recibe una ruta, no una lista de
                    # objetivos, y no tiene alcance de red que confinar.
                    resultado: ScanOutcome = await run_code_scan(
                        trabajo.targets[0],
                        profile=trabajo.profile,
                        project_name=trabajo.project,
                        db=self.db,
                        on_progress=trabajo.publicar,
                        **kwargs,
                    )
                    scan_id, resumen = resultado.scan_id, resumen_de("code", resultado)
                elif trabajo.sandbox:
                    # Con aislamiento el escaneo corre en otro proceso, dentro
                    # del namespace. El servidor se queda fuera: si entrara,
                    # 127.0.0.1 sería el loopback del namespace y la interfaz
                    # dejaría de existir para el navegador del analista.
                    scan_id, resumen = await self._aislado(trabajo, **kwargs)
                else:
                    resultado = await run_web_scan(
                        trabajo.targets,
                        profile=trabajo.profile,
                        project_name=trabajo.project,
                        db=self.db,
                        on_progress=trabajo.publicar,
                        **kwargs,
                    )
                    scan_id, resumen = resultado.scan_id, resumen_de("web", resultado)
            except asyncio.CancelledError:
                trabajo.estado = "cancelado"
                trabajo.publicar("cancelado", "cancelado por el operador", trabajo.progreso)
                raise
            except FileNotFoundError as exc:
                # Ruta inexistente: es un error del operador, no del programa,
                # y merece un mensaje que diga qué corregir.
                trabajo.estado = "fallido"
                trabajo.error = str(exc)
                trabajo.publicar("ruta-invalida", str(exc), 1.0)
            except SandboxNoDisponible as exc:
                # Se pidió aislar y no se puede. No se escanea «igual pero sin
                # aislar»: quien marca esa casilla está diciendo que no quiere
                # que el tráfico pueda salir, y cumplirlo a medias en silencio
                # sería peor que no cumplirlo.
                trabajo.estado = "fallido"
                trabajo.error = str(exc)
                trabajo.publicar("aislamiento-imposible", str(exc), 1.0)
            except AutenticacionFallida as exc:
                # No se pudo entrar. No se escanea como anónimo: quien da unas
                # credenciales está pidiendo ver lo de dentro, y un informe
                # hecho desde fuera parecería completo sin serlo.
                trabajo.estado = "fallido"
                trabajo.error = str(exc)
                trabajo.publicar("autenticacion-fallida", str(exc), 1.0)
            except ScopeError as exc:
                # El alcance rechazado no es un fallo del programa: es el
                # control de seguridad funcionando, y merece su propio mensaje.
                trabajo.estado = "fallido"
                trabajo.error = str(exc)
                trabajo.publicar("alcance-rechazado", str(exc), 1.0)
            except Exception as exc:
                trabajo.estado = "fallido"
                trabajo.error = f"{type(exc).__name__}: {exc}"
                trabajo.publicar("error", trabajo.error, 1.0)
            else:
                trabajo.estado = "hecho"
                trabajo.scan_id = scan_id
                trabajo.resumen = resumen
                trabajo.publicar("hecho", "escaneo terminado", 1.0)
            finally:
                trabajo.terminado = datetime.now(timezone.utc)
                self._cerrar_suscriptores(trabajo)

    async def _aislado(self, trabajo: Trabajo, **kwargs: Any) -> tuple[int, dict]:
        """Escanea dentro de un namespace de red, en un proceso hijo.

        Devuelve `(scan_id, resumen)` igual que la ruta normal. El progreso del
        hijo se republica tal cual, así que la interfaz no distingue un escaneo
        aislado de uno que no lo está —salvo por el aviso de la fase inicial—.
        """
        disponible, motivo = comprobar_disponible()
        if not disponible:
            raise SandboxNoDisponible(motivo)

        trabajo.publicar("aislamiento", "preparando la red aislada", 0.0)
        # Construir el alcance aquí, antes de tocar nada, cumple dos cosas: un
        # objetivo fuera de las redes internas se rechaza sin haber montado el
        # namespace, y las direcciones que el cortafuegos permitirá son las
        # mismas que el escaneo tiene permitido visitar.
        # Con los proveedores de identidad dentro: si no, el namespace no les da
        # ruta ni nombre, y el login no tiene por dónde salir.
        scope = construir_alcance(
            trabajo.targets,
            allow_public=kwargs.get("allow_public", False),
            extra_hosts=kwargs.get("extra_hosts", ()),
            credenciales=kwargs.get("credenciales"),
            roles=kwargs.get("roles", ()),
        )
        caja = SandboxDeRed(nombre=f"cxweb{trabajo.id}", scope=scope)

        en_loopback = caja.objetivos_en_loopback()
        if en_loopback:
            # Se dice antes de montar nada. Dentro de un namespace de red
            # 127.0.0.1 es el loopback del propio namespace, así que estos
            # objetivos son inalcanzables por diseño; sin este aviso, el
            # resultado vacío se leería como que la aplicación no responde.
            raise SandboxNoDisponible(
                f"{', '.join(en_loopback)} escucha en localhost, y dentro de un "
                "namespace de red 127.0.0.1 es otro loopback: desde el "
                "aislamiento no hay forma de alcanzarlo. Escanéalo sin "
                "aislamiento, o haz que la aplicación escuche en una dirección "
                "encaminable."
            )

        await asyncio.to_thread(caja.crear)
        try:
            trabajo.publicar(
                "aislamiento",
                "red aislada: solo " + ", ".join(caja.permitidas),
                0.02,
            )
            return await self._hijo(trabajo, caja, scope, **kwargs)
        finally:
            await asyncio.to_thread(caja.destruir, silencioso=True)

    async def _hijo(
        self, trabajo: Trabajo, caja: SandboxDeRed, scope: Scope, **kwargs: Any
    ) -> tuple[int, dict]:
        """Lanza el worker dentro del namespace y traduce lo que cuenta."""
        raiz = str(Path(__file__).resolve().parents[2])
        orden = caja.envolver([
            "env",
            "CRUX_EN_SANDBOX=1",
            f"HOME={os.path.expanduser('~')}",
            f"XDG_DATA_HOME={os.environ.get('XDG_DATA_HOME', os.path.expanduser('~/.local/share'))}",
            # `sudo` limpia el entorno, así que el hijo no heredaría la ruta de
            # importación: se le pasa dentro de la orden, como la marca.
            f"PYTHONPATH={raiz}",
            sys.executable, "-m", "crux.core.worker",
        ])
        proceso = await asyncio.create_subprocess_exec(
            *orden,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        peticion = {
            "targets": trabajo.targets,
            "profile": trabajo.profile,
            "project": trabajo.project,
            "db": str(self.db) if self.db else None,
            "allow_public": kwargs.get("allow_public", False),
            "extra_hosts": list(kwargs.get("extra_hosts", ())),
            "only": list(kwargs["only"]) if kwargs.get("only") is not None else None,
            "con_crawler": kwargs.get("con_crawler", True),
            "credenciales": serializar_credenciales(kwargs.get("credenciales")),
            "roles": serializar_roles(kwargs.get("roles", ())),
        }

        scan_id: int | None = None
        resumen: dict[str, Any] = {}
        fallo: tuple[str, str] | None = None
        try:
            proceso.stdin.write(json.dumps(peticion, ensure_ascii=False).encode())
            await proceso.stdin.drain()
            proceso.stdin.close()

            async for cruda in proceso.stdout:
                try:
                    linea = json.loads(cruda)
                except json.JSONDecodeError:
                    # Una línea que no es nuestra —un aviso de una biblioteca
                    # que escribe por la salida estándar— no debe tumbar el
                    # escaneo; se ignora y el resto sigue.
                    continue
                if linea.get("t") == "evento":
                    trabajo.publicar(
                        linea["fase"], linea["mensaje"], float(linea["progreso"])
                    )
                elif linea.get("t") == "resultado":
                    scan_id, resumen = linea["scan_id"], linea["resumen"]
                elif linea.get("t") == "error":
                    fallo = (linea.get("clase", "Exception"), linea.get("mensaje", ""))
        except asyncio.CancelledError:
            proceso.terminate()
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(proceso.wait(), timeout=10)
            raise
        codigo = await proceso.wait()

        if fallo is not None:
            clase, mensaje = fallo
            raise {"ScopeError": ScopeError,
                   "AutenticacionFallida": AutenticacionFallida}.get(clase, RuntimeError)(mensaje)
        if scan_id is None:
            # El hijo murió sin contar nada. Su salida de error es lo único que
            # explica por qué, así que se enseña en vez de un código a secas.
            detalle = (await proceso.stderr.read()).decode(errors="replace").strip()
            raise RuntimeError(
                f"el escaneo aislado terminó con código {codigo} sin devolver "
                f"resultado{': ' + detalle[-600:] if detalle else ''}"
            )
        resumen["aislado"] = True
        resumen["permitidas"] = caja.permitidas
        return scan_id, resumen

    async def cancelar(self, job_id: str) -> bool:
        trabajo = self._trabajos.get(job_id)
        if trabajo is None or not trabajo.activo:
            return False
        trabajo.estado = "cancelado"
        if trabajo._tarea is not None:
            trabajo._tarea.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await trabajo._tarea
        return True

    # -- transmisión en vivo -------------------------------------------------
    async def seguir(self, job_id: str) -> AsyncIterator[dict[str, Any]]:
        """Eventos de un trabajo: primero lo ya ocurrido, luego lo que llegue.

        Repetir el historial evita que quien abre la página a mitad de escaneo
        vea una barra de progreso vacía hasta el siguiente evento.
        """
        trabajo = self._trabajos.get(job_id)
        if trabajo is None:
            return

        # El historial se reenvía en el mismo formato que lo que viene en vivo.
        # Devolver aquí el objeto crudo y el diccionario en el bucle siguiente
        # rompía la transmisión solo cuando alguien se conectaba a mitad de
        # escaneo, que es precisamente el caso que importa.
        for evento in list(trabajo.eventos):
            yield evento.como_dict()
        if not trabajo.activo:
            return

        cola: asyncio.Queue = asyncio.Queue(maxsize=HISTORIAL)
        trabajo._suscriptores.append(cola)
        try:
            while True:
                try:
                    evento = await asyncio.wait_for(cola.get(), timeout=15)
                except asyncio.TimeoutError:
                    # Latido: mantiene viva la conexión SSE a través de proxies
                    # y deja que el cliente note una desconexión.
                    yield {"ts": time.time(), "fase": "latido", "mensaje": "",
                           "progreso": trabajo.progreso}
                    if not trabajo.activo:
                        return
                    continue
                if evento is None:
                    return
                yield evento
                if evento.get("fase") in FASES_FINALES:
                    return
        finally:
            with contextlib.suppress(ValueError):
                trabajo._suscriptores.remove(cola)

    def _cerrar_suscriptores(self, trabajo: Trabajo) -> None:
        for cola in list(trabajo._suscriptores):
            with contextlib.suppress(asyncio.QueueFull):
                cola.put_nowait(None)
