"""Ejecuta un escaneo en otro proceso y cuenta el avance por líneas JSON.

Existe por el aislamiento de red. El sandbox no envuelve una herramienta: mete
el proceso entero en un namespace de red, porque la mitad del tráfico de un
escaneo la generan los módulos propios —probador, crawler, authz— desde este
mismo proceso. Por línea de órdenes eso se resuelve relanzando el comando
dentro del namespace. El servidor web no puede hacer eso: dentro del namespace,
127.0.0.1 es otro loopback, así que el navegador del analista perdería la
interfaz en el mismo instante en que empezara el escaneo.

La salida es un proceso hijo. Este módulo es ese hijo: recibe el trabajo por la
entrada estándar, ejecuta el escaneo y escribe una línea JSON por evento, que
la cola lee y reparte a quien esté mirando. La interfaz ve el mismo progreso en
vivo que en un escaneo sin aislar; el servidor se queda fuera del namespace,
alcanzable.

El trabajo llega por la entrada estándar, no por argumentos, porque lleva
contraseñas: `ps` enseña el argv de cualquier proceso a cualquier usuario del
equipo, y la entrada estándar no se ve ahí.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any

from .scan import ScanOutcome


# ── Serialización del trabajo ───────────────────────────────────────────────
# Las credenciales viajan como diccionario porque tienen que cruzar un límite
# de proceso. Se hace aquí, en un sitio, y no con métodos en la dataclase: un
# `como_dict()` en `Credenciales` invita a que acabe en un registro o en una
# respuesta de la API, que es exactamente donde una contraseña no debe estar.
CAMPOS_CREDENCIALES = (
    "url_login", "usuario", "clave", "selector_usuario", "selector_clave",
    "selector_enviar", "cabeceras", "cookies", "senal_de_exito", "proveedor_identidad",
)


def serializar_credenciales(credenciales: Any | None) -> dict[str, Any] | None:
    if credenciales is None:
        return None
    return {campo: getattr(credenciales, campo) for campo in CAMPOS_CREDENCIALES}


def deserializar_credenciales(datos: dict[str, Any] | None) -> Any | None:
    from ..modules.auth import Credenciales

    if not datos:
        return None
    return Credenciales(**{c: datos[c] for c in CAMPOS_CREDENCIALES if c in datos})


def serializar_roles(roles: Any) -> list[dict[str, Any]]:
    return [
        {"nombre": nombre, "rol": rol,
         "credenciales": serializar_credenciales(credencial)}
        for nombre, rol, credencial in roles
    ]


def deserializar_roles(datos: list[dict[str, Any]]) -> list[tuple[str, str, Any]]:
    return [
        (d["nombre"], d["rol"], deserializar_credenciales(d["credenciales"]))
        for d in datos
    ]


def resumen_de(tipo: str, resultado: ScanOutcome) -> dict[str, Any]:
    """El resumen que la interfaz muestra al terminar.

    Vive aquí para que un escaneo aislado y uno sin aislar devuelvan lo mismo:
    si el resumen se construyera dos veces, las dos rutas se separarían en
    cuanto una de ellas cambiara.
    """
    return {
        "tipo": tipo,
        "hallazgos": len(resultado.findings),
        "por_severidad": resultado.by_severity,
        "nuevos": resultado.new,
        "recurrentes": resultado.recurring,
        "corregidos": resultado.fixed,
        "urls_vivas": sum(1 for p in resultado.probes if p.alive),
        "urls_probadas": len(resultado.probes),
    }


# ── El hijo ─────────────────────────────────────────────────────────────────
def _emitir(linea: dict[str, Any]) -> None:
    """Una línea JSON por evento, vaciada al momento.

    Sin el vaciado explícito, la salida de un proceso hijo se almacena en un
    búfer de bloque y el progreso llegaría a la interfaz a ráfagas de 4 KB: la
    barra se quedaría quieta todo el escaneo y daría un salto al final.
    """
    sys.stdout.write(json.dumps(linea, ensure_ascii=False) + "\n")
    sys.stdout.flush()


async def _ejecutar(trabajo: dict[str, Any]) -> None:
    from .scan import run_web_scan
    from .scope import ScopeError

    def progreso(fase: str, mensaje: str, pct: float) -> None:
        _emitir({"t": "evento", "fase": fase, "mensaje": mensaje, "progreso": pct})

    try:
        resultado = await run_web_scan(
            trabajo["targets"],
            profile=trabajo.get("profile", "safe-active"),
            project_name=trabajo.get("project", "default"),
            db=trabajo.get("db"),
            allow_public=trabajo.get("allow_public", False),
            extra_hosts=trabajo.get("extra_hosts", []),
            only=trabajo.get("only"),
            con_crawler=trabajo.get("con_crawler", True),
            credenciales=deserializar_credenciales(trabajo.get("credenciales")),
            roles=deserializar_roles(trabajo.get("roles", [])),
            on_progress=progreso,
        )
    except ScopeError as exc:
        # El alcance rechazado no es un fallo: es el control funcionando. Se
        # distingue del resto para que la cola lo cuente como tal.
        _emitir({"t": "error", "clase": "ScopeError", "mensaje": str(exc)})
    except Exception as exc:
        _emitir({"t": "error", "clase": type(exc).__name__, "mensaje": str(exc)})
    else:
        _emitir({"t": "resultado", "scan_id": resultado.scan_id,
                 "resumen": resumen_de("web", resultado)})


def main() -> int:
    crudo = sys.stdin.read()
    try:
        trabajo = json.loads(crudo)
    except json.JSONDecodeError as exc:
        _emitir({"t": "error", "clase": "JSONDecodeError",
                 "mensaje": f"el trabajo no se pudo leer: {exc}"})
        return 2
    asyncio.run(_ejecutar(trabajo))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
