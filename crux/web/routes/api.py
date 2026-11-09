"""Rutas de la API. Todo lo que la interfaz necesita, y nada más."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Literal, Sequence

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import desc, func, select

from ...core import paths
from ...core.findings import FindingStatus
from ...core.models import (
    EvidenceRecord,
    FindingRecord,
    FindingState,
    Project,
    Scan,
    Task,
)
from ...core.policy import Profile
from ...core.report import render_html, render_pdf
from ...core.report.html import build_context
from ...core.scope import Scope
from ...core.severity import Severity
from ...core.store import session_scope

router = APIRouter()


# ── Modelos de entrada ──────────────────────────────────────────────────────
class CredencialesEntrada(BaseModel):
    """Cómo entra el escáner en la aplicación auditada.

    Son los tres modos que el producto cubre: formulario con cookie de sesión,
    token o cabecera fija, y una sesión ya capturada a mano. Entran por el
    cuerpo de la petición y se usan en memoria; no se guardan en la base ni se
    devuelven en ninguna respuesta.
    """

    url_login: str | None = None
    usuario: str | None = None
    clave: str | None = None
    selector_usuario: str | None = None
    selector_clave: str | None = None
    selector_enviar: str | None = None
    cabeceras: dict[str, str] = {}
    cookies: dict[str, str] = {}
    senal_de_exito: str | None = None
    # Solo hace falta si la aplicación salta a él con JavaScript; si lo hace
    # con una redirección, se descubre solo.
    proveedor_identidad: str | None = None

    def construir(self):
        from ...modules.auth import Credenciales

        return Credenciales(**self.model_dump())


class RolEntrada(BaseModel):
    """Un rol con el que comparar el control de acceso."""

    nombre: str = Field(min_length=1)
    rol: str = ""
    credenciales: CredencialesEntrada


class PeticionDeEscaneo(BaseModel):
    """Una petición de escaneo, de cualquiera de los dos pilares.

    En un escaneo web, `targets` son URLs o redes. En uno de código es una
    sola ruta de disco, y el resto de campos de red no aplican.
    """

    targets: list[str] = Field(min_length=1)
    tipo: Literal["web", "code"] = "web"
    profile: str = Profile.SAFE_ACTIVE.value
    project: str = "default"
    allow_public: bool = False
    extra_hosts: list[str] = []
    # Limita el escaneo a estos adaptadores. None ejecuta todos; una lista
    # vacía, ninguno. Sirve para relanzar una sola herramienta sin repetir el
    # escaneo entero.
    only: list[str] | None = None
    # Sesión con la que recorrer la aplicación. Sin ella solo se ve lo público,
    # que en una aplicación interna es la menor parte.
    credenciales: CredencialesEntrada | None = None
    # Roles a comparar entre sí. Hacen falta dos para que la comparación diga
    # algo; con uno se acepta la petición y se avisa.
    roles: list[RolEntrada] = []
    # Especificación OpenAPI o Swagger de la API, si el analista la tiene a
    # mano. Sin ella se busca en las rutas habituales de la aplicación, que es
    # lo que resuelve el caso normal.
    especificacion_api: str | None = None
    # Analizar la API que hay por debajo de la interfaz.
    con_api: bool = True
    # Mete el escaneo en un namespace de red que solo alcanza el alcance
    # declarado. Si no se puede, el escaneo falla: no se degrada a «igual pero
    # sin aislar».
    sandbox: bool = False


class CambioDeEstado(BaseModel):
    status: FindingStatus
    note: str = ""


# ── Salud y catálogo ────────────────────────────────────────────────────────
@router.get("/health")
async def health() -> dict[str, Any]:
    return {"ok": True, "version": "0.1.0", "perfiles": [p.value for p in Profile]}


@router.get("/sandbox")
async def aislamiento() -> dict[str, Any]:
    """¿Se puede aislar la red en este equipo, y si no, por qué?

    La interfaz lo pregunta para no ofrecer una casilla que va a fallar, y para
    poder decir qué falta en vez de desactivarla sin explicación.
    """
    from ...core.sandbox import comprobar_disponible

    disponible, motivo = comprobar_disponible()
    return {"disponible": disponible, "motivo": motivo}


@router.get("/projects")
async def proyectos() -> list[dict[str, Any]]:
    with session_scope() as s:
        filas = s.execute(
            select(
                Project.id, Project.slug, Project.name, Project.created_at,
                func.count(Scan.id).label("escaneos"),
            )
            .outerjoin(Scan, Scan.project_id == Project.id)
            .group_by(Project.id)
            .order_by(Project.name)
        ).all()
        return [
            {"id": f.id, "slug": f.slug, "name": f.name,
             "created_at": f.created_at.isoformat(), "escaneos": f.escaneos}
            for f in filas
        ]


# ── Escaneos ────────────────────────────────────────────────────────────────
@router.get("/scans")
async def escaneos(project: str | None = None, limit: int = Query(50, le=200)) -> list[dict]:
    with session_scope() as s:
        consulta = select(Scan).order_by(desc(Scan.id)).limit(limit)
        if project:
            consulta = consulta.join(Project).where(Project.slug == project)
        return [_scan_dict(s, scan) for scan in s.scalars(consulta)]


@router.get("/scans/{scan_id}")
async def escaneo(scan_id: int) -> dict[str, Any]:
    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(404, "ese escaneo no existe")
        datos = _scan_dict(s, scan)
        datos["tareas"] = [
            {"name": t.name, "tool": t.tool, "status": str(t.status),
             "argv": t.argv, "error": t.error,
             "duracion": _segundos(t.started_at, t.finished_at)}
            for t in s.scalars(select(Task).where(Task.scan_id == scan_id))
        ]
        datos["scope"] = scan.scope
        datos["tool_versions"] = scan.tool_versions
        # Qué se comprobó y en qué se quedaron los hallazgos: el detalle de un
        # escaneo tiene que poder explicar la diferencia entre lo que se
        # encontró y lo que se lee.
        datos["coverage"] = scan.coverage
        return datos


def _scan_dict(sesion, scan: Scan) -> dict[str, Any]:
    conteos = dict(
        sesion.execute(
            select(FindingRecord.severity, func.count(FindingRecord.id))
            .where(FindingRecord.scan_id == scan.id)
            .group_by(FindingRecord.severity)
        ).all()
    )
    return {
        "id": scan.id,
        "project_id": scan.project_id,
        "kind": str(scan.kind),
        "profile": scan.profile,
        "status": str(scan.status),
        "started_at": scan.started_at.isoformat() if scan.started_at else None,
        "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
        "duracion": _segundos(scan.started_at, scan.finished_at),
        "error": scan.error,
        # En un escaneo de código el «objetivo» es la ruta analizada: no hay
        # entradas de alcance de red porque no se usó la red.
        "targets": (
            [(scan.scope or {}).get("ruta", "")]
            if str(scan.kind) == "code"
            else [e.get("raw") for e in (scan.scope or {}).get("entries", [])]
        ),
        "por_severidad": {
            Severity(nivel).label: total for nivel, total in conteos.items()
        },
        "hallazgos": sum(conteos.values()),
    }


def _segundos(inicio, fin) -> float | None:
    return (fin - inicio).total_seconds() if inicio and fin else None


class BorradoDeEscaneos(BaseModel):
    """Qué escaneos borrar. En lote porque limpiar la lista de uno en uno no
    es limpiar la lista."""

    ids: list[int] = Field(min_length=1)


@router.post("/scans/delete")
async def borrar_escaneos(peticion: BorradoDeEscaneos) -> dict[str, Any]:
    """Borra escaneos y todo lo que cuelga de ellos.

    Lo que se va con el escaneo: sus hallazgos, su evidencia, sus tareas, su
    registro de auditoría, las salidas crudas de las herramientas en disco y
    los informes ya generados. Lo que **no** se va: el juicio de triaje del
    proyecto, que vive por huella y no por escaneo —si lo borráramos, el falso
    positivo que marcaste volvería a aparecer como nuevo en el siguiente
    escaneo—. Solo se limpian los juicios que se quedan sin ningún hallazgo al
    que referirse, que ya no le sirven a nadie.
    """
    import shutil

    borrados, no_encontrados = [], []
    proyectos_tocados: set[int] = set()
    with session_scope() as s:
        for scan_id in dict.fromkeys(peticion.ids):
            scan = s.get(Scan, scan_id)
            if scan is None:
                no_encontrados.append(scan_id)
                continue
            proyectos_tocados.add(scan.project_id)
            # La evidencia cuelga de los hallazgos, y los hallazgos del
            # escaneo: el borrado en cascada se encarga, y las claves ajenas
            # están activas (ver store._configure_sqlite).
            s.delete(scan)
            borrados.append(scan_id)

        # Juicios que ya no tienen ningún hallazgo detrás.
        huerfanos = 0
        for project_id in proyectos_tocados:
            vivos = set(s.scalars(
                select(FindingRecord.fingerprint)
                .where(FindingRecord.project_id == project_id)
            ))
            for estado in s.scalars(
                select(FindingState).where(FindingState.project_id == project_id)
            ):
                if estado.fingerprint not in vivos:
                    s.delete(estado)
                    huerfanos += 1

    liberado = 0
    for scan_id in borrados:
        for ruta in (paths.runs_dir() / f"scan-{scan_id:06d}",
                     paths.reports_dir() / f"scan-{scan_id:06d}.html",
                     paths.reports_dir() / f"scan-{scan_id:06d}.pdf"):
            if not ruta.exists():
                continue
            liberado += _tamano(ruta)
            shutil.rmtree(ruta) if ruta.is_dir() else ruta.unlink()

    if not borrados:
        raise HTTPException(404, "ninguno de esos escaneos existe")
    return {
        "borrados": borrados,
        "no_encontrados": no_encontrados,
        "triajes_huerfanos": huerfanos,
        "bytes_liberados": liberado,
    }


def _tamano(ruta) -> int:
    if ruta.is_file():
        return ruta.stat().st_size
    return sum(f.stat().st_size for f in ruta.rglob("*") if f.is_file())


@router.delete("/scans/{scan_id}")
async def borrar_escaneo(scan_id: int) -> dict[str, Any]:
    return await borrar_escaneos(BorradoDeEscaneos(ids=[scan_id]))


@router.get("/storage")
async def almacenamiento() -> dict[str, Any]:
    """Qué ocupa Crux en disco, y dónde.

    Está aquí para responder en la propia interfaz a una pregunta razonable:
    dónde se guardan los escaneos. No en el navegador —limpiar la sesión no
    borra nada—, sino en un fichero SQLite del equipo.
    """
    piezas = {
        "base de datos": paths.db_path(),
        "salidas de herramientas": paths.runs_dir(),
        "informes": paths.reports_dir(),
    }
    detalle = []
    for nombre, ruta in piezas.items():
        detalle.append({
            "nombre": nombre,
            "ruta": str(ruta),
            "bytes": _tamano(ruta) if ruta.exists() else 0,
        })
    # El WAL de SQLite puede ser mayor que el propio fichero mientras hay
    # escrituras en vuelo; contarlo aparte evita que la cifra parezca mentira.
    wal = paths.db_path().with_name(paths.db_path().name + "-wal")
    if wal.exists():
        detalle[0]["bytes"] += wal.stat().st_size
    with session_scope() as s:
        escaneos_ = s.scalar(select(func.count(Scan.id))) or 0
        hallazgos_ = s.scalar(select(func.count(FindingRecord.id))) or 0
    return {
        "directorio": str(paths.data_dir()),
        "piezas": detalle,
        "escaneos": escaneos_,
        "hallazgos": hallazgos_,
    }


# ── Hallazgos ───────────────────────────────────────────────────────────────
@router.get("/scans/{scan_id}/findings")
async def hallazgos(scan_id: int) -> list[dict[str, Any]]:
    """Todos los hallazgos del escaneo, con su estado de triaje ya resuelto.

    Se devuelven de una vez y sin paginar: la tabla de la interfaz está
    virtualizada y filtra en el cliente, que para los volúmenes de un escaneo
    interno (cientos, no millones) es más ágil que ir y volver por cada faceta.
    """
    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(404, "ese escaneo no existe")

        estados = {
            e.fingerprint: e
            for e in s.scalars(
                select(FindingState).where(FindingState.project_id == scan.project_id)
            )
        }
        conteo_evidencia = dict(
            s.execute(
                select(EvidenceRecord.finding_id, func.count(EvidenceRecord.id))
                .group_by(EvidenceRecord.finding_id)
            ).all()
        )
        salida = []
        for f in s.scalars(
            select(FindingRecord)
            .where(FindingRecord.scan_id == scan_id)
            .order_by(desc(FindingRecord.severity), FindingRecord.source)
        ):
            estado = estados.get(f.fingerprint)
            salida.append(
                {
                    "id": f.id,
                    "fingerprint": f.fingerprint,
                    "source": f.source,
                    "check_id": f.check_id,
                    "title": f.title,
                    "description": f.description,
                    "remediation": f.remediation,
                    "severity": Severity(f.severity).label,
                    "confidence": int(f.confidence),
                    "cvss_score": f.cvss_score,
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                    "target": f.target,
                    "param": f.param,
                    "tags": f.tags,
                    "extra": f.extra,
                    "status": str(estado.status) if estado else "new",
                    "note": estado.note if estado else "",
                    "first_seen": estado.first_seen.isoformat() if estado else None,
                    "evidencias": conteo_evidencia.get(f.id, 0),
                }
            )
        return salida


@router.get("/findings/{finding_id}/evidence")
async def evidencia(finding_id: int) -> list[dict[str, Any]]:
    with session_scope() as s:
        if s.get(FindingRecord, finding_id) is None:
            raise HTTPException(404, "ese hallazgo no existe")
        return [
            {"id": e.id, "kind": e.kind, "request": e.request, "response": e.response,
             "snippet": e.snippet, "path": e.path, "meta": e.meta}
            for e in s.scalars(
                select(EvidenceRecord).where(EvidenceRecord.finding_id == finding_id)
            )
        ]


@router.get("/findings/{finding_id}/diff")
async def diferencia(finding_id: int) -> dict[str, Any]:
    """Compara la evidencia de un hallazgo con la de su observación anterior.

    Qué se compara, que es la decisión de diseño: el **mismo fingerprint en el
    escaneo anterior del mismo proyecto**. Responde a la pregunta que de verdad
    se hace un analista al reabrir un hallazgo recurrente —"¿esto ha cambiado
    desde la última vez?"— y distingue un hallazgo que sigue igual de uno que
    ha empeorado o que está a medio corregir.

    Cuando el módulo de authz exista (fase 3), el mismo visor servirá para
    comparar las respuestas de dos roles: el formato de salida es el mismo.
    """
    with session_scope() as s:
        actual = s.get(FindingRecord, finding_id)
        if actual is None:
            raise HTTPException(404, "ese hallazgo no existe")

        anterior = s.scalar(
            select(FindingRecord)
            .where(
                FindingRecord.project_id == actual.project_id,
                FindingRecord.fingerprint == actual.fingerprint,
                FindingRecord.scan_id < actual.scan_id,
            )
            .order_by(desc(FindingRecord.scan_id))
            .limit(1)
        )
        if anterior is None:
            return {
                "comparable": False,
                "motivo": "es la primera vez que se observa este hallazgo",
                "fingerprint": actual.fingerprint,
            }

        def respuesta_de(fila: FindingRecord) -> str:
            ev = s.scalar(
                select(EvidenceRecord)
                .where(EvidenceRecord.finding_id == fila.id,
                       EvidenceRecord.response.is_not(None))
                .limit(1)
            )
            return ev.response if ev else ""

        izquierda, derecha = respuesta_de(anterior), respuesta_de(actual)
        return {
            "comparable": bool(izquierda or derecha),
            "fingerprint": actual.fingerprint,
            "antes": {
                "scan_id": anterior.scan_id,
                "fecha": anterior.detected_at.isoformat(),
                "severidad": Severity(anterior.severity).label,
                "texto": izquierda,
            },
            "ahora": {
                "scan_id": actual.scan_id,
                "fecha": actual.detected_at.isoformat(),
                "severidad": Severity(actual.severity).label,
                "texto": derecha,
            },
            "identicas": izquierda == derecha,
        }


@router.patch("/projects/{project_id}/findings/{fingerprint}")
async def triar(project_id: int, fingerprint: str, cambio: CambioDeEstado) -> dict[str, Any]:
    """Marca un hallazgo. El juicio se guarda por huella, no por fila: así
    sobrevive a los reescaneos."""
    with session_scope() as s:
        estado = s.scalar(
            select(FindingState).where(
                FindingState.project_id == project_id,
                FindingState.fingerprint == fingerprint,
            )
        )
        if estado is None:
            raise HTTPException(404, "ese hallazgo no está en el proyecto")
        estado.status = cambio.status
        estado.note = cambio.note
        return {"fingerprint": fingerprint, "status": str(cambio.status), "note": cambio.note}


# ── Superficie de ataque ────────────────────────────────────────────────────
@router.get("/scans/{scan_id}/surface")
async def superficie(scan_id: int) -> dict[str, Any]:
    """Grafo host → servicio → ruta → hallazgo, listo para Cytoscape.

    El grafo se arma con **todo lo que el escaneo vio**, no solo con lo que
    salió mal: las URLs sondeadas y los endpoints del recorrido entran aunque
    no tengan ningún hallazgo. Una superficie de ataque es lo que está
    expuesto, y una ruta sin hallazgos es exactamente eso —a veces, la más
    interesante: la que nadie ha mirado todavía—.

    Cada nodo lleva su detalle dentro, para que pulsarlo no cueste otra vuelta
    al servidor.
    """
    from urllib.parse import urlsplit

    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(404, "ese escaneo no existe")
        filas = list(
            s.scalars(select(FindingRecord).where(FindingRecord.scan_id == scan_id))
        )
        bruta = scan.surface or {}
        es_codigo = str(scan.kind) == "code"

    rutas: dict[str, dict[str, Any]] = {}

    def ruta_de(url: str) -> dict[str, Any] | None:
        partes = urlsplit(url)
        if not partes.netloc:
            return None
        origen = f"{partes.scheme}://{partes.netloc}"
        camino = partes.path or "/"
        clave = f"{origen}{camino}"
        return rutas.setdefault(clave, {
            "id": clave, "origen": origen, "host": partes.hostname or partes.netloc,
            "esquema": partes.scheme, "puerto": partes.port, "ruta": camino,
            "status": None, "titulo": "", "servidor": "", "tipo_contenido": "",
            "longitud": None, "tecnologias": [], "redirecciones": [],
            "metodos": set(), "params": set(), "descubierta_por": set(),
            "hallazgos": [],
        })

    # 1. Lo que respondió al sondeo: es la capa que da estado y título.
    for sonda in bruta.get("sondas", []):
        fila = ruta_de(sonda.get("final_url") or sonda.get("url", ""))
        if fila is None:
            continue
        fila["status"] = sonda.get("status")
        fila["titulo"] = sonda.get("titulo") or fila["titulo"]
        fila["servidor"] = sonda.get("servidor") or fila["servidor"]
        fila["tipo_contenido"] = sonda.get("tipo_contenido") or fila["tipo_contenido"]
        fila["longitud"] = sonda.get("longitud")
        fila["tecnologias"] = sonda.get("tecnologias") or fila["tecnologias"]
        fila["redirecciones"] = sonda.get("redirecciones") or []
        fila["descubierta_por"].add("sonda")

    # 2. Lo que encontró el recorrido: aporta métodos y parámetros, que es
    #    donde se inyecta.
    for punto in bruta.get("endpoints", []):
        fila = ruta_de(punto.get("url", ""))
        if fila is None:
            continue
        fila["metodos"].add(punto.get("metodo") or "GET")
        fila["params"].update(punto.get("params") or [])
        # Los parámetros del cuerpo cuentan igual: en la API son casi todos, y
        # sin ellos la superficie de un POST a /api/… se dibujaba vacía.
        fila["params"].update(punto.get("params_cuerpo") or [])
        fila["descubierta_por"].add(punto.get("origen") or "enlace")

    # 3. Los hallazgos, que pueden caer en rutas que ninguna de las dos vio
    #    (una herramienta externa prueba rutas por su cuenta).
    #
    #    Un hallazgo cuyo objetivo no tiene host —hay herramientas que informan
    #    de «/search» y no de la URL entera— no se puede colgar de ningún
    #    servicio. Antes se descartaba, así que el grafo decía 13 hallazgos en
    #    el resumen y dibujaba 11: justo los dos más graves desaparecían sin
    #    que nada lo dijera. Se agrupan aparte y se cuentan.
    sin_ubicar: list[FindingRecord] = []
    for f in filas:
        fila = ruta_de(f.target)
        if fila is None:
            sin_ubicar.append(f)
            continue
        fila["hallazgos"].append(f)
        if f.param:
            fila["params"].add(f.param)
        fila["descubierta_por"].add(f.source)

    nodos: dict[str, dict[str, Any]] = {}
    aristas: list[dict[str, Any]] = []
    peor: dict[str, int] = {}

    def nodo(id_: str, etiqueta: str, tipo: str, **datos: Any) -> dict[str, Any]:
        return nodos.setdefault(
            id_, {"data": {"id": id_, "label": etiqueta, "tipo": tipo, **datos}}
        )["data"]

    for fila in rutas.values():
        host, origen, id_ruta = fila["host"], fila["origen"], fila["id"]
        nodo(host, host, "host", detalle={"host": host})
        servicio = nodo(origen, origen.split("://")[-1], "servicio",
                        detalle={"esquema": fila["esquema"], "host": host,
                                 "puerto": fila["puerto"]})
        servicio.setdefault("_tec", set()).update(fila["tecnologias"])
        servicio.setdefault("_srv", set()).add(fila["servidor"] or "")
        aristas.append({"data": {"source": host, "target": origen}})

        nodo(id_ruta, fila["ruta"], "ruta",
             sin_hallazgos=not fila["hallazgos"],
             detalle={
                 "url": id_ruta,
                 "status": fila["status"],
                 "titulo": fila["titulo"],
                 "servidor": fila["servidor"],
                 "tipo_contenido": fila["tipo_contenido"],
                 "longitud": fila["longitud"],
                 "tecnologias": sorted(fila["tecnologias"]),
                 "redirecciones": fila["redirecciones"],
                 "metodos": sorted(fila["metodos"]) or ["GET"],
                 "params": sorted(fila["params"]),
                 "descubierta_por": sorted(fila["descubierta_por"]),
                 "hallazgos": len(fila["hallazgos"]),
             })
        aristas.append({"data": {"source": origen, "target": id_ruta}})

        for f in fila["hallazgos"]:
            id_hallazgo = f"f{f.id}"
            severidad = Severity(f.severity)
            nodo(id_hallazgo, f.title, "hallazgo", severidad=severidad.label,
                 fingerprint=f.fingerprint, finding_id=f.id,
                 detalle={
                     "titulo": f.title,
                     "severidad": severidad.label,
                     "origen": f.source,
                     "check_id": f.check_id,
                     "objetivo": f.target,
                     "param": f.param,
                     "cwe": f.cwe,
                     "owasp": f.owasp,
                     "descripcion": f.description,
                     "correccion": f.remediation,
                 })
            aristas.append({"data": {"source": id_ruta, "target": id_hallazgo}})

            # La severidad peor se propaga hacia arriba: así el host se colorea
            # por lo más grave que cuelga de él, que es lo que se mira de un
            # vistazo.
            for ancestro in (host, origen, id_ruta):
                peor[ancestro] = max(peor.get(ancestro, 0), int(severidad))

    # La rama de los que no se pudieron ubicar. Se dibuja como un origen más
    # para que estén en el grafo y se vean, no para fingir que se sabe dónde
    # están: su ficha dice exactamente eso.
    if sin_ubicar:
        raiz = "sin-host"
        nodo(raiz, "objetivo sin host", "host", detalle={
            "que_pasa": (
                "Estos hallazgos llegaron con una ruta relativa en vez de una "
                "URL completa, así que no se pueden colgar de ningún servicio. "
                "Vuelve a escanear para que queden en su sitio."
            ),
            "hallazgos": len(sin_ubicar),
        })
        for f in sin_ubicar:
            id_hallazgo = f"f{f.id}"
            severidad = Severity(f.severity)
            nodo(id_hallazgo, f.title, "hallazgo", severidad=severidad.label,
                 fingerprint=f.fingerprint, finding_id=f.id,
                 detalle={
                     "titulo": f.title,
                     "severidad": severidad.label,
                     "origen": f.source,
                     "check_id": f.check_id,
                     "objetivo": f.target,
                     "param": f.param,
                     "cwe": f.cwe,
                     "owasp": f.owasp,
                     "descripcion": f.description,
                     "correccion": f.remediation,
                 })
            aristas.append({"data": {"source": raiz, "target": id_hallazgo}})
            peor[raiz] = max(peor.get(raiz, 0), int(severidad))

    for id_, valor in peor.items():
        nodos[id_]["data"]["severidad"] = Severity(valor).label

    # Los conjuntos del servicio se resuelven al final, cuando ya han pasado
    # todas sus rutas.
    for datos in nodos.values():
        d = datos["data"]
        if d["tipo"] != "servicio":
            continue
        d["detalle"]["tecnologias"] = sorted(d.pop("_tec", set()))
        d["detalle"]["servidor"] = next(iter(sorted(x for x in d.pop("_srv", set()) if x)), "")
        d["detalle"]["rutas"] = sum(
            1 for f in rutas.values() if f["origen"] == d["id"]
        )

    sin_hallazgos = sum(1 for f in rutas.values() if not f["hallazgos"])
    return {
        "nodes": list(nodos.values()),
        "edges": aristas,
        "resumen": {
            "hosts": sum(1 for n in nodos.values() if n["data"]["tipo"] == "host"),
            "servicios": sum(1 for n in nodos.values() if n["data"]["tipo"] == "servicio"),
            "rutas": len(rutas),
            "rutas_sin_hallazgos": sin_hallazgos,
            "rutas_con_parametros": sum(1 for f in rutas.values() if f["params"]),
            "hallazgos": len(filas),
            # Cuántos se dibujan de verdad. Va aparte del total a propósito:
            # el fallo que esto previene fue decir 13 y pintar 11, y la única
            # forma de que no vuelva a pasar inadvertido es que las dos cifras
            # viajen juntas y la interfaz las compare.
            "hallazgos_dibujados": sum(
                1 for n in nodos.values() if n["data"]["tipo"] == "hallazgo"
            ),
            # Si esto no es cero, el grafo no puede decir dónde viven esos
            # hallazgos. Es dato, no detalle: la interfaz lo dice.
            "hallazgos_sin_ubicar": len(sin_ubicar),
            "paginas_visitadas": bruta.get("paginas_visitadas", 0),
            "hubo_recorrido": bruta.get("hubo_recorrido", False),
            "fuera_de_alcance": bruta.get("fuera_de_alcance", []),
            # Un escaneo guardado antes de que se registrara la superficie no
            # tiene nada que enseñar más allá de sus hallazgos, y la interfaz
            # debe decirlo en vez de dar a entender que no se encontró nada.
            "superficie_registrada": bool(bruta),
            "es_codigo": es_codigo,
        },
    }


# ── Métricas ────────────────────────────────────────────────────────────────
@router.get("/projects/{project_id}/metrics")
async def metricas(project_id: int) -> dict[str, Any]:
    """Todo lo que el panel enseña de un proyecto, en una sola petición.

    El criterio de qué entra aquí: una cifra merece estar en el panel si
    cambia lo que harías a continuación. «Cuántos hallazgos hay» no lo hace
    —siempre hay—; «cuántos quedan sin mirar», «qué comprobación se repite
    más» y «qué llevaba más tiempo abierto» sí.
    """
    from datetime import timezone as _tz

    with session_scope() as s:
        if s.get(Project, project_id) is None:
            raise HTTPException(404, "ese proyecto no existe")

        escaneos_ = list(
            s.scalars(
                select(Scan).where(Scan.project_id == project_id).order_by(Scan.id)
            )
        )
        tendencia = []
        for scan in escaneos_:
            conteos = dict(
                s.execute(
                    select(FindingRecord.severity, func.count(FindingRecord.id))
                    .where(FindingRecord.scan_id == scan.id)
                    .group_by(FindingRecord.severity)
                ).all()
            )
            tendencia.append(
                {
                    "scan_id": scan.id,
                    "fecha": scan.started_at.isoformat() if scan.started_at else None,
                    "kind": str(scan.kind),
                    **{Severity(n).label: t for n, t in conteos.items()},
                }
            )
        triaje = dict(
            s.execute(
                select(FindingState.status, func.count(FindingState.id))
                .where(FindingState.project_id == project_id)
                .group_by(FindingState.status)
            ).all()
        )

        ultimo = escaneos_[-1] if escaneos_ else None
        if ultimo is None:
            return {"tendencia": [], "triaje": {}, "resumen": {"escaneos": 0},
                    "por_herramienta": {}, "top_checks": [], "top_objetivos": [],
                    "antiguedad": {"tramos": {}, "mas_viejos": []},
                    "cobertura": {"origenes": [], "tareas": []}, "cambio": None}

        estados = {
            e.fingerprint: e
            for e in s.scalars(
                select(FindingState).where(FindingState.project_id == project_id)
            )
        }
        ultimos = list(
            s.scalars(select(FindingRecord).where(FindingRecord.scan_id == ultimo.id))
        )

        por_herramienta = dict(
            s.execute(
                select(FindingRecord.source, func.count(FindingRecord.id))
                .where(FindingRecord.scan_id == ultimo.id)
                .group_by(FindingRecord.source)
                .order_by(desc(func.count(FindingRecord.id)))
            ).all()
        )

        # Lo que más se repite: una comprobación que sale veinte veces suele
        # ser un arreglo único —una cabecera, una plantilla— que cierra
        # veinte hallazgos de golpe. Es la cifra que mejor ordena el trabajo.
        repetidas: dict[tuple[str, str], dict[str, Any]] = {}
        for f in ultimos:
            clave = (f.source, f.check_id)
            entrada = repetidas.setdefault(clave, {
                "source": f.source, "check_id": f.check_id, "titulo": f.title,
                "severidad": Severity(f.severity).label, "total": 0,
            })
            entrada["total"] += 1
            if int(f.severity) > int(Severity[entrada["severidad"].upper()]):
                entrada["severidad"] = Severity(f.severity).label
        top_checks = sorted(repetidas.values(), key=lambda e: -e["total"])[:8]
        top_checks = [e for e in top_checks if e["total"] > 1] or top_checks[:3]

        objetivos: dict[str, dict[str, Any]] = {}
        for f in ultimos:
            from urllib.parse import urlsplit

            partes = urlsplit(f.target)
            clave = partes.netloc or f.target
            entrada = objetivos.setdefault(clave, {
                "objetivo": clave, "total": 0, "peor": "info", "rutas": set(),
            })
            entrada["total"] += 1
            entrada["rutas"].add(partes.path or "/")
            if int(f.severity) > int(Severity[entrada["peor"].upper()]):
                entrada["peor"] = Severity(f.severity).label
        top_objetivos = sorted(
            ({**e, "rutas": len(e["rutas"])} for e in objetivos.values()),
            key=lambda e: -e["total"],
        )[:6]

        # Antigüedad de lo que sigue abierto. Un hallazgo confirmado hace tres
        # semanas y todavía abierto dice más que el total del último escaneo.
        ahora = datetime.now(_tz.utc)
        abiertos = [
            (f, estados.get(f.fingerprint)) for f in ultimos
            if str(estados.get(f.fingerprint).status if estados.get(f.fingerprint)
                   else "new") in ("new", "confirmed")
        ]
        tramos = {"hoy": 0, "esta semana": 0, "este mes": 0, "más de un mes": 0}
        edades = []
        for f, estado in abiertos:
            visto = estado.first_seen if estado else f.detected_at
            if visto.tzinfo is None:
                visto = visto.replace(tzinfo=_tz.utc)
            dias = max((ahora - visto).days, 0)
            tramos["hoy" if dias < 1 else "esta semana" if dias < 7
                   else "este mes" if dias < 31 else "más de un mes"] += 1
            edades.append({
                "titulo": f.title, "objetivo": f.target, "dias": dias,
                "severidad": Severity(f.severity).label,
                "estado": str(estado.status) if estado else "new",
                "fingerprint": f.fingerprint,
            })
        mas_viejos = sorted(edades, key=lambda e: -e["dias"])[:5]

        tareas = [
            {"name": t.name, "tool": t.tool, "status": str(t.status), "error": t.error}
            for t in s.scalars(select(Task).where(Task.scan_id == ultimo.id))
        ]
        resumen = {
            "escaneos": len(escaneos_),
            "hallazgos": len(ultimos),
            "graves": sum(1 for f in ultimos if int(f.severity) >= int(Severity.HIGH)),
            # Un hallazgo sin fila de estado es nuevo por definición: nadie
            # lo ha mirado todavía.
            "pendientes": sum(
                1 for f in ultimos
                if f.fingerprint not in estados
                or str(estados[f.fingerprint].status) == "new"
            ),
            "abiertos": len(abiertos),
            "ultimo": {
                "id": ultimo.id,
                "kind": str(ultimo.kind),
                "profile": ultimo.profile,
                "status": str(ultimo.status),
                "fecha": ultimo.started_at.isoformat() if ultimo.started_at else None,
                "duracion": _segundos(ultimo.started_at, ultimo.finished_at),
                "tareas_fallidas": sum(1 for t in tareas if t["status"] == "failed"),
                "tareas_omitidas": sum(1 for t in tareas if t["status"] == "skipped"),
            },
        }
        cobertura = {**(ultimo.coverage or {}), "tareas": tareas}
        anterior = escaneos_[-2] if len(escaneos_) > 1 else None

    cambio = None
    if anterior is not None:
        from ...core.diff import comparar

        try:
            d = comparar(anterior.id, ultimo.id)
        except ValueError:
            cambio = None
        else:
            cambio = {
                "antes": d.scan_antes, "ahora": d.scan_ahora,
                **d.resumen, "hay_regresion": d.hay_regresion,
            }

    return {
        "tendencia": tendencia,
        "triaje": {str(k): v for k, v in triaje.items()},
        "resumen": resumen,
        "por_herramienta": por_herramienta,
        "top_checks": top_checks,
        "top_objetivos": top_objetivos,
        "antiguedad": {"tramos": tramos, "mas_viejos": mas_viejos},
        "cobertura": cobertura,
        "cambio": cambio,
    }


@router.get("/scans/{antes}/diff/{ahora}")
async def diferencia_entre_escaneos(antes: int, ahora: int) -> dict[str, Any]:
    """Qué cambió entre dos escaneos del mismo proyecto.

    Separa lo corregido de lo que dejó de comprobarse. Es la distinción que
    evita cantar victoria: si el segundo escaneo usó otro perfil o le faltó
    una herramienta, los hallazgos que ya no aparecen no están arreglados.
    """
    from ...core.diff import comparar

    try:
        d = comparar(antes, ahora)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    return {
        "scan_antes": d.scan_antes,
        "scan_ahora": d.scan_ahora,
        "resumen": d.resumen,
        "hay_regresion": d.hay_regresion,
        "nuevos": d.nuevos,
        "corregidos": d.corregidos,
        "persistentes": d.persistentes,
        "sin_comprobar": d.sin_comprobar,
        "cambios_de_severidad": [
            {"fingerprint": c.fingerprint, "titulo": c.titulo, "objetivo": c.objetivo,
             "antes": c.antes.label, "ahora": c.ahora.label, "empeora": c.empeora}
            for c in d.cambios
        ],
    }


# ── Trabajos en curso ───────────────────────────────────────────────────────
@router.post("/jobs", status_code=202)
async def lanzar(peticion: PeticionDeEscaneo, request: Request) -> dict[str, Any]:
    if peticion.tipo == "code":
        if len(peticion.targets) != 1:
            raise HTTPException(
                400, "un análisis de código recibe una sola ruta, no una lista"
            )
        for campo, etiqueta in (
            (peticion.credenciales, "las credenciales"),
            (peticion.roles, "los roles"),
            (peticion.sandbox, "el aislamiento de red"),
        ):
            if campo:
                raise HTTPException(
                    400,
                    f"{etiqueta} no aplican a un análisis de código: no usa la red",
                )

    avisos: list[str] = []
    credenciales = peticion.credenciales.construir() if peticion.credenciales else None
    if credenciales is not None and credenciales.modo == "ninguno":
        raise HTTPException(
            400,
            "las credenciales no dicen cómo entrar: hace falta una URL de "
            "acceso con usuario, una cabecera, o unas cookies",
        )

    roles = []
    for r in peticion.roles:
        credencial = r.credenciales.construir()
        if credencial.modo == "ninguno":
            raise HTTPException(
                400, f"el rol «{r.nombre}» no dice cómo entrar"
            )
        roles.append((r.nombre, r.rol, credencial))
    if len(roles) == 1:
        # Igual que en la línea de órdenes: con un solo rol la fase de
        # autorización no puede comparar nada. Se acepta y se dice, en vez de
        # ejecutar una fase que no puede dar resultado.
        avisos.append(
            "con un solo rol no hay comparación posible; añade otro para "
            "detectar fallos de autorización"
        )

    if peticion.sandbox:
        from ...core.sandbox import comprobar_disponible

        disponible, motivo = comprobar_disponible()
        if not disponible:
            # 409 y no 400: la petición es correcta, es el equipo el que no
            # puede cumplirla. Y se comprueba antes de encolar para que el
            # fallo salga en la respuesta y no haya que ir a buscarlo al
            # historial de un trabajo que nunca arrancó.
            raise HTTPException(409, f"no se puede aislar la red: {motivo}")

    trabajo = request.app.state.cola.enviar(
        peticion.targets,
        tipo=peticion.tipo,
        profile=peticion.profile,
        project=peticion.project,
        allow_public=peticion.allow_public,
        extra_hosts=peticion.extra_hosts,
        only=peticion.only,
        credenciales=credenciales,
        roles=roles,
        con_api=peticion.con_api,
        especificacion=peticion.especificacion_api,
        sandbox=peticion.sandbox,
    )
    return {**trabajo.como_dict(), "avisos": avisos}


@router.get("/jobs")
async def trabajos(request: Request) -> list[dict[str, Any]]:
    return [t.como_dict() for t in request.app.state.cola.listar()]


@router.get("/jobs/{job_id}")
async def trabajo(job_id: str, request: Request) -> dict[str, Any]:
    t = request.app.state.cola.obtener(job_id)
    if t is None:
        raise HTTPException(404, "ese trabajo no existe")
    return t.como_dict()


@router.delete("/jobs/{job_id}")
async def cancelar(job_id: str, request: Request) -> dict[str, Any]:
    ok = await request.app.state.cola.cancelar(job_id)
    if not ok:
        raise HTTPException(409, "el trabajo ya no está activo")
    return {"cancelado": job_id}


@router.get("/jobs/{job_id}/events")
async def eventos(job_id: str, request: Request) -> StreamingResponse:
    """Progreso en vivo por SSE. Reenvía lo ya ocurrido antes de seguir en
    directo, para que abrir la página a mitad de escaneo no muestre una barra
    vacía."""
    cola = request.app.state.cola
    if cola.obtener(job_id) is None:
        raise HTTPException(404, "ese trabajo no existe")

    async def flujo():
        async for evento in cola.seguir(job_id):
            yield f"data: {json.dumps(evento, ensure_ascii=False)}\n\n"

    return StreamingResponse(
        flujo(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


# ── Informes ────────────────────────────────────────────────────────────────
@router.get("/scans/{scan_id}/report.{formato}")
async def informe(scan_id: int, formato: str) -> FileResponse:
    if formato not in ("html", "pdf"):
        raise HTTPException(400, "formato no soportado: usa html o pdf")

    with session_scope() as s:
        scan = s.get(Scan, scan_id)
        if scan is None:
            raise HTTPException(404, "ese escaneo no existe")
        proyecto = s.get(Project, scan.project_id)
        datos = await hallazgos(scan_id)
        objetivos = [e["raw"] for e in (scan.scope or {}).get("entries", [])]
        perfil, inicio = scan.profile, scan.started_at

    destino = paths.reports_dir() / f"scan-{scan_id:06d}.{formato}"
    if not destino.exists():
        _generar(destino, scan_id, proyecto.name, perfil, objetivos, inicio, datos, formato)
    return FileResponse(destino, filename=destino.name)


def _generar(destino, scan_id, proyecto, perfil, objetivos, inicio, datos, formato) -> None:
    """Reconstruye los `Finding` desde la base para reutilizar el mismo
    renderizador que usa el CLI: un solo informe, no dos que se parecen."""
    from ...core.findings import Evidence, EvidenceKind, Finding
    from ...core.severity import Confidence

    reconstruidos: list[Finding] = []
    with session_scope() as s:
        for d in datos:
            evidencias = [
                Evidence(kind=EvidenceKind(e.kind), request=e.request,
                         response=e.response, snippet=e.snippet, path=e.path, meta=e.meta)
                for e in s.scalars(
                    select(EvidenceRecord).where(EvidenceRecord.finding_id == d["id"])
                )
            ]
            reconstruidos.append(
                Finding(
                    source=d["source"], check_id=d["check_id"], title=d["title"],
                    description=d["description"], remediation=d["remediation"],
                    target=d["target"], param=d["param"],
                    severity=Severity[d["severity"].upper()],
                    confidence=Confidence(d["confidence"]),
                    cvss_score=d["cvss_score"], cwe=d["cwe"], owasp=d["owasp"],
                    tags=d["tags"], evidence=evidencias, extra=d["extra"],
                )
            )

    contexto = build_context(
        reconstruidos, project=proyecto, scan_id=scan_id, profile=perfil,
        scope=Scope.build(objetivos, allow_public=True), started=inicio,
        duration="—", alive=0, probed=0,
        tools=sorted({f.source for f in reconstruidos}),
    )
    html = render_html(contexto, destino if formato == "html" else None)
    if formato == "pdf":
        render_pdf(html, destino)
