"""Orquestación de un escaneo web: fases, persistencia y triaje persistente.

Un escaneo es una secuencia de fases. Cada fase deja una fila en `tasks` con el
argv exacto que se ejecutó, de modo que después se puede responder con precisión
a "qué le lanzasteis exactamente a esta máquina".

La parte menos obvia está al final, en `_persist`: los hallazgos se cruzan contra
`FindingState` por `(proyecto, fingerprint)`, lo que produce tres cosas que un
escaneo suelto no puede dar — qué es nuevo, qué sigue ahí y qué se ha corregido —
y hace que un falso positivo marcado hace tres semanas siga marcado hoy.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Sequence
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..adapters import all_adapters
from ..adapters.base import ScanContext
from ..modules import activos, jwt as jwt_mod, passive
from ..modules.auth import Credenciales, Sesion, autenticar
from ..modules.authz import ComparadorDeRoles, comprobar_fijacion_de_sesion
from ..modules.crawler import Crawler, nuevo_navegador
from ..modules.probe import ProbeResult, Prober
from . import paths
from .equivalence import canonical_for, prefer
from .equivalence import SOURCE_RANK
from .findings import Finding, FindingStatus
from .models import (
    AuditEvent,
    Artifact,
    EvidenceRecord,
    FindingRecord,
    FindingState,
    Project,
    RunStatus,
    Scan,
    ScanKind,
    Target,
    Task,
)
from .policy import Policy, Profile, get_policy
from .runner import Runner, ToolMissing, tool_version, version_flags
from .scope import Scope
from .severity import Severity
from .store import init_db, session_scope

# Rutas que se prueban siempre, aunque no estén enlazadas: son baratas y
# concentran una parte desproporcionada de los hallazgos reales.
SEED_PATHS: tuple[str, ...] = (
    "/", "/robots.txt", "/.git/config", "/.env", "/debug/env",
    "/login", "/signin", "/auth/login",
    "/actuator/env", "/actuator/health", "/server-status",
    "/files/", "/backup/", "/admin/", "/api/", "/swagger-ui/",
    "/openapi.json", "/.well-known/security.txt",
)

ProgressFn = Callable[[str, str, float], None]


@dataclass(slots=True)
class ScanOutcome:
    scan_id: int
    findings: list[Finding] = field(default_factory=list)
    probes: list[ProbeResult] = field(default_factory=list)
    tasks: list[dict[str, object]] = field(default_factory=list)
    new: int = 0
    recurring: int = 0
    fixed: int = 0

    @property
    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.severity.label] = counts.get(finding.severity.label, 0) + 1
        return counts


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def seed_urls(scope: Scope) -> list[str]:
    """URLs de partida: lo que pidió el operador más las rutas de siembra."""
    urls: list[str] = []
    for entry in scope.entries:
        if entry.kind != "url":
            continue
        base = f"{entry.scheme}://{entry.host}"
        if entry.port not in (80, 443):
            base += f":{entry.port}"
        urls.append(entry.raw)
        urls.extend(base + path for path in SEED_PATHS)
    return list(dict.fromkeys(urls))


async def run_web_scan(
    targets: Sequence[str],
    *,
    profile: str | Profile = Profile.SAFE_ACTIVE,
    project_name: str = "default",
    db=None,
    allow_public: bool = False,
    extra_hosts: Iterable[str] = (),
    only: Sequence[str] | None = None,
    credenciales: Credenciales | None = None,
    roles: Sequence[tuple[str, str, Credenciales]] = (),
    con_crawler: bool = True,
    on_progress: ProgressFn | None = None,
) -> ScanOutcome:
    """Ejecuta un escaneo web completo y lo persiste.

    `credenciales` autentica al crawler. `roles` son tripletas
    (nombre, rol, credenciales) para comparar control de acceso: hacen falta al
    menos dos para que la comparación diga algo.

    `con_crawler=False` omite el navegador. Cuesta unos segundos por escaneo y
    es lo que más tarda cuando no aporta: en una API sin interfaz, o en los
    tests que comprueban el ciclo de triaje y no la detección.
    """
    policy = get_policy(profile)
    # Construir el alcance resuelve DNS y rechaza lo que no sea interno: si esto
    # lanza, no se ha tocado nada todavía.
    scope = Scope.build(
        targets, allow_public=allow_public, extra_hosts=extra_hosts
    )

    init_db(db)
    with session_scope(db) as session:
        project = _get_or_create_project(session, project_name)
        scan = Scan(
            project_id=project.id,
            kind=ScanKind.WEB,
            profile=str(policy.profile),
            status=RunStatus.RUNNING,
            started_at=_utcnow(),
            scope=scope.describe(),
        )
        session.add(scan)
        session.flush()
        scan_id, project_id = scan.id, project.id
        session.add(
            AuditEvent(
                scan_id=scan_id,
                action="scan.start",
                detail={
                    "targets": list(targets),
                    "profile": str(policy.profile),
                    "allow_public": allow_public,
                    "rejected": scope.describe()["rejected"],
                },
            )
        )

    workdir = paths.runs_dir() / f"scan-{scan_id:06d}"
    workdir.mkdir(parents=True, exist_ok=True)
    outcome = ScanOutcome(scan_id=scan_id)

    def progress(phase: str, message: str, pct: float) -> None:
        if on_progress is not None:
            on_progress(phase, message, pct)

    audit: list[tuple[str, dict]] = []
    # Qué comprobaciones y qué orígenes se ejecutaron realmente en este escaneo.
    cobertura_checks: set[str] = set()
    cobertura_origenes: set[str] = set()
    runner = Runner(workdir=workdir, audit=lambda a, d: audit.append((a, d)))

    try:
        # ── Fase 1: probar y tomar huella ─────────────────────────────────
        progress("probe", "probando objetivos", 0.0)
        urls = seed_urls(scope)
        prober = Prober(scope, policy)
        with _task(db, scan_id, "probe", "crux") as task:
            outcome.probes = await prober.probe_many(urls)
            alive = [p for p in outcome.probes if p.alive]
            task["detail"] = f"{len(alive)} de {len(urls)} URLs responden"
        progress("probe", f"{len(alive)} URLs vivas de {len(urls)}", 0.25)

        # ── Fase 2: comprobaciones propias, sin red ───────────────────────
        with _task(db, scan_id, "checks-pasivos", "crux") as task:
            own = passive.run_all(outcome.probes)
            outcome.findings.extend(own)
            # Lo que se comprobó, no solo lo que se encontró: sin esto, un
            # hallazgo que desaparece porque esta vez no se buscó acabaría
            # marcado como corregido.
            cobertura_checks.update(passive.coverage(outcome.probes))
            cobertura_origenes.add("passive")
            task["detail"] = f"{len(own)} hallazgos"
        progress("passive", f"{len(own)} hallazgos propios", 0.4)

        # ── Fase 3: recorrido con navegador ───────────────────────────────
        crawl = None
        if con_crawler and policy.crawl_max_pages > 0:
            progress("crawler", "recorriendo con navegador", 0.45)
            with _task(db, scan_id, "crawler", "selenium") as task:
                try:
                    # Selenium es síncrono; se aparta del bucle de eventos para
                    # no bloquear la transmisión de progreso de la interfaz.
                    # Las semillas incluyen lo que el probador encontró vivo,
                    # no solo el objetivo declarado: rutas como /login no
                    # suelen estar enlazadas desde la portada, y desde ellas
                    # cuelga buena parte de la aplicación.
                    semillas = list(dict.fromkeys(
                        [e.raw for e in scope.entries if e.kind == "url"]
                        + [p.final_url for p in outcome.probes if p.alive]
                    ))
                    crawl = await asyncio.to_thread(
                        Crawler(scope, policy, credenciales=credenciales).recorrer,
                        semillas,
                    )
                    task["detail"] = (f"{crawl.paginas_visitadas} páginas, "
                                      f"{len(crawl.endpoints)} endpoints")
                    cobertura_origenes.add("crawler")
                except Exception as exc:
                    # Sin navegador el escaneo sigue: se pierde cobertura, no
                    # todo el resultado.
                    task["status"] = RunStatus.FAILED
                    task["detail"] = f"{type(exc).__name__}: {exc}"

        if crawl is not None:
            outcome.findings.extend(_hallazgos_de_crawl(crawl))

        # ── Fase 4: comprobaciones que necesitan el recorrido ─────────────
        if crawl is not None and policy.allow_active_probes:
            progress("jwt", "analizando tokens", 0.55)
            with _task(db, scan_id, "jwt", "crux") as task:
                encontrados = await _fase_jwt(scope, policy, outcome, crawl, credenciales)
                outcome.findings.extend(encontrados)
                cobertura_origenes.add("jwt")
                task["detail"] = f"{len(encontrados)} hallazgos"

        if crawl is not None and policy.allow_active_probes:
            progress("activos", "probando parámetros descubiertos", 0.58)
            with _task(db, scan_id, "checks-activos", "crux") as task:
                endpoints = [{"url": e.url, "params": e.params}
                             for e in crawl.con_parametros]
                encontrados = await activos.comprobar_redireccion_abierta(
                    scope, policy, endpoints
                )
                outcome.findings.extend(encontrados)
                cobertura_origenes.add("activos")
                task["detail"] = f"{len(encontrados)} hallazgos"

        if len(roles) >= 1 and crawl is not None:
            progress("authz", "comparando roles", 0.62)
            with _task(db, scan_id, "authz", "crux") as task:
                encontrados = await _fase_authz(scope, policy, crawl, roles)
                outcome.findings.extend(encontrados)
                cobertura_origenes.add("authz")
                task["detail"] = f"{len(encontrados)} hallazgos"

        # ── Fase 5: adaptadores de herramienta ────────────────────────────
        context = ScanContext(
            scope=scope,
            policy=policy,
            workdir=workdir,
            project_id=project_id,
            scan_id=scan_id,
            discovered={
                "urls": list(dict.fromkeys(
                    [p.final_url for p in outcome.probes if p.alive]
                    + (crawl.urls if crawl else [])
                )),
                # La huella que sacó nuestro probador acota el catálogo de
                # plantillas de nuclei. Sin esto el escaneo dura quince minutos
                # en vez de uno.
                "technologies": sorted(
                    {t for p in outcome.probes if p.alive for t in p.technologies}
                ),
                # Endpoints con parámetros: la superficie donde inyectar.
                "endpoints": [
                    {"url": e.url, "metodo": e.metodo, "params": e.params}
                    for e in (crawl.con_parametros if crawl else [])
                ],
            },
        )
        adapters = all_adapters()
        # `only=None` significa todos; una lista vacía significa ninguno. Antes
        # ambas cosas significaban "todos", que es lo contrario de lo esperable.
        wanted = [n for n in adapters if (only is None or n in only)]
        for index, name in enumerate(wanted):
            adapter = adapters[name]()
            if adapter.kind != "web":
                continue
            # El tramo de adaptadores empieza donde acaban las fases propias,
            # no en 0.4: el progreso no debe retroceder nunca.
            progress(name, f"ejecutando {name}", 0.65 + 0.25 * index / max(len(wanted), 1))
            with _task(db, scan_id, name, name) as task:
                if not adapter.available():
                    task["status"] = RunStatus.SKIPPED
                    task["detail"] = "no instalada"
                    continue
                try:
                    produced = await adapter.execute(context, runner)
                except ToolMissing as exc:
                    task["status"] = RunStatus.SKIPPED
                    task["detail"] = str(exc)
                    continue
                outcome.findings.extend(produced)
                cobertura_origenes.add(name)
                task["detail"] = f"{len(produced)} hallazgos"

        progress("persist", "guardando resultados", 0.92)
        _persist(db, scan_id, project_id, outcome, scope, audit,
                 cobertura_checks, cobertura_origenes,
                 superficie=_superficie(outcome.probes, crawl))
        progress("done", "escaneo terminado", 1.0)
        return outcome

    except Exception as exc:
        with session_scope(db) as session:
            scan = session.get(Scan, scan_id)
            scan.status = RunStatus.FAILED
            scan.error = f"{type(exc).__name__}: {exc}"
            scan.finished_at = _utcnow()
        raise


class _task:
    """Contexto que abre y cierra una fila de `tasks`, pase lo que pase."""

    def __init__(self, db, scan_id: int, name: str, tool: str) -> None:
        self.db, self.scan_id, self.name, self.tool = db, scan_id, name, tool
        self.state: dict[str, object] = {"status": RunStatus.DONE, "detail": ""}

    def __enter__(self) -> dict[str, object]:
        self.started = _utcnow()
        return self.state

    def __exit__(self, exc_type, exc, tb) -> bool:
        status = self.state["status"]
        error = None
        if exc is not None:
            status, error = RunStatus.FAILED, f"{type(exc).__name__}: {exc}"
        with session_scope(self.db) as session:
            session.add(
                Task(
                    scan_id=self.scan_id,
                    name=self.name,
                    tool=self.tool,
                    status=status,
                    started_at=self.started,
                    finished_at=_utcnow(),
                    error=error,
                    progress=1.0,
                    argv=list(self.state.get("argv") or []),
                )
            )
        # Un adaptador que falla no debe tumbar el escaneo entero: se registra
        # la tarea como fallida y se sigue con los demás.
        return exc is not None and not isinstance(exc, (KeyboardInterrupt, SystemExit))


def _aviso_de_descuadre(conteo: dict[str, int], descuadre: int) -> Finding:
    """Hallazgo sobre el propio escaneo: las cuentas no cuadran."""
    from .severity import Confidence, Severity

    return Finding(
        source="crux",
        check_id="descuadre-de-hallazgos",
        title=f"{abs(descuadre)} hallazgo(s) se perdieron entre fases del escaneo",
        description=(
            f"Las fases produjeron {conteo['producidos']} hallazgo(s). "
            f"{conteo['colapsados_por_huella']} se colapsaron por huella "
            f"—la misma comprobación vista por dos herramientas— y "
            f"{conteo['absorbidos_por_otro_mejor']} los absorbió otro mejor "
            f"explicado, lo que deja {conteo['guardados']} guardado(s). "
            + (
                f"De los absorbidos, {conteo['absorbidos_sin_quien_los_cubra']} "
                "desaparecieron sin que el hallazgo que debía cubrirlos esté en "
                "el informe. "
                if conteo.get("absorbidos_sin_quien_los_cubra") else
                f"La resta no cuadra por {abs(descuadre)}. "
            )
            + "Este informe está incompleto y no se sabe exactamente en qué."
        ),
        remediation=(
            "Esto es un fallo de Crux, no del objetivo. Repite el escaneo y, "
            "si vuelve a pasar, no des el informe por completo."
        ),
        target="crux",
        severity=Severity.HIGH,
        confidence=Confidence.CERTAIN,
        tags=["cobertura"],
        extra=dict(conteo),
    )


def _absorb(
    findings: list[Finding],
) -> tuple[list[Finding], list[tuple[Finding, tuple[str, str]]]]:
    """Descarta hallazgos que otro mejor explicado ya cubre.

    El deduplicado por fingerprint no basta cuando la herramienta de menor rango
    no puede aportar el discriminante. nuclei dice "falta la marca Secure" sin
    decir en qué cookie; nuestro módulo emite un hallazgo por cookie con su
    nombre, sus tres atributos y la corrección. Conservar ambos multiplica las
    filas sin añadir información, así que el suyo se absorbe cuando ya existe el
    nuestro sobre el mismo origen.

    Es deliberadamente conservador: si el hallazgo mejor explicado NO existe
    —porque nuestro módulo no llegó a esa ruta—, el de la herramienta se queda.
    Absorber nunca debe esconder un hallazgo que nadie más reporta.
    """
    from urllib.parse import urlsplit

    def origen(url: str) -> str:
        split = urlsplit(url)
        return f"{split.scheme}://{split.netloc}" if split.netloc else url.lower()

    # Qué identidades canónicas cubre cada origen, y con qué rango de fuente.
    cobertura: dict[tuple[str, str], int] = {}
    for finding in findings:
        canonical = canonical_for(finding.source, finding.check_id)
        if canonical is None:
            continue
        clave = (canonical.check_id, origen(finding.target))
        rango = SOURCE_RANK.get(finding.source, 0)
        cobertura[clave] = max(cobertura.get(clave, 0), rango)

    conservados: list[Finding] = []
    # Cada absorbido, con la identidad que supuestamente lo cubre. Devolverlo
    # es lo que permite comprobar después que esa cobertura existe de verdad:
    # contar las bajas no demuestra nada, porque una baja indebida también se
    # cuenta y la resta sigue cuadrando.
    absorbidos: list[tuple[Finding, tuple[str, str]]] = []
    for finding in findings:
        canonical = canonical_for(finding.source, finding.check_id)
        if canonical is None or not canonical.absorb:
            conservados.append(finding)
            continue
        clave = (canonical.check_id, origen(finding.target))
        mi_rango = SOURCE_RANK.get(finding.source, 0)
        if cobertura.get(clave, 0) > mi_rango:
            absorbidos.append((finding, clave))   # ya lo cubre uno mejor
            continue
        conservados.append(finding)
    return conservados, absorbidos


def _absorciones_justificadas(
    conservados: list[Finding], absorbidos: list[tuple[Finding, tuple[str, str]]]
) -> list[Finding]:
    """De los absorbidos, los que se fueron sin que nadie los cubra.

    Absorber es legítimo: un hallazgo peor explicado desaparece porque otro
    dice lo mismo mejor. Lo que no es legítimo es que desaparezca y el que
    supuestamente lo cubría no esté. Esto se comprueba, no se supone.
    """
    from urllib.parse import urlsplit

    def origen(url: str) -> str:
        split = urlsplit(url)
        return f"{split.scheme}://{split.netloc}" if split.netloc else url.lower()

    presentes = set()
    for f in conservados:
        canonical = canonical_for(f.source, f.check_id)
        if canonical is not None:
            presentes.add((canonical.check_id, origen(f.target)))
    return [f for f, clave in absorbidos if clave not in presentes]


def _get_or_create_project(session: Session, name: str) -> Project:
    slug = name.strip().lower().replace(" ", "-")[:96] or "default"
    project = session.scalar(select(Project).where(Project.slug == slug))
    if project is None:
        project = Project(slug=slug, name=name)
        session.add(project)
        session.flush()
    return project


# Orígenes cuya cobertura se conoce comprobación a comprobación. Para una
# herramienta externa solo sabemos si se ejecutó o no: nuclei no informa de qué
# plantillas descartó el filtro de etiquetas.
OWN_SOURCES = frozenset({"passive", "probe", "authz", "jwt"})


def _superficie(probes, crawl) -> dict[str, Any]:
    """La superficie que el escaneo vio, con hallazgos o sin ellos.

    Hasta ahora esto se tiraba al acabar: el grafo se reconstruía solo a partir
    de los hallazgos, así que una ruta sin fallos no existía en él. Pero una
    superficie de ataque es lo que hay expuesto, no lo que está roto; una ruta
    sin hallazgos es igual de parte de la superficie, y a veces la más
    interesante —la que nadie ha mirado—.
    """
    sondas = [
        {
            "url": p.url,
            "final_url": p.final_url,
            "status": p.status,
            "viva": p.alive,
            "titulo": p.title,
            "servidor": p.server,
            "tipo_contenido": p.content_type,
            "longitud": p.content_length,
            "tecnologias": list(p.technologies),
            "redirecciones": list(p.redirect_chain),
            "error": p.error,
        }
        for p in probes
    ]
    endpoints = [
        {
            "url": e.url,
            "metodo": e.metodo,
            "params": list(e.params),
            "origen": e.origen,
            "tipo_contenido": e.tipo_contenido,
        }
        for e in (crawl.endpoints if crawl else [])
    ]
    return {
        "sondas": sondas,
        "endpoints": endpoints,
        "formularios": [dict(f) for f in (crawl.formularios if crawl else [])],
        "fuera_de_alcance": list(crawl.fuera_de_alcance) if crawl else [],
        "paginas_visitadas": crawl.paginas_visitadas if crawl else 0,
        # Que el recorrido no se hiciera no es lo mismo que no haber
        # encontrado nada, y la interfaz tiene que poder distinguirlo.
        "hubo_recorrido": crawl is not None,
    }


def _persist(db, scan_id: int, project_id: int, outcome: ScanOutcome,
             scope: Scope | None, audit: list[tuple[str, dict]],
             cobertura_checks: set[str] | None = None,
             cobertura_origenes: set[str] | None = None,
             superficie: dict[str, Any] | None = None) -> None:
    """Guarda hallazgos y cruza con el triaje previo del proyecto.

    Lleva la cuenta de cada reducción —colapsos por huella, absorciones— y
    comprueba que cuadre con lo que las fases produjeron. Si no cuadra, se
    guarda un hallazgo que lo dice en vez de dejar que el informe enseñe menos
    de lo que hubo, que es la forma más cara de equivocarse que tiene una
    herramienta de auditoría: no da un susto, da tranquilidad falsa.
    """
    now = _utcnow()
    producidos = len(outcome.findings)
    # Deduplicar dentro del propio escaneo: dos herramientas pueden reportar lo
    # mismo, y el fingerprint es justo lo que las hace colapsar.
    unique: dict[str, Finding] = {}
    for finding in outcome.findings:
        existing = unique.get(finding.fingerprint)
        if existing is None:
            unique[finding.fingerprint] = finding
            continue
        # Al colapsar gana el que mejor explica el hallazgo: más severidad, y a
        # igualdad, el origen de mayor rango (nuestros módulos agrupan, razonan
        # la severidad y escriben la corrección; una herramienta solo dispara).
        if finding.severity > existing.severity or (
            finding.severity == existing.severity
            and prefer(finding.source, existing.source)
            and finding.source != existing.source
        ):
            finding.evidence.extend(existing.evidence)
            finding.extra.setdefault("also_found_by", []).append(existing.source)
            unique[finding.fingerprint] = finding
        else:
            # Se conserva la evidencia de ambos: dos pruebas valen más que una.
            existing.evidence.extend(finding.evidence)
            if finding.source not in existing.extra.get("also_found_by", []):
                existing.extra.setdefault("also_found_by", []).append(finding.source)
    # La absorción tiene que aplicarse ANTES de persistir, no solo a lo que se
    # muestra: si no, la base guarda el hallazgo absorbido y la web UI —que lee
    # de la base— enseña uno más que el CLI y que el informe.
    colapsados = producidos - len(unique)
    antes_de_absorber = len(unique)
    conservados, absorbidos = _absorb(list(unique.values()))
    unique = {f.fingerprint: f for f in conservados}
    outcome.findings = conservados

    # Dos comprobaciones distintas, y las dos hacen falta:
    #
    # 1. Que la resta cuadre: todo lo que entró está guardado o tiene un motivo
    #    declarado. Esto pilla una pérdida por el camino.
    # 2. Que cada absorción esté justificada: el hallazgo que supuestamente
    #    cubre al absorbido sigue ahí. Esto pilla lo que la resta no puede
    #    pillar, porque una baja indebida también se cuenta como baja y la
    #    resta sigue cuadrando. Fue exactamente el agujero de la primera
    #    versión de esta comprobación.
    huerfanos = _absorciones_justificadas(conservados, absorbidos)
    conteo = {
        "producidos": producidos,
        "colapsados_por_huella": colapsados,
        "absorbidos_por_otro_mejor": len(absorbidos),
        "absorbidos_sin_quien_los_cubra": len(huerfanos),
        "guardados": len(unique),
    }
    descuadre = (
        (antes_de_absorber - len(absorbidos) - len(conservados))
        + (producidos - colapsados - antes_de_absorber)
        + len(huerfanos)
    )
    if descuadre:
        # No debería poder pasar. Si pasa, se dice: un hallazgo que se pierde
        # entre fases es exactamente lo que nadie va a echar de menos.
        aviso = _aviso_de_descuadre(conteo, descuadre)
        unique[aviso.fingerprint] = aviso
        # También a lo que se devuelve: el CLI y el informe enseñan
        # `outcome.findings`, no la base. Si el aviso solo llegara a una de las
        # dos, por consola el escaneo seguiría saliendo callado.
        outcome.findings = list(unique.values())
        conteo["guardados"] = len(unique)
        conteo["descuadre"] = descuadre

    with session_scope(db) as session:
        seen_now = set(unique)
        previous = {
            state.fingerprint: state
            for state in session.scalars(
                select(FindingState).where(FindingState.project_id == project_id)
            )
        }

        for fingerprint, finding in unique.items():
            record = FindingRecord(
                scan_id=scan_id,
                project_id=project_id,
                fingerprint=fingerprint,
                source=finding.source,
                check_id=finding.check_id,
                title=finding.title,
                description=finding.description,
                remediation=finding.remediation,
                severity=finding.severity,
                confidence=finding.confidence,
                cvss_vector=finding.cvss_vector,
                cvss_score=finding.cvss_score,
                target=finding.target,
                param=finding.param,
                cwe=finding.cwe,
                owasp=finding.owasp,
                references=finding.references,
                tags=finding.tags,
                extra=finding.extra,
                detected_at=finding.detected_at,
            )
            session.add(record)
            session.flush()
            for evidence in finding.evidence:
                session.add(
                    EvidenceRecord(
                        finding_id=record.id,
                        kind=str(evidence.kind),
                        request=evidence.request,
                        response=evidence.response,
                        snippet=evidence.snippet,
                        path=evidence.path,
                        meta=evidence.meta,
                    )
                )

            state = previous.get(fingerprint)
            if state is None:
                session.add(
                    FindingState(
                        project_id=project_id,
                        fingerprint=fingerprint,
                        source=finding.source,
                        check_id=finding.check_id,
                        status=FindingStatus.NEW,
                        first_seen=now,
                        last_seen=now,
                        last_scan_id=scan_id,
                    )
                )
                outcome.new += 1
            else:
                state.last_seen = now
                state.last_scan_id = scan_id
                # Si se había dado por corregido y vuelve a aparecer, deja de
                # estarlo: una regresión no puede quedarse marcada como resuelta.
                if state.status == FindingStatus.FIXED:
                    state.status = FindingStatus.NEW
                outcome.recurring += 1

        # Lo que estaba y ya no aparece se marca corregido — pero SOLO si la
        # comprobación que lo produjo se ha vuelto a ejecutar.
        #
        # Es la parte más delicada del ciclo. Un hallazgo puede desaparecer por
        # dos motivos opuestos: porque se arregló, o porque esta vez no se
        # buscó (otro perfil, una herramienta ausente, un adaptador que falló).
        # Confundirlos significa decirle a un equipo que una vulnerabilidad está
        # resuelta sin haberla comprobado, que es peor que no decir nada.
        checks = cobertura_checks or set()
        origenes = cobertura_origenes or set()
        for fingerprint, state in previous.items():
            if fingerprint in seen_now:
                continue
            if state.status in (FindingStatus.FALSE_POSITIVE, FindingStatus.ACCEPTED_RISK):
                continue
            if state.source and state.source not in origenes:
                continue    # su origen no se ejecutó: no sabemos nada
            if state.source in OWN_SOURCES and state.check_id and state.check_id not in checks:
                continue    # su comprobación concreta no se evaluó
            if state.status != FindingStatus.FIXED:
                state.status = FindingStatus.FIXED
                outcome.fixed += 1

        for host in (scope.hosts if scope is not None else []):
            if not session.scalar(
                select(Target).where(Target.project_id == project_id, Target.raw == host)
            ):
                session.add(Target(project_id=project_id, raw=host, kind="web", host=host))

        for action, detail in audit:
            session.add(AuditEvent(scan_id=scan_id, action=action, detail=detail))

        versions = {}
        for name in all_adapters():
            adapter = all_adapters()[name]()
            if adapter.available():
                versions[name] = tool_version(
                    adapter.binary, (adapter.binary, *version_flags(adapter.binary))
                )
        scan = session.get(Scan, scan_id)
        scan.status = RunStatus.DONE
        scan.finished_at = now
        scan.tool_versions = versions
        scan.coverage = {
            "origenes": sorted(cobertura_origenes or set()),
            "comprobaciones": sorted(cobertura_checks or set()),
            # Cuántos hallazgos produjeron las fases y en qué se quedaron. La
            # interfaz lo enseña: un informe tiene que poder explicar la
            # diferencia entre lo que se encontró y lo que se lee.
            "conteo": conteo,
        }
        if superficie is not None:
            scan.surface = superficie


# ── Funciones de fase ───────────────────────────────────────────────────────
def _hallazgos_de_crawl(crawl) -> list[Finding]:
    """Lo que el propio recorrido revela, sin más comprobaciones.

    Que una aplicación interna cargue recursos de fuera es un hallazgo por sí
    mismo: además de la fuga de información hacia el tercero, pone la
    disponibilidad y la integridad de la página en manos ajenas.
    """
    from ..core.findings import Evidence, EvidenceKind
    from ..core.severity import Confidence

    if not crawl.fuera_de_alcance:
        return []
    destinos = sorted({urlsplit(u).netloc for u in crawl.fuera_de_alcance})
    return [Finding(
        source="crawler",
        check_id="recurso-externo-cargado",
        title=f"La aplicación carga recursos de {len(destinos)} origen(es) externo(s)",
        description=(
            "Mientras se recorría la aplicación, el navegador pidió recursos a "
            + ", ".join(destinos[:6])
            + ". Una aplicación interna que depende de un tercero le entrega el "
            "control de lo que se ejecuta en el navegador del empleado, y le "
            "revela quién la usa y cuándo."
        ),
        remediation=(
            "Sirve esos recursos desde la propia red. Si alguno tiene que venir "
            "de fuera, fíjalo con Subresource Integrity y decláralo en la CSP."
        ),
        target=crawl.fuera_de_alcance[0],
        severity=Severity.MEDIUM,
        confidence=Confidence.CERTAIN,
        cwe=["CWE-829"],
        owasp=["A08:2021"],
        evidence=[Evidence(kind=EvidenceKind.RAW,
                           snippet="\n".join(crawl.fuera_de_alcance[:20]))],
        extra={"destinos": destinos, "urls": crawl.fuera_de_alcance[:50]},
    )]


async def _fase_jwt(scope: Scope, policy: Policy, outcome: ScanOutcome,
                    crawl, credenciales: Credenciales | None) -> list[Finding]:
    """Busca JWTs en lo observado y, si hay dónde probarlos, los forja."""
    import httpx

    textos: list[tuple[str, str]] = []
    for sonda in outcome.probes:
        if not sonda.alive:
            continue
        for nombre, valor in sonda.headers.items():
            textos.append((f"header:{nombre}", valor))
        for cookie in sonda.cookies:
            # El valor, no el nombre: es donde vive el token.
            textos.append((f"cookie:{cookie.get('name')}", str(cookie.get("value", ""))))
        textos.append((f"body:{sonda.final_url}", sonda.body_preview))
    if crawl is not None and crawl.sesion is not None:
        for nombre, valor in crawl.sesion.cookies.items():
            textos.append((f"cookie:{nombre}", valor))
        for nombre, valor in crawl.sesion.cabeceras.items():
            textos.append((f"header:{nombre}", valor))
    if credenciales:
        for nombre, valor in credenciales.cabeceras.items():
            textos.append((f"credencial:{nombre}", valor))

    tokens = jwt_mod.extraer(textos)
    if not tokens:
        return []

    objetivo = next((e.raw for e in scope.entries if e.kind == "url"), "")
    hallazgos: list[Finding] = []
    for token in tokens:
        hallazgos.extend(jwt_mod.analizar(token, objetivo))

    # La prueba activa necesita un endpoint que consuma el token. Se eligen los
    # que el recorrido marcó como de API: son los que lo usan.
    candidatos = [e.url for e in crawl.endpoints
                  if "/api/" in e.url or e.url.rstrip("/").endswith(("/me", "/profile"))]
    if candidatos and policy.allow_active_probes:
        async with httpx.AsyncClient(trust_env=False, verify=False,
                                     timeout=httpx.Timeout(policy.request_timeout)) as cliente:
            for token in tokens[:3]:
                for url in candidatos[:5]:
                    if not scope.allows_url(url):
                        continue
                    hallazgo = await jwt_mod.probar_alg_none(cliente, url, token)
                    if hallazgo is not None:
                        hallazgos.append(hallazgo)
                        break
    return hallazgos


async def _fase_authz(scope: Scope, policy: Policy, crawl,
                      roles: Sequence[tuple[str, str, Credenciales]]) -> list[Finding]:
    """Compara lo que ve cada rol. Necesita al menos una sesión autenticada."""
    sesiones: list[Sesion] = [Sesion(nombre="anónima", autenticada=False)]
    driver = None
    try:
        for nombre, rol, credencial in roles:
            if credencial.modo == "formulario":
                if driver is None:
                    driver = await asyncio.to_thread(nuevo_navegador)
                sesion = await asyncio.to_thread(
                    autenticar, driver, credencial, nombre=nombre, rol=rol
                )
            else:
                sesion = await asyncio.to_thread(
                    autenticar, None, credencial, nombre=nombre, rol=rol
                )
            sesiones.append(sesion)
    finally:
        if driver is not None:
            with contextlib.suppress(Exception):
                await asyncio.to_thread(driver.quit)

    if sum(1 for s in sesiones if s.autenticada) == 0:
        return []

    comparador = ComparadorDeRoles(scope, policy, sesiones)
    urls = crawl.urls[: policy.crawl_max_pages]
    comparaciones = await comparador.comparar(urls)

    # Lo que la aplicación publica por su cuenta no es un fallo de acceso.
    publicas = [c.url for c in comparaciones]
    anonimas = [c.url for c in comparaciones
                if (r := c.respuestas.get("anónima")) is not None and r.correcta]

    hallazgos = comparador.evaluar(comparaciones, publicas=publicas)
    hallazgos += await comparador.buscar_idor(urls, anonimamente_legibles=anonimas)
    objetivo = next((e.raw for e in scope.entries if e.kind == "url"), "")
    for sesion in sesiones:
        hallazgos += comprobar_fijacion_de_sesion(sesion, objetivo)
    return hallazgos



async def run_code_scan(
    ruta: str | Path,
    *,
    profile: str | Profile = Profile.SAFE_ACTIVE,
    project_name: str = "default",
    db=None,
    only: Sequence[str] | None = None,
    on_progress: ProgressFn | None = None,
) -> ScanOutcome:
    """Analiza un repositorio: código, secretos y dependencias.

    No toca la red en ningún momento —ni siquiera para consultar vulnerabilidades,
    porque la base de trivy se descarga en el bootstrap y se consulta en local—,
    así que este escaneo no tiene alcance que confinar. Se registra sin `scope`
    en lugar de inventarse uno: decir que el objetivo fue 127.0.0.1 cuando no se
    abrió un socket sería falsear el registro de auditoría.
    """
    raiz = Path(ruta).expanduser().resolve()
    if not raiz.exists():
        raise FileNotFoundError(f"no existe la ruta a analizar: {raiz}")
    policy = get_policy(profile)

    init_db(db)
    with session_scope(db) as session:
        project = _get_or_create_project(session, project_name)
        scan = Scan(
            project_id=project.id,
            kind=ScanKind.CODE,
            profile=str(policy.profile),
            status=RunStatus.RUNNING,
            started_at=_utcnow(),
            scope={"ruta": str(raiz), "tipo": "código", "red": "no se usa"},
        )
        session.add(scan)
        session.flush()
        scan_id, project_id = scan.id, project.id
        session.add(AuditEvent(scan_id=scan_id, action="scan.start",
                               detail={"ruta": str(raiz), "kind": "code"}))

    workdir = paths.runs_dir() / f"scan-{scan_id:06d}"
    workdir.mkdir(parents=True, exist_ok=True)
    outcome = ScanOutcome(scan_id=scan_id)

    def progress(fase: str, mensaje: str, pct: float) -> None:
        if on_progress is not None:
            on_progress(fase, mensaje, pct)

    audit: list[tuple[str, dict]] = []
    cobertura_origenes: set[str] = set()
    runner = Runner(workdir=workdir, audit=lambda a, d: audit.append((a, d)))
    context = ScanContext(policy=policy, workdir=workdir, ruta=raiz,
                          project_id=project_id, scan_id=scan_id)

    try:
        adapters = all_adapters()
        wanted = [n for n, cls in adapters.items()
                  if cls.kind == "code" and (only is None or n in only)]
        for indice, nombre in enumerate(wanted):
            adapter = adapters[nombre]()
            progress(nombre, f"ejecutando {nombre}", indice / max(len(wanted), 1) * 0.9)
            with _task(db, scan_id, nombre, nombre) as task:
                if not adapter.available():
                    task["status"] = RunStatus.SKIPPED
                    task["detail"] = "no instalada"
                    continue
                try:
                    producidos = await adapter.execute(context, runner)
                except ToolMissing as exc:
                    task["status"] = RunStatus.SKIPPED
                    task["detail"] = str(exc)
                    continue
                outcome.findings.extend(producidos)
                cobertura_origenes.add(nombre)
                task["detail"] = f"{len(producidos)} hallazgos"

        progress("persist", "guardando resultados", 0.95)
        _persist(db, scan_id, project_id, outcome, None, audit,
                 set(), cobertura_origenes)
        progress("done", "análisis terminado", 1.0)
        return outcome

    except Exception as exc:
        with session_scope(db) as session:
            scan = session.get(Scan, scan_id)
            scan.status = RunStatus.FAILED
            scan.error = f"{type(exc).__name__}: {exc}"
            scan.finished_at = _utcnow()
        raise
