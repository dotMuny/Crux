"""`crux scan`: lanzar un escaneo desde la línea de órdenes."""

from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from ..core import paths
from ..core.policy import Profile
from ..core.report import render_html, render_pdf
from ..core.report.html import LEVEL_LABEL, ORDER, build_context
from ..core.scan import run_code_scan, run_web_scan
from ..core.scope import ScopeError
from ..modules.auth import AutenticacionFallida

_SEV_STYLE = {
    "critical": "bold red", "high": "dark_orange", "medium": "yellow",
    "low": "blue", "info": "dim",
}


@click.group("scan")
def scan() -> None:
    """Lanzar escaneos."""


@scan.command("web")
@click.argument("targets", nargs=-1, required=True)
@click.option("--profile", type=click.Choice([p.value for p in Profile]),
              default=Profile.SAFE_ACTIVE.value, show_default=True,
              help="Cuánto se permite tocar el objetivo.")
@click.option("--project", default="default", show_default=True,
              help="Agrupa escaneos y conserva el triaje entre ejecuciones.")
@click.option("--allow-public", is_flag=True,
              help="Permite objetivos que resuelvan a IP pública. Queda auditado.")
@click.option("--extra-host", "extra_hosts", multiple=True,
              help="Host adicional permitido aunque no sea objetivo directo.")
@click.option("--only", multiple=True,
              help="Ejecutar solo estos adaptadores (repetible).")
@click.option("--login-url", help="URL de acceso: la de la aplicación, aunque el "
                                   "formulario esté en un Keycloak o un ADFS.")
@click.option("--user", "usuario", help="Usuario con el que entra el escaneo.")
@click.option("--password", "clave", help="Contraseña de ese usuario.")
@click.option("--idp", "proveedor", help="Proveedor de identidad (Keycloak, ADFS…). Solo "
                                        "hace falta si la aplicación salta a él con "
                                        "JavaScript; una redirección se descubre sola.")
@click.option("--selector-usuario", help="Selector CSS del campo de usuario, si la heurística falla.")
@click.option("--selector-clave", help="Selector CSS del campo de contraseña.")
@click.option("--header", "cabeceras", multiple=True, metavar="'K: V'",
              help="Cabecera fija, p. ej. 'Authorization: Bearer …'. Repetible.")
@click.option("--role", "roles_crudos", multiple=True, metavar="NOMBRE:ROL:USUARIO:CLAVE",
              help="Rol a comparar para el control de acceso. Hacen falta dos "
                   "para que la comparación diga algo. Repetible.")
@click.option("--sandbox", is_flag=True,
              help="Ejecuta el escaneo dentro de un namespace de red que solo "
                   "alcanza el alcance declarado. Convierte el egress cero de "
                   "comprobación en imposición. Necesita privilegios.")
@click.option("--report", "report_path", type=click.Path(path_type=Path),
              help="Escribe el informe HTML en esta ruta (y el PDF junto a él).")
@click.option("--no-pdf", is_flag=True, help="No generar el PDF.")
def scan_web(targets, profile, project, allow_public, extra_hosts, only,
             login_url, usuario, clave, proveedor, selector_usuario, selector_clave,
             cabeceras, roles_crudos, sandbox, report_path, no_pdf) -> None:
    """Escanea una o varias aplicaciones web internas.

    El alcance se confina a redes internas y se congela al arrancar: un objetivo
    que resuelva a una IP pública se rechaza salvo --allow-public.
    """
    console = Console()
    started = datetime.now(timezone.utc)
    clock = time.monotonic()

    # El sandbox envuelve el PROCESO ENTERO, no cada herramienta. Nuestros
    # propios módulos —probador, crawler, authz— hacen peticiones desde este
    # mismo proceso, así que envolver solo el argv de las herramientas externas
    # dejaría fuera justo la mitad del tráfico.
    credenciales = _credenciales(login_url, usuario, clave, proveedor,
                                 selector_usuario, selector_clave, cabeceras)
    try:
        roles = _roles(roles_crudos, login_url, proveedor)
    except ValueError as exc:
        console.print(f"[red]✗[/red] {exc}")
        raise SystemExit(2)

    if sandbox and not os.environ.get("CRUX_EN_SANDBOX"):
        _relanzar_en_sandbox(console, targets, allow_public, extra_hosts,
                             credenciales, roles)
        return
    if len(roles) == 1:
        # Un solo rol no permite comparar nada: mejor decirlo que ejecutar una
        # fase que no puede producir resultado.
        console.print(
            "[yellow]–[/yellow] con un solo --role no hay comparación posible; "
            "añade otro para detectar fallos de autorización."
        )

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold]{task.fields[phase]}[/bold]"),
        BarColumn(bar_width=28, complete_style="cyan", finished_style="cyan"),
        TextColumn("{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        bar = progress.add_task("arrancando", total=1.0, phase="inicio")

        def on_progress(phase: str, message: str, pct: float) -> None:
            progress.update(bar, completed=pct, description=message, phase=phase)

        try:
            outcome = asyncio.run(
                run_web_scan(
                    targets,
                    profile=profile,
                    project_name=project,
                    allow_public=allow_public,
                    extra_hosts=extra_hosts,
                    only=only or None,
                    credenciales=credenciales,
                    roles=roles,
                    on_progress=on_progress,
                )
            )
        except ScopeError as exc:
            console.print(Panel.fit(f"[bold red]Alcance rechazado[/bold red]\n{exc}",
                                    border_style="red"))
            raise SystemExit(2)
        except AutenticacionFallida as exc:
            # No se sigue como anónimo: el informe parecería completo sin serlo.
            console.print(Panel.fit(f"[bold red]No se pudo entrar[/bold red]\n{exc}",
                                    border_style="red"))
            raise SystemExit(5)

    duration = _fmt_duration(time.monotonic() - clock)
    counts = outcome.by_severity
    alive = sum(1 for p in outcome.probes if p.alive)

    table = Table("", "severidad", "comprobación", "objetivo", box=None, pad_edge=False)
    for finding in sorted(outcome.findings, key=lambda f: -int(f.severity)):
        style = _SEV_STYLE[finding.severity.label]
        table.add_row(
            f"[{style}]█[/{style}]",
            f"[{style}]{LEVEL_LABEL[finding.severity.label]}[/{style}]",
            f"{finding.source}:{finding.check_id}",
            _trim(finding.target, 56),
        )
    console.print(table)

    summary = " · ".join(
        f"[{_SEV_STYLE[level]}]{counts.get(level, 0)} {LEVEL_LABEL[level]}[/{_SEV_STYLE[level]}]"
        for level in ORDER if counts.get(level)
    ) or "sin hallazgos"
    console.print(
        Panel.fit(
            f"{summary}\n"
            f"[dim]{alive} URLs vivas de {len(outcome.probes)} · {duration} · "
            f"{outcome.new} nuevos, {outcome.fixed} corregidos[/dim]\n"
            f"[cyan]0 conexiones fuera del alcance[/cyan]",
            title=f"escaneo {outcome.scan_id}",
            border_style="cyan",
        )
    )

    if report_path:
        from ..core.scope import Scope

        scope = Scope.build(targets, allow_public=allow_public, extra_hosts=extra_hosts)
        context = build_context(
            outcome.findings,
            project=project,
            scan_id=outcome.scan_id,
            profile=profile,
            scope=scope,
            started=started,
            duration=duration,
            alive=alive,
            probed=len(outcome.probes),
            new=outcome.new,
            fixed=outcome.fixed,
            tools=sorted({f.source for f in outcome.findings}),
        )
        html = render_html(context, report_path)
        console.print(f"[green]✓[/green] informe HTML: {report_path}")
        if not no_pdf:
            pdf_path = report_path.with_suffix(".pdf")
            try:
                render_pdf(html, pdf_path)
                console.print(f"[green]✓[/green] informe PDF:  {pdf_path}")
            except Exception as exc:
                console.print(f"[yellow]–[/yellow] PDF no generado: {exc}")


def _fmt_duration(seconds: float) -> str:
    minutes, secs = divmod(int(seconds), 60)
    return f"{minutes} min {secs:02d} s" if minutes else f"{secs} s"


def _trim(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def _credenciales(login_url, usuario, clave, proveedor, selector_usuario,
                  selector_clave, cabeceras):
    """Construye las credenciales del escaneo, o None si no se dieron."""
    from ..modules.auth import Credenciales

    cabeceras_dict: dict[str, str] = {}
    for cruda in cabeceras:
        nombre, _, valor = cruda.partition(":")
        if nombre.strip():
            cabeceras_dict[nombre.strip()] = valor.strip()
    if not (login_url or cabeceras_dict):
        return None
    return Credenciales(
        url_login=login_url, usuario=usuario, clave=clave,
        selector_usuario=selector_usuario, selector_clave=selector_clave,
        cabeceras=cabeceras_dict, proveedor_identidad=proveedor,
    )


def _roles(roles_crudos, login_url, proveedor=None):
    """Interpreta NOMBRE:ROL:USUARIO:CLAVE. La contraseña puede llevar «:»."""
    from ..modules.auth import Credenciales

    roles = []
    for crudo in roles_crudos:
        partes = crudo.split(":", 3)
        if len(partes) != 4:
            raise ValueError(
                f"--role mal formado: {crudo!r}. Se espera NOMBRE:ROL:USUARIO:CLAVE"
            )
        nombre, rol, usuario, clave = partes
        if not login_url:
            raise ValueError("--role necesita también --login-url")
        roles.append((nombre, rol,
                      Credenciales(url_login=login_url, usuario=usuario, clave=clave,
                                   proveedor_identidad=proveedor)))
    return roles


@scan.command("code")
@click.argument("ruta", type=click.Path(exists=True, path_type=Path))
@click.option("--project", default="default", show_default=True,
              help="Agrupa escaneos y conserva el triaje entre ejecuciones.")
@click.option("--only", multiple=True, help="Ejecutar solo estos adaptadores.")
@click.option("--report", "report_path", type=click.Path(path_type=Path),
              help="Escribe el informe HTML en esta ruta (y el PDF junto a él).")
@click.option("--no-pdf", is_flag=True, help="No generar el PDF.")
def scan_code(ruta, project, only, report_path, no_pdf) -> None:
    """Analiza un repositorio: código, secretos y dependencias.

    No usa la red en ningún momento. La base de vulnerabilidades se descarga en
    la instalación y se consulta en local, así que el análisis funciona igual
    en una máquina sin salida.
    """
    console = Console()
    started = datetime.now(timezone.utc)
    clock = time.monotonic()

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold]{task.fields[phase]}[/bold]"),
        BarColumn(bar_width=28, complete_style="cyan", finished_style="cyan"),
        TextColumn("{task.description}"),
        console=console, transient=True,
    ) as progress:
        bar = progress.add_task("arrancando", total=1.0, phase="inicio")
        outcome = asyncio.run(run_code_scan(
            ruta, project_name=project, only=only or None,
            on_progress=lambda f, m, p: progress.update(
                bar, completed=p, description=m, phase=f),
        ))

    duration = _fmt_duration(time.monotonic() - clock)
    counts = outcome.by_severity

    table = Table("", "severidad", "comprobación", "dónde", box=None, pad_edge=False)
    for finding in sorted(outcome.findings, key=lambda f: -int(f.severity))[:40]:
        style = _SEV_STYLE[finding.severity.label]
        table.add_row(
            f"[{style}]█[/{style}]",
            f"[{style}]{LEVEL_LABEL[finding.severity.label]}[/{style}]",
            f"{finding.source}:{_trim(finding.check_id, 30)}",
            _trim(finding.target, 46),
        )
    console.print(table)
    if len(outcome.findings) > 40:
        console.print(f"[dim]… y {len(outcome.findings) - 40} más. "
                      f"Están todos en el informe y en la interfaz.[/dim]")

    resumen = " · ".join(
        f"[{_SEV_STYLE[n]}]{counts.get(n, 0)} {LEVEL_LABEL[n]}[/{_SEV_STYLE[n]}]"
        for n in ORDER if counts.get(n)
    ) or "sin hallazgos"
    console.print(Panel.fit(
        f"{resumen}\n"
        f"[dim]{duration} · {outcome.new} nuevos, {outcome.fixed} corregidos[/dim]\n"
        f"[cyan]sin usar la red[/cyan]",
        title=f"análisis de código {outcome.scan_id}", border_style="cyan",
    ))

    if report_path:
        from ..core.scope import Scope

        contexto = build_context(
            outcome.findings, project=project, scan_id=outcome.scan_id,
            profile="code", scope=Scope(entries=[]), started=started,
            duration=duration, alive=0, probed=0,
            new=outcome.new, fixed=outcome.fixed,
            kind="code", ruta=str(ruta),
            tools=sorted({f.source for f in outcome.findings}),
        )
        html = render_html(contexto, report_path)
        console.print(f"[green]✓[/green] informe HTML: {report_path}")
        if not no_pdf:
            pdf = report_path.with_suffix(".pdf")
            try:
                render_pdf(html, pdf)
                console.print(f"[green]✓[/green] informe PDF:  {pdf}")
            except Exception as exc:
                console.print(f"[yellow]–[/yellow] PDF no generado: {exc}")


def _relanzar_en_sandbox(console, targets, allow_public, extra_hosts,
                         credenciales=None, roles=()) -> None:
    """Monta el aislamiento y vuelve a lanzar este mismo comando dentro.

    Re-ejecutar el proceso completo es lo que de verdad contiene el escaneo:
    una herramienta externa envuelta se quedaría dentro, pero las peticiones
    que hace Crux por su cuenta saldrían por la red del equipo.
    """
    import subprocess
    import sys

    from ..core.sandbox import SandboxDeRed, SandboxNoDisponible, comprobar_disponible
    from ..core.scope import ScopeError
    from ..modules.auth import construir_alcance

    disponible, motivo = comprobar_disponible()
    if not disponible:
        console.print(Panel.fit(
            f"[bold red]No se puede aislar la red[/bold red]\n{motivo}\n\n"
            "[dim]Sin --sandbox el escaneo sigue funcionando: el egress se\n"
            "comprueba igual, pero se comprueba en vez de imponerse.[/dim]",
            border_style="red"))
        raise SystemExit(3)

    try:
        # Con los proveedores de identidad: si no, el namespace no les da ruta
        # y el login no tiene por dónde salir.
        scope = construir_alcance(targets, allow_public=allow_public,
                                  extra_hosts=list(extra_hosts),
                                  credenciales=credenciales, roles=roles)
    except ScopeError as exc:
        console.print(f"[red]✗[/red] {exc}")
        raise SystemExit(2)

    nombre = f"crux{os.getpid()}"
    try:
        with SandboxDeRed(nombre=nombre, scope=scope) as caja:
            en_loopback = caja.objetivos_en_loopback()
            if en_loopback:
                # Decirlo antes de escanear: dentro del namespace, 127.0.0.1 es
                # otro loopback, y quien no lo sepa leería el resultado vacío
                # como que la aplicación no responde.
                console.print(Panel.fit(
                    "[bold yellow]Objetivos inalcanzables dentro del aislamiento"
                    f"[/bold yellow]\n{', '.join(en_loopback)}\n\n"
                    "Dentro de un namespace de red, 127.0.0.1 es el loopback del\n"
                    "propio namespace. Escanea esos objetivos sin --sandbox, o\n"
                    "haz que la aplicación escuche en una dirección encaminable.",
                    border_style="yellow"))
                raise SystemExit(4)

            console.print(Panel.fit(
                "[bold]Red aislada[/bold]\n"
                + "\n".join(f"  permitido  {d}" for d in caja.permitidas)
                + "\n  [dim]todo lo demás no tiene ruta[/dim]",
                border_style="cyan"))

            # La marca va con `env` dentro de la orden, no en el entorno del
            # subproceso: sudo limpia el entorno por defecto, así que pasarla
            # por fuera no llegaba y el hijo intentaba montar otro sandbox.
            orden = caja.envolver([
                "env", "CRUX_EN_SANDBOX=1",
                f"HOME={os.path.expanduser('~')}",
                f"XDG_DATA_HOME={os.environ.get('XDG_DATA_HOME', os.path.expanduser('~/.local/share'))}",
                sys.executable, "-m", "crux.cli.main", *sys.argv[1:],
            ])
            resultado = subprocess.run(orden)
            raise SystemExit(resultado.returncode)
    except SandboxNoDisponible as exc:
        console.print(f"[red]✗[/red] {exc}")
        raise SystemExit(3)
