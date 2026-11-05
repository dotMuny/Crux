"""`crux web`: levanta la interfaz local."""

from __future__ import annotations

import click
from rich.console import Console
from rich.panel import Panel

from ..web.app import DIST


@click.command("web")
@click.option("--host", default="127.0.0.1", show_default=True,
              help="Dirección de escucha. Cambiarla expone la interfaz, que no "
                   "tiene autenticación.")
@click.option("--port", default=8777, show_default=True)
@click.option("--reload", is_flag=True, help="Recarga al cambiar el código (desarrollo).")
def web(host: str, port: int, reload: bool) -> None:
    """Arranca la interfaz web en local."""
    import uvicorn

    console = Console()
    if host not in ("127.0.0.1", "localhost", "::1"):
        # No se impide, pero tampoco se deja pasar en silencio: la interfaz no
        # tiene login, y quien la exponga debe hacerlo a sabiendas.
        console.print(
            Panel.fit(
                f"[bold yellow]Vas a escuchar en {host}[/bold yellow]\n"
                "La interfaz [bold]no tiene autenticación[/bold]: cualquiera que "
                "alcance ese puerto\nverá los hallazgos y podrá lanzar escaneos.",
                border_style="yellow",
            )
        )
    if not DIST.is_dir():
        console.print(
            "[yellow]–[/yellow] la interfaz no está compilada; solo responderá la API.\n"
            "    [dim]cd frontend && pnpm install && pnpm build[/dim]"
        )

    console.print(
        Panel.fit(
            f"[bold]Crux[/bold] en [cyan]http://{host}:{port}[/cyan]\n"
            f"[dim]API en /api/docs · Ctrl-C para parar[/dim]",
            border_style="cyan",
        )
    )
    uvicorn.run(
        "crux.web.app:app",
        host=host,
        port=port,
        reload=reload,
        log_level="warning",
        access_log=False,
    )
