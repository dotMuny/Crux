"""`crux diff`: qué ha cambiado entre dos escaneos."""

from __future__ import annotations

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..core.diff import comparar

_ESTILO = {"critical": "bold red", "high": "dark_orange", "medium": "yellow",
           "low": "blue", "info": "dim"}
_ES = {"critical": "crítica", "high": "alta", "medium": "media",
       "low": "baja", "info": "info"}


@click.command("diff")
@click.argument("antes", type=int)
@click.argument("ahora", type=int)
@click.option("--solo-regresiones", is_flag=True,
              help="Muestra únicamente lo nuevo y lo que ha empeorado.")
def diff(antes: int, ahora: int, solo_regresiones: bool) -> None:
    """Compara dos escaneos del mismo proyecto.

    Distingue lo corregido de lo que simplemente no se volvió a comprobar: si
    un escaneo usó otro perfil o le faltó una herramienta, los hallazgos que
    dejan de aparecer no están arreglados, están sin mirar.
    """
    console = Console()
    try:
        d = comparar(antes, ahora)
    except ValueError as exc:
        console.print(f"[red]✗[/red] {exc}")
        raise SystemExit(2)

    def tabla(titulo: str, filas: list[dict], color: str) -> None:
        if not filas:
            return
        t = Table("", "severidad", "comprobación", "dónde", box=None,
                  title=f"[{color}]{titulo} · {len(filas)}[/{color}]",
                  title_justify="left", pad_edge=False)
        for f in filas[:25]:
            estilo = _ESTILO[f["severity"]]
            t.add_row(f"[{estilo}]█[/{estilo}]",
                      f"[{estilo}]{_ES[f['severity']]}[/{estilo}]",
                      f"{f['source']}:{f['check_id'][:28]}",
                      f["target"][:48])
        console.print(t)
        if len(filas) > 25:
            console.print(f"[dim]  … y {len(filas) - 25} más[/dim]")
        console.print()

    tabla("Nuevos", d.nuevos, "red")
    if d.cambios:
        t = Table("", "cambio", "hallazgo", box=None,
                  title="[yellow]Cambios de severidad[/yellow]",
                  title_justify="left", pad_edge=False)
        for c in d.cambios:
            flecha = "↑" if c.empeora else "↓"
            color = "red" if c.empeora else "green"
            t.add_row(f"[{color}]{flecha}[/{color}]",
                      f"{_ES[c.antes.label]} → {_ES[c.ahora.label]}",
                      c.titulo[:52])
        console.print(t)
        console.print()

    if not solo_regresiones:
        tabla("Corregidos", d.corregidos, "green")
        # Esta lista es la que evita cantar victoria: no es lo mismo arreglar
        # algo que dejar de buscarlo.
        if d.sin_comprobar:
            tabla("Ya no aparecen, pero NO se comprobaron", d.sin_comprobar, "yellow")
            console.print(
                "[dim]  Esos hallazgos no se han corregido: el escaneo nuevo no "
                "llegó a buscarlos.\n"
                "  Suele pasar al cambiar de perfil o si faltaba una herramienta.[/dim]\n"
            )

    resumen = d.resumen
    estado = ("[bold red]hay regresiones[/bold red]" if d.hay_regresion
              else "[bold green]sin regresiones[/bold green]")
    console.print(Panel.fit(
        f"{estado}\n"
        f"[red]{resumen['nuevos']} nuevos[/red] · "
        f"[green]{resumen['corregidos']} corregidos[/green] · "
        f"{resumen['persistentes']} siguen · "
        f"[yellow]{resumen['sin_comprobar']} sin comprobar[/yellow]",
        title=f"escaneo {antes} → {ahora}", border_style="cyan",
    ))
    if d.hay_regresion:
        # Código distinto de cero para poder encadenarlo en un trabajo
        # programado: «avísame si algo empeora».
        raise SystemExit(1)
