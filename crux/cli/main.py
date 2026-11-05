"""Punto de entrada del CLI."""

from __future__ import annotations

import click

from .cmd_doctor import doctor
from .cmd_diff import diff
from .cmd_scan import scan
from .cmd_web import web

VERSION = "0.1.0"


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(VERSION, prog_name="crux")
def cli() -> None:
    """Crux — auditoría de aplicaciones web internas, sin salida a internet.

    En ejecución, Crux no contacta con ningún servicio de terceros: el alcance
    se confina a redes internas y cada herramienta se lanza con su telemetría
    desactivada. Empieza por `crux doctor`.
    """


cli.add_command(doctor)
cli.add_command(diff)
cli.add_command(scan)
cli.add_command(web)


if __name__ == "__main__":
    cli()
