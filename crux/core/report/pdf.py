"""Informe PDF mediante WeasyPrint. Sin red: ni fuentes ni hojas remotas.

WeasyPrint aplica la rama `@media print` de `tokens.css`, que cambia a la
superficie clara manteniendo la misma identidad que la interfaz.
"""

from __future__ import annotations

from pathlib import Path


def render_pdf(html: str, destination: Path, *, base_url: str | None = None) -> Path:
    from weasyprint import HTML

    destination.parent.mkdir(parents=True, exist_ok=True)
    # base_url a None impide que WeasyPrint resuelva referencias externas: todo
    # lo que necesita el informe ya está en línea.
    HTML(string=html, base_url=base_url).write_pdf(str(destination))
    return destination
