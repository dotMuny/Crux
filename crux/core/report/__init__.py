"""Generación de informes. Todo se resuelve en local: ni CDN ni fuentes remotas."""

from .html import render_html
from .pdf import render_pdf

__all__ = ["render_html", "render_pdf"]
