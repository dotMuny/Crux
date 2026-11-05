"""Objetivo de pruebas deliberadamente vulnerable.

Existe para verificar que Crux detecta lo que dice detectar. Escucha **solo** en
127.0.0.1 y cada vulnerabilidad está plantada a propósito y etiquetada, de modo
que los tests puedan comprobar la lista esperada contra lo que el escaneo
encuentra. No se despliega en ningún sitio: es un fixture de test.
"""

from .app import EXPECTED_FINDINGS, create_app

__all__ = ["EXPECTED_FINDINGS", "create_app"]
