"""Lo que la suite da por supuesto, comprobado en voz alta.

Existe por un fallo de la suite, no del producto. Con la aplicación de pruebas
parada, los tests que lanzan escaneos reales no encontraban nada y pasaban en
verde: la comprobación de conservación cuadraba sola —0 producidos, 0
guardados— y las de triaje y diferencias comparaban dos escaneos vacíos entre
sí. Un test que no puede fallar no prueba nada, y éstos son lo único que dice
que los detectores siguen vivos después de cada cambio.

Los tres que sí fallaban lo hacían por casualidad, porque afirmaban un número
concreto de hallazgos. El resto callaba.

Ahora quien necesita el objetivo lo declara con la marca `necesita_objetivo`,
y si no responde la suite se detiene diciendo exactamente qué levantar.
"""

from __future__ import annotations

import socket

import pytest

HOST, PUERTO = "127.0.0.1", 8999
OBJETIVO = f"http://{HOST}:{PUERTO}/"

COMO_LEVANTARLO = (
    f"La aplicación de pruebas no responde en {OBJETIVO}\n\n"
    "    Estos tests lanzan escaneos de verdad contra ella. Sin objetivo no\n"
    "    encuentran nada, y un escaneo vacío cuadra con cualquier invariante:\n"
    "    pasarían en verde sin haber comprobado un solo detector.\n\n"
    "    Levántala en otra terminal:\n\n"
    "        .venv/bin/python -m tests.fixtures.vulnapp\n\n"
    "    O sáltatelos:  pytest -m 'not necesita_objetivo'"
)


def responde(host: str = HOST, puerto: int = PUERTO, espera: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, puerto), timeout=espera):
            return True
    except OSError:
        return False


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "necesita_objetivo: lanza peticiones reales contra la aplicación de "
        "pruebas; la suite se detiene si no está levantada",
    )


@pytest.fixture(scope="session")
def objetivo_vivo() -> str:
    """El objetivo, comprobado una vez por sesión.

    `pytest.fail` y no `skip` a propósito: saltar es lo que convierte una
    comprobación ausente en un verde. Que se vea en rojo.
    """
    if not responde():
        pytest.fail(COMO_LEVANTARLO, pytrace=False)
    return OBJETIVO


@pytest.fixture(autouse=True)
def _exige_objetivo(request):
    if request.node.get_closest_marker("necesita_objetivo"):
        request.getfixturevalue("objetivo_vivo")
