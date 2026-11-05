"""La interfaz no sirve nada que esté fuera de su propio `dist`.

Este fichero existe por un fallo encontrado auto-analizando Crux con Crux:

    GET http://127.0.0.1:8777///////../../../etc/passwd  →  200, /etc/passwd

La ruta comodín que devuelve la SPA hacía `DIST / ruta` y preguntaba
`is_file()`. Con `ruta = "../../../etc/passwd"` eso apunta fuera del directorio
y el fichero existe, así que respondía que sí. Una herramienta de auditoría
sirviendo ficheros arbitrarios del equipo del analista no es una ironía: es el
mismo fallo que buscamos en los demás.

La defensa que se prueba aquí no filtra patrones —`..`, `%2e%2e`, `....//` y
compañía son una lista que siempre se queda corta—, sino que resuelve la ruta
y comprueba que el resultado cae dentro del directorio permitido.
"""

from __future__ import annotations

import asyncio

import pytest

from crux.web import app as modulo


# Rutas que un atacante probaría. Todas tienen que acabar en el index, nunca
# en un fichero del sistema.
TRAVESIAS = [
    "../../../etc/passwd",
    "///////../../../etc/passwd",          # la que apareció en el escaneo
    "..%2f..%2f..%2fetc%2fpasswd",         # codificada una vez
    "....//....//....//etc/passwd",        # por si alguien "limpiara" los «..»
    "assets/../../../../etc/passwd",       # saliendo desde un directorio real
    "/etc/passwd",
    "../pyproject.toml",                   # un fichero del propio proyecto
    "../../.local/share/crux/crux.db",     # la base de datos del analista
]


def pedir_crudo(app, ruta: str) -> tuple[int, bytes]:
    """Una petición con la ruta EXACTA, sin que nadie la normalice por el camino.

    Hace falta hablar con la aplicación ASGI a pelo: httpx rechaza una ruta que
    empiece por `//` y, como curl sin `--path-as-is`, colapsa los `..` antes de
    enviar. Un cliente educado no puede reproducir el vector tal y como llegó,
    y es justo el vector el que hay que probar.
    """
    mensajes: list[dict] = []

    async def recibir():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def enviar(mensaje):
        mensajes.append(mensaje)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0", "spec_version": "2.3"},
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": ruta,
        "raw_path": ruta.encode(),
        "root_path": "",
        "query_string": b"",
        "headers": [(b"host", b"testserver")],
        "client": ("127.0.0.1", 50000),
        "server": ("127.0.0.1", 8777),
    }
    asyncio.run(app(scope, recibir, enviar))
    estado = next(m["status"] for m in mensajes if m["type"] == "http.response.start")
    cuerpo = b"".join(
        m.get("body", b"") for m in mensajes if m["type"] == "http.response.body"
    )
    return estado, cuerpo


@pytest.fixture(scope="module")
def aplicacion():
    if not modulo.DIST.is_dir():
        pytest.skip("la interfaz no está compilada en este equipo")
    return modulo.create_app()


@pytest.mark.parametrize("ruta", TRAVESIAS)
def test_no_se_escapa_del_dist(aplicacion, ruta):
    camino = ruta if ruta.startswith("/") else "/" + ruta
    estado, cuerpo = pedir_crudo(aplicacion, camino)

    # Lo único que no se negocia: el contenido del fichero no sale.
    assert b"root:x:0:0" not in cuerpo, f"{ruta} devolvió /etc/passwd"

    # Hay dos respuestas correctas según quién atienda la ruta. Lo que cuelga
    # de /assets lo sirve StaticFiles, que ya comprueba la contención y corta
    # con un 404; el resto cae en la ruta comodín, que devuelve el index.
    assert estado in (200, 404), f"{ruta} respondió {estado}"
    if estado == 200:
        bajo = cuerpo.lower()
        assert b"<!doctype html" in bajo or b"<html" in bajo, (
            f"{ruta} devolvió algo que no es el index"
        )


@pytest.mark.parametrize("ruta", TRAVESIAS)
def test_la_comprobacion_rechaza_la_ruta(ruta):
    """Lo mismo un escalón más abajo, sin pasar por HTTP.

    Importa tenerlo aquí: si mañana alguien cambia el enrutado, la función que
    decide qué se puede servir sigue cubierta por su cuenta.
    """
    assert modulo.fichero_servible(ruta) is None


def test_lo_que_sí_está_dentro_se_sirve():
    """El control negativo. Sin esto, una función que devuelva siempre None
    pasaría todo lo de arriba sin proteger nada."""
    if not modulo.DIST.is_dir():
        pytest.skip("la interfaz no está compilada en este equipo")
    assert modulo.fichero_servible("index.html") is not None


def test_un_enlace_que_apunta_fuera_tampoco_vale(tmp_path, monkeypatch):
    """Resolver enlaces simbólicos es parte de la comprobación.

    Un `dist` con un enlace hacia fuera —por un empaquetado descuidado, por
    ejemplo— volvería a abrir el agujero si solo se mirase el texto de la ruta.
    """
    dist = tmp_path / "dist"
    dist.mkdir()
    (dist / "index.html").write_text("<!doctype html><title>x</title>")
    secreto = tmp_path / "secreto.txt"
    secreto.write_text("root:x:0:0:")
    (dist / "atajo.txt").symlink_to(secreto)

    monkeypatch.setattr(modulo, "DIST", dist)
    assert modulo.fichero_servible("atajo.txt") is None
    assert modulo.fichero_servible("index.html") is not None
