"""La cola de trabajos y su transmisión de eventos."""

from __future__ import annotations

import asyncio
import json

import pytest

from crux.core.queue import ColaDeTrabajos

OBJETIVO = "http://127.0.0.1:8999/"


@pytest.fixture
def cola(tmp_path):
    return ColaDeTrabajos(db=tmp_path / "cola.db")


def test_un_trabajo_completa_y_resume(cola):
    async def run():
        t = cola.enviar([OBJETIVO], profile="passive", project="p", only=[],
                        con_crawler=False)
        async for _ in cola.seguir(t.id):
            pass
        return t

    t = asyncio.run(run())
    assert t.estado == "hecho"
    assert t.scan_id is not None
    assert t.resumen["hallazgos"] > 0


def test_el_historial_se_reenvia_en_el_mismo_formato(cola):
    """Quien se conecta a mitad de escaneo recibe lo ya ocurrido.

    Devolver el objeto crudo en el historial y un diccionario en el directo
    rompía la transmisión SSE justo en ese caso, que es el que importa: abrir
    la página con el escaneo ya empezado.
    """
    async def run():
        t = cola.enviar([OBJETIVO], profile="passive", project="p", only=[],
                        con_crawler=False)
        await t._tarea                      # deja que termine y acumule historial
        return [ev async for ev in cola.seguir(t.id)]

    eventos = asyncio.run(run())
    assert eventos, "debería reenviarse el historial"
    for ev in eventos:
        assert isinstance(ev, dict), "los eventos deben ser diccionarios serializables"
        assert {"ts", "fase", "mensaje", "progreso"} <= set(ev)
    import json
    json.dumps(eventos)                     # debe poder serializarse


def test_el_alcance_rechazado_tiene_su_propio_estado(cola):
    """Un objetivo público no es un error del programa: es el control de
    seguridad funcionando, y la interfaz debe poder distinguirlo."""
    async def run():
        t = cola.enviar(["https://example.com"], profile="passive", project="p")
        async for _ in cola.seguir(t.id):
            pass
        return t

    t = asyncio.run(run())
    assert t.estado == "fallido"
    assert "pública" in (t.error or "")
    assert any(ev.fase == "alcance-rechazado" for ev in t.eventos)


def test_el_progreso_avanza_de_cero_a_uno(cola):
    async def run():
        t = cola.enviar([OBJETIVO], profile="passive", project="p", only=[],
                        con_crawler=False)
        return [ev async for ev in cola.seguir(t.id)]

    progresos = [ev["progreso"] for ev in asyncio.run(run())]
    assert progresos[0] == 0.0 and progresos[-1] == 1.0
    assert progresos == sorted(progresos), "el progreso no debe retroceder"


def test_la_cola_lanza_analisis_de_codigo(cola, tmp_path):
    """El pilar de código tiene que poder dispararse desde la interfaz.

    Antes la cola solo sabía llamar a run_web_scan, así que la mitad del
    producto solo existía por línea de órdenes.
    """
    async def run():
        t = cola.enviar(["tests/fixtures/vulncode"], tipo="code", project="p",
                        only=["gitleaks"])
        async for _ in cola.seguir(t.id):
            pass
        return t

    t = asyncio.run(run())
    assert t.tipo == "code"
    assert t.estado == "hecho"
    assert t.resumen["hallazgos"] > 0


def test_una_ruta_inexistente_se_explica(cola):
    """Es un error del operador, no del programa, y merece decir qué corregir."""
    async def run():
        t = cola.enviar(["/no/existe/de/ninguna/manera"], tipo="code", project="p")
        async for _ in cola.seguir(t.id):
            pass
        return t

    t = asyncio.run(run())
    assert t.estado == "fallido"
    assert "no existe la ruta" in (t.error or "")
    assert any(ev.fase == "ruta-invalida" for ev in t.eventos)


def test_un_tipo_desconocido_se_rechaza(cola):
    with pytest.raises(ValueError, match="tipo de escaneo desconocido"):
        cola.enviar(["x"], tipo="otra-cosa")


def test_el_aislamiento_no_aplica_al_codigo(cola):
    """El análisis de código no usa la red: no hay nada que confinar, y
    aceptar la casilla en silencio haría creer que sí se confinó algo."""
    with pytest.raises(ValueError, match="solo aplica a los escaneos web"):
        cola.enviar(["tests/fixtures/vulncode"], tipo="code", sandbox=True)


def test_aislar_un_objetivo_en_loopback_falla_en_vez_de_escanear(cola):
    """Dentro de un namespace de red, 127.0.0.1 es otro loopback.

    Lo que se comprueba aquí no es el aislamiento —eso necesita privilegios y
    vive en test_sandbox— sino que no se degrada: pedir aislamiento y no poder
    dárselo tiene que fallar, nunca escanear igual pero sin aislar.
    """
    async def run():
        t = cola.enviar([OBJETIVO], profile="passive", project="p", sandbox=True)
        async for _ in cola.seguir(t.id):
            pass
        return t

    t = asyncio.run(run())
    assert t.estado == "fallido"
    assert any(ev.fase == "aislamiento-imposible" for ev in t.eventos)
    assert t.scan_id is None, "no debe haber quedado ningún escaneo a medias"


def test_la_sesion_se_describe_sin_la_credencial(cola):
    """`como_dict` va por la API. Una contraseña que sale por la API ya no es
    una contraseña, así que del acceso solo se cuenta el modo y los nombres."""
    import json

    from crux.modules.auth import Credenciales

    ana = Credenciales(url_login=OBJETIVO + "login", usuario="ana",
                       clave="Primavera2026")
    luis = Credenciales(url_login=OBJETIVO + "login", usuario="luis",
                        clave="luis123")
    async def run():
        t = cola.enviar([OBJETIVO], profile="passive", project="p", only=[],
                        con_crawler=False, credenciales=ana,
                        roles=[("ana", "admin", ana), ("luis", "user", luis)])
        t._tarea.cancel()
        return t.como_dict()

    datos = asyncio.run(run())
    assert datos["autenticacion"] == "formulario"
    assert datos["roles"] == ["ana", "luis"]
    crudo = json.dumps(datos)
    for secreto in ("Primavera2026", "luis123"):
        assert secreto not in crudo


def test_las_credenciales_cruzan_el_limite_de_proceso_intactas():
    """Con aislamiento el escaneo corre en otro proceso, y las credenciales
    tienen que llegar enteras: si se perdiera un selector o la señal de éxito,
    el escaneo aislado se quedaría sin sesión sin dar un error."""
    from crux.core.worker import (
        deserializar_credenciales, deserializar_roles,
        serializar_credenciales, serializar_roles,
    )
    from crux.modules.auth import Credenciales

    ana = Credenciales(
        url_login="http://10.20.4.9/login", usuario="ana", clave="s3cr3t",
        selector_usuario="#user", selector_clave="#pwd",
        cabeceras={"X-Tenant": "corp"}, cookies={"SESSIONID": "abc"},
        senal_de_exito="Salir",
    )
    vuelta = deserializar_credenciales(serializar_credenciales(ana))
    assert vuelta == ana
    assert serializar_credenciales(None) is None
    assert deserializar_credenciales(None) is None

    roles = [("ana", "admin", ana)]
    assert deserializar_roles(serializar_roles(roles)) == roles


def test_lo_que_viaja_al_proceso_aislado_es_serializable():
    """El trabajo cruza por la entrada estándar como JSON. Un campo que no se
    pueda serializar rompería el escaneo aislado y solo ése."""
    from crux.core.worker import serializar_credenciales, serializar_roles
    from crux.modules.auth import Credenciales

    cred = Credenciales(url_login="http://10.20.4.9/login", usuario="ana", clave="x")
    json.dumps({"credenciales": serializar_credenciales(cred),
                "roles": serializar_roles([("ana", "admin", cred)])})
