"""El informe no ejecuta lo que el objetivo le escriba.

Este fichero existe por un fallo encontrado al rediseñar el informe. La
plantilla se llama `report.html.j2` y el entorno de Jinja decidía si escapar
mirando la extensión: `.j2` no es `.html`, así que el escapado estaba apagado
y nada lo avisaba. El título, la descripción y la evidencia de un hallazgo
salen del objetivo auditado —una cabecera reflejada, un mensaje de error, el
cuerpo de una respuesta—, y todo eso llegaba al informe tal cual.

Lo que eso significa en una auditoría: un objetivo hostil, o simplemente uno
comprometido, escribe `<script>` en una respuesta; Crux lo recoge como
evidencia; el analista abre el informe desde su disco, donde no hay política
de contenido que valga, y el script corre en su navegador. O lo abre el
cliente, que es peor.
"""

from __future__ import annotations

import pytest

from crux.core.report import html as informe

# Lo que un objetivo hostil pondría donde pueda. Cada vector cierra un contexto
# distinto, porque el fallo no es el mismo en un título que dentro de un <pre>.
VECTORES = [
    "<script>alert(document.domain)</script>",
    "<img src=x onerror=alert(1)>",
    "</pre><script>alert(2)</script>",
    "</style><script>alert(3)</script>",
    "\"><svg onload=alert(4)>",
]


def contexto(**hallazgo):
    base = dict(
        severity_label="critical", source="s", check_id="c", cwe=[], cvss_score=None,
        is_new=False, title="t", target="http://h/", param=None, description="",
        remediation="", evidence=[],
    )
    base.update(hallazgo)
    return dict(
        project="p", scan_id=1, profile="x", started="s", egress="e",
        headline="h", lede="l", severity_counts={"critical": 1},
        level_token=informe.LEVEL_TOKEN, level_label=informe.LEVEL_LABEL,
        order=informe.ORDER, kind="web", targets_count=1, alive=1, probed=1,
        new=0, fixed=0, duration="1 s", tools="t", version="0", generated="g",
        scope_text="s", tokens="", fuentes="", findings=[base],
    )


# Dónde puede aterrizar texto del objetivo, y cómo se coloca ahí.
SITIOS = {
    "título": lambda v: dict(title=v),
    "descripción": lambda v: dict(description=v),
    "corrección": lambda v: dict(remediation=v),
    "objetivo": lambda v: dict(target=v),
    "parámetro": lambda v: dict(param=v),
    "origen": lambda v: dict(source=v),
    "CWE": lambda v: dict(cwe=[v]),
    "fragmento": lambda v: dict(evidence=[dict(request=None, response=None, snippet=v)]),
    "petición": lambda v: dict(evidence=[dict(request=v, response=None, snippet=None)]),
    "respuesta": lambda v: dict(evidence=[dict(request=None, response=v, snippet=None)]),
}


@pytest.mark.parametrize("sitio", SITIOS)
@pytest.mark.parametrize("vector", VECTORES)
def test_lo_que_viene_del_objetivo_sale_escapado(sitio, vector):
    salida = informe.render_html(contexto(**SITIOS[sitio](vector)))
    assert vector not in salida, f"{sitio} llegó al informe sin escapar"


def test_la_cabecera_del_proyecto_tambien_se_escapa():
    """El nombre del proyecto lo escribe el analista, pero acaba en el mismo
    HTML: no hay motivo para tratarlo distinto."""
    ctx = contexto()
    ctx["project"] = ctx["headline"] = "<script>alert(1)</script>"
    assert "<script>alert(1)</script>" not in informe.render_html(ctx)


def test_el_resaltado_de_cabeceras_sigue_funcionando():
    """El control negativo de lo anterior.

    Escaparlo todo sería trivial y rompería el informe: los nombres de
    cabecera van marcados con un `<span>` que añadimos nosotros, y ese sí
    tiene que llegar como HTML.
    """
    salida = informe.render_html(contexto(
        evidence=[dict(request="GET / HTTP/1.1\nHost: h\n", response=None, snippet=None)]))
    assert '<span class="hk">Host</span>:' in salida


def test_el_estilo_llega_sin_estropear():
    """Otro control: el CSS lleva comillas, y escaparlas lo deja inservible
    sin que el navegador proteste —simplemente no aplica la regla—."""
    ctx = contexto()
    ctx["tokens"] = ':root{--cx-sans:"B612","Verdana"}'
    assert ':root{--cx-sans:"B612","Verdana"}' in informe.render_html(ctx)


def test_el_primer_parrafo_escapa_la_ruta_analizada():
    """Ese párrafo se inserta como HTML porque lleva negritas nuestras; lo que
    venga de fuera dentro de él se escapa a mano."""
    parrafo = informe._lede({}, 0, 0, 0, kind="code", ruta="<script>x</script>")
    assert "<script>" not in parrafo
    assert "&lt;script&gt;" in parrafo


def test_la_tipografia_viaja_dentro_del_informe():
    """El informe se abre donde la B612 no está instalada, y no puede pedirla
    a la red. Va en base64, sin una sola URL."""
    fuentes = informe.fuentes_en_linea()
    assert fuentes.count("@font-face") == 3
    assert "data:font/woff2;base64," in fuentes
    assert "http" not in fuentes
