"""El adaptador de nuclei: política de egress y carga de trabajo.

Los dos tests de carga existen por un fallo real: el primer escaneo completo
tardaba cuarenta minutos contra una aplicación Flask de juguete, porque se
lanzaba el catálogo entero contra cada una de las rutas descubiertas.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from crux.adapters.base import ScanContext
from crux.core.severity import Severity
from crux.adapters.nuclei import BASELINE_TAGS, NucleiAdapter, tags_for
from crux.core.policy import get_policy
from crux.core.runner import ToolRun
from crux.core.scope import Scope


@pytest.fixture
def ctx():
    scope = Scope.build(["http://127.0.0.1:8999/"])
    return ScanContext(
        scope=scope,
        policy=get_policy("safe-active"),
        workdir=Path(tempfile.mkdtemp()),
        discovered={
            "urls": [f"http://127.0.0.1:8999{p}" for p in
                     ("/", "/a", "/b", "/c", "/debug/env", "/.git/config")],
            "technologies": ["Apache httpd 2.4.49", "Werkzeug 3.1.8", "PHP 5.6.40"],
        },
    )


class TestCargaDeTrabajo:
    def test_a_nuclei_se_le_dan_origenes_no_cada_ruta(self, ctx):
        """Sus plantillas construyen su ruta desde {{BaseURL}}: pasarle las seis
        rutas del mismo host sextuplica el trabajo sin encontrar nada más."""
        assert NucleiAdapter().targets_for(ctx) == ["http://127.0.0.1:8999/"]

    def test_el_perfil_agresivo_si_recibe_las_rutas(self, ctx):
        """El fuzzing DAST inyecta en parámetros concretos, así que ahí las
        rutas sí importan."""
        ctx.policy = get_policy("aggressive")
        assert len(NucleiAdapter().targets_for(ctx)) == len(ctx.urls)

    def test_las_etiquetas_salen_de_la_huella_detectada(self):
        tags = tags_for(["Apache httpd 2.4.49", "PHP 5.6.40"])
        assert "apache" in tags and "php" in tags
        assert set(BASELINE_TAGS).issubset(tags)
        # Nada de WordPress si no se ha detectado WordPress.
        assert "wordpress" not in tags

    def test_sin_huella_quedan_las_etiquetas_de_base(self):
        assert tags_for([]) == sorted(BASELINE_TAGS)


class TestEgress:
    def test_el_argv_cumple_su_propia_politica(self, ctx, tmp_path):
        """Lo que construye el adaptador tiene que pasar su propio filtro."""
        ctx.workdir = tmp_path
        templates = tmp_path / "plantillas"
        templates.mkdir()
        (templates / "x.yaml").write_text("id: x\n")

        adapter = NucleiAdapter()
        adapter.templates_dir = lambda: templates  # type: ignore[method-assign]
        argv = adapter.build_argv(ctx)
        NucleiAdapter.egress.check("nuclei", argv)  # no debe lanzar

        assert "-ni" in argv, "sin -ni, nuclei usa el Interactsh público"
        assert "-duc" in argv
        assert "-pt" in argv and argv[argv.index("-pt") + 1] == "http"

    def test_sin_plantillas_locales_falla_con_instrucciones(self, ctx, tmp_path):
        ctx.workdir = tmp_path
        adapter = NucleiAdapter()
        adapter.templates_dir = lambda: None  # type: ignore[method-assign]
        with pytest.raises(RuntimeError, match="bootstrap|plantillas"):
            adapter.build_argv(ctx)


class TestParseo:
    def test_un_registro_real_se_traduce(self, ctx, tmp_path):
        ctx.workdir = tmp_path
        registro = {
            "template-id": "spring-actuator-env",
            "matcher-name": "env",
            "info": {
                "name": "Spring Boot Actuator expone /env",
                "severity": "high",
                "tags": ["springboot", "exposure"],
                "classification": {
                    "cwe-id": ["cwe-200"],
                    "cve-id": ["CVE-2021-0000"],
                    "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "cvss-score": 7.5,
                },
            },
            "matched-at": "http://127.0.0.1:8999/actuator/env",
            "request": "GET /actuator/env HTTP/1.1\r\n\r\n",
            "response": "HTTP/1.1 200 OK\r\n\r\n{}",
        }
        (tmp_path / "nuclei-results.jsonl").write_text(json.dumps(registro) + "\n")
        run = ToolRun(tool="nuclei", argv=[], exit_code=0,
                      stdout_path=tmp_path / "o", stderr_path=tmp_path / "e", duration=0.1)

        hallazgo = next(iter(NucleiAdapter().parse(run, ctx)))
        assert hallazgo.severity.label == "high"
        assert hallazgo.cwe == ["CWE-200"]
        assert hallazgo.cvss_score == 7.5
        assert any("CVE-2021-0000" in r for r in hallazgo.references)
        assert hallazgo.evidence and hallazgo.evidence[0].request

    def test_el_matcher_separa_hallazgos_de_la_misma_plantilla(self, ctx, tmp_path):
        ctx.workdir = tmp_path
        base = {"template-id": "headers", "info": {"name": "x", "severity": "info"},
                "matched-at": "http://127.0.0.1:8999/"}
        lineas = [json.dumps(base | {"matcher-name": m}) for m in ("csp", "hsts")]
        (tmp_path / "nuclei-results.jsonl").write_text("\n".join(lineas) + "\n")
        run = ToolRun(tool="nuclei", argv=[], exit_code=0,
                      stdout_path=tmp_path / "o", stderr_path=tmp_path / "e", duration=0.1)

        hallazgos = list(NucleiAdapter().parse(run, ctx))
        assert len({f.fingerprint for f in hallazgos}) == 2

    def test_la_basura_no_rompe_el_parseo_pero_se_cuenta(self, ctx, tmp_path):
        """Una línea ilegible no tumba el escaneo, pero tampoco se calla.

        Antes este test exigía exactamente un hallazgo, y con eso daba por
        buena la pérdida: `{roto` era una línea que nuclei escribió —un
        hallazgo suyo— y que desaparecía sin dejar rastro. El progreso que
        nuclei mezcla por la salida estándar sí es ruido y no cuenta.
        """
        ctx.workdir = tmp_path
        (tmp_path / "nuclei-results.jsonl").write_text(
            "[INF] progreso que no es JSON\n{roto\n"
            '{"template-id":"x","info":{"name":"n","severity":"low"},'
            '"matched-at":"http://127.0.0.1:8999/"}\n'
        )
        run = ToolRun(tool="nuclei", argv=[], exit_code=0,
                      stdout_path=tmp_path / "o", stderr_path=tmp_path / "e", duration=0.1)

        hallazgos = list(NucleiAdapter().parse(run, ctx))
        reales = [f for f in hallazgos if f.check_id != "salida-ilegible"]
        avisos = [f for f in hallazgos if f.check_id == "salida-ilegible"]
        assert len(reales) == 1
        assert len(avisos) == 1, "la línea ilegible tiene que salir en el informe"
        assert avisos[0].extra["ilegibles"] == 1
        assert avisos[0].severity >= Severity.MEDIUM
