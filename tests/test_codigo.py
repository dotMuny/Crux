"""El pilar de código: semgrep, gitleaks y trivy."""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

import pytest

from crux.adapters.base import ScanContext
from crux.adapters.gitleaks import GitleaksAdapter, _ocultar
from crux.adapters.semgrep import OMITIDOS_POR_DEFECTO, SemgrepAdapter
from crux.adapters.trivy import TrivyAdapter
from crux.core.policy import get_policy
from crux.core.runner import ToolRun
from crux.core.severity import Severity

FIXTURE = Path(__file__).parent / "fixtures" / "vulncode"


@pytest.fixture
def repo(tmp_path):
    """El fixture, copiado fuera de tests/.

    Hace falta porque semgrep omite todo lo que cuelgue de un directorio
    llamado `tests`, así que analizarlo donde vive daría cero hallazgos sin que
    nada falle: el peor tipo de test verde.
    """
    destino = tmp_path / "repo"
    shutil.copytree(FIXTURE, destino)
    return destino


@pytest.fixture
def ctx(repo, tmp_path):
    return ScanContext(policy=get_policy("safe-active"),
                       workdir=tmp_path / "trabajo", ruta=repo)


class TestEgress:
    def test_semgrep_no_descarga_reglas_del_registry(self, ctx, tmp_path):
        """--config=auto baja reglas remotas en cada ejecución: además de
        tráfico saliente, hace que dos escaneos del mismo código difieran."""
        ctx.workdir.mkdir(parents=True, exist_ok=True)
        adapter = SemgrepAdapter()
        if adapter.reglas() is None:
            pytest.skip("sin reglas locales instaladas")
        argv = adapter.build_argv(ctx)
        SemgrepAdapter.egress.check("semgrep", argv)
        assert "--metrics=off" in argv
        assert not any("auto" in a or a.startswith("p/") for a in argv)

    def test_trivy_no_actualiza_la_base_al_escanear(self, ctx, tmp_path):
        ctx.workdir.mkdir(parents=True, exist_ok=True)
        adapter = TrivyAdapter()
        if adapter.base_de_datos() is None:
            pytest.skip("sin base de vulnerabilidades descargada")
        argv = adapter.build_argv(ctx)
        TrivyAdapter.egress.check("trivy", argv)
        assert "--skip-db-update" in argv and "--offline-scan" in argv

    def test_la_politica_rechaza_descargar_la_base(self):
        from crux.core.egress import EgressPolicyError

        with pytest.raises(EgressPolicyError):
            TrivyAdapter.egress.check(
                "trivy", ["trivy", "image", "--download-db-only"]
            )


class TestSemgrep:
    def test_avisa_de_lo_que_no_analizo(self, ctx, repo):
        """Un informe que dice «sin hallazgos» sobre código que nadie miró es
        peor que no informar."""
        (repo / "node_modules").mkdir()
        (repo / "node_modules" / "x.js").write_text("eval(req.query.x)")
        datos = {"results": [], "paths": {"scanned": ["a.py"]}}
        run = ToolRun(tool="semgrep", argv=[], exit_code=0,
                      stdout_path=Path("/dev/null"), stderr_path=Path("/dev/null"),
                      duration=0.1, stdout=json.dumps(datos))
        hallazgos = list(SemgrepAdapter().parse(run, ctx))
        aviso = [f for f in hallazgos if f.check_id == "cobertura-parcial"]
        assert aviso and "node_modules" in aviso[0].extra["omitidos"]

    def test_sin_directorios_omitidos_no_avisa(self, ctx, tmp_path):
        limpio = tmp_path / "limpio"
        limpio.mkdir()
        (limpio / "a.py").write_text("x = 1")
        ctx.ruta = limpio
        datos = {"results": [], "paths": {"scanned": ["a.py"]}}
        run = ToolRun(tool="semgrep", argv=[], exit_code=0,
                      stdout_path=Path("/dev/null"), stderr_path=Path("/dev/null"),
                      duration=0.1, stdout=json.dumps(datos))
        assert list(SemgrepAdapter().parse(run, ctx)) == []

    def test_la_lista_de_omitidos_es_la_comprobada(self):
        """Verificada empíricamente con esta versión, no copiada de la documentación."""
        assert "tests" in OMITIDOS_POR_DEFECTO
        assert "node_modules" in OMITIDOS_POR_DEFECTO
        assert "src" not in OMITIDOS_POR_DEFECTO


class TestGitleaks:
    def test_el_titular_no_reproduce_el_secreto(self):
        oculto = _ocultar("wJalrXUtnFEMI/K7MDENG")
        assert "alrXUtnFEMI" not in oculto
        assert oculto.startswith("wJa") and "ENG" in oculto
        assert _ocultar("corto") == "*****"

    def test_la_mascara_no_crece_con_el_secreto(self):
        """Una clave privada producía una tira de asteriscos que desbordaba el
        informe a lo ancho. La longitud real se da como dato, no como ancho."""
        corto = _ocultar("a" * 20)
        largo = _ocultar("a" * 600)
        assert corto.count("*") == largo.count("*") == 8
        assert "600 caracteres" in largo

    def test_los_secretos_se_gradua_por_tipo(self, ctx, tmp_path):
        """Una clave privada no pesa lo mismo que un JWT de ejemplo."""
        informe = ctx.workdir
        informe.mkdir(parents=True, exist_ok=True)
        (informe / "gitleaks.json").write_text(json.dumps([
            {"RuleID": "private-key", "File": str(ctx.ruta / "id_rsa"),
             "StartLine": 1, "Secret": "-----BEGIN RSA PRIVATE KEY-----"},
            {"RuleID": "jwt", "File": str(ctx.ruta / "t.js"),
             "StartLine": 3, "Secret": "eyJhbGciOi"},
        ]))
        run = ToolRun(tool="gitleaks", argv=[], exit_code=1,
                      stdout_path=Path("/dev/null"), stderr_path=Path("/dev/null"),
                      duration=0.1)
        por_regla = {f.check_id: f.severity for f in GitleaksAdapter().parse(run, ctx)}
        assert por_regla["private-key"] is Severity.CRITICAL
        assert por_regla["jwt"] is Severity.MEDIUM

    def test_sin_repositorio_git_se_analiza_el_arbol(self, ctx):
        ctx.workdir.mkdir(parents=True, exist_ok=True)
        argv = GitleaksAdapter().build_argv(ctx)
        assert "--no-git" in argv


class TestTrivy:
    def _run(self, ctx, resultados):
        ctx.workdir.mkdir(parents=True, exist_ok=True)
        (ctx.workdir / "trivy.json").write_text(json.dumps({"Results": resultados}))
        return ToolRun(tool="trivy", argv=[], exit_code=0,
                       stdout_path=Path("/dev/null"), stderr_path=Path("/dev/null"),
                       duration=0.1)

    def test_un_hallazgo_por_paquete_no_por_cve(self, ctx):
        """Una versión antigua de jackson arrastra sesenta CVE: sesenta filas
        para una sola acción dejan el informe ilegible."""
        vulns = [{"VulnerabilityID": f"CVE-2019-{n}", "PkgName": "jackson-databind",
                  "InstalledVersion": "2.9.8", "FixedVersion": "2.9.10",
                  "Severity": "CRITICAL" if n % 2 else "HIGH"} for n in range(10)]
        run = self._run(ctx, [{"Target": "pom.xml", "Type": "pom",
                               "Vulnerabilities": vulns}])
        hallazgos = [f for f in TrivyAdapter().parse(run, ctx)
                     if f.check_id.startswith("dependencia-vulnerable")]
        assert len(hallazgos) == 1
        assert hallazgos[0].severity is Severity.CRITICAL   # manda el peor
        assert hallazgos[0].extra["total_cves"] == 10

    def test_dos_versiones_del_mismo_paquete_son_dos_hallazgos(self, ctx):
        run = self._run(ctx, [{"Target": "pom.xml", "Type": "pom", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-1", "PkgName": "lib", "InstalledVersion": "1.0",
             "Severity": "HIGH"},
            {"VulnerabilityID": "CVE-2", "PkgName": "lib", "InstalledVersion": "2.0",
             "Severity": "HIGH"},
        ]}])
        hallazgos = [f for f in TrivyAdapter().parse(run, ctx)
                     if f.check_id.startswith("dependencia-vulnerable")]
        assert len({f.fingerprint for f in hallazgos}) == 2

    def test_avisa_de_manifiestos_sin_fichero_de_bloqueo(self, ctx, repo):
        """Sin lockfile, trivy no mira npm, Composer ni NuGet. Un informe
        limpio ahí parecería una buena noticia sin serlo."""
        (repo / "sinlock").mkdir()
        (repo / "sinlock" / "package.json").write_text('{"name":"x"}')
        run = self._run(ctx, [])
        avisos = [f for f in TrivyAdapter().parse(run, ctx)
                  if f.check_id == "sin-fichero-de-bloqueo"]
        assert avisos
        assert any("sinlock" in m for m in avisos[0].extra["manifiestos"])

    def test_el_fixture_tiene_sus_lockfiles(self, repo):
        """Si se pierden, el fixture deja de probar npm, Composer y NuGet sin
        que ningún test falle."""
        for ruta in ("javascript/package-lock.json", "php/composer.lock",
                     "dotnet/packages.lock.json"):
            assert (repo / ruta).exists(), ruta
