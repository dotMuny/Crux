"""El fingerprint: la pieza de la que dependen el deduplicado y los diffs."""

from __future__ import annotations

from crux.core.findings import Finding, compute_fingerprint, normalize_target
from crux.core.severity import Severity, from_cvss_vector, from_tool


class TestNormalizacion:
    def test_los_identificadores_de_ruta_se_colapsan(self):
        """/user/41 y /user/42 son el mismo hallazgo, no dos."""
        a = normalize_target("https://app.intra/user/41/perfil")
        b = normalize_target("https://app.intra/user/42/perfil")
        assert a == b == "https://app.intra/user/{id}/perfil"

    def test_uuids_y_hashes_tambien(self):
        uuid = normalize_target("http://a/doc/550e8400-e29b-41d4-a716-446655440000")
        hexa = normalize_target("http://a/doc/9f2b7c1d4e8a3f61")
        assert uuid == hexa == "http://a/doc/{id}"

    def test_se_conservan_los_nombres_de_parametro_no_los_valores(self):
        a = normalize_target("http://a/buscar?q=ana&orden=asc")
        b = normalize_target("http://a/buscar?orden=desc&q=luis")
        assert a == b == "http://a/buscar?orden&q"

    def test_los_parametros_volatiles_se_descartan(self):
        """Un csrf o un timestamp cambian en cada ejecución; si entrasen en el
        fingerprint, cada escaneo reportaría todo como nuevo."""
        base = normalize_target("http://a/x?id=1")
        ruidoso = normalize_target("http://a/x?id=1&csrftoken=abc&_=1730000000&sid=zz")
        assert base == ruidoso

    def test_el_puerto_por_defecto_no_cuenta(self):
        assert normalize_target("https://a:443/x") == normalize_target("https://a/x")
        assert normalize_target("http://a:80/x") == normalize_target("http://a/x")

    def test_un_puerto_no_estandar_si_cuenta(self):
        assert normalize_target("http://a:8080/x") != normalize_target("http://a/x")

    def test_las_rutas_de_fichero_pasan_tal_cual(self):
        assert normalize_target("src/app/views.py:42") == "src/app/views.py:42"


class TestFingerprint:
    def test_estable_entre_ejecuciones_equivalentes(self):
        a = compute_fingerprint(check_id="nuclei:x", target="https://h/u/1?id=2")
        b = compute_fingerprint(check_id="nuclei:x", target="https://h/u/9?id=5&token=z")
        assert a == b

    def test_distingue_comprobaciones_distintas(self):
        a = compute_fingerprint(check_id="nuclei:a", target="https://h/")
        b = compute_fingerprint(check_id="nuclei:b", target="https://h/")
        assert a != b

    def test_distingue_parametros_distintos(self):
        a = compute_fingerprint(check_id="c", target="https://h/x", param="user")
        b = compute_fingerprint(check_id="c", target="https://h/x", param="pass")
        assert a != b

    def test_el_discriminante_extra_separa_hallazgos_del_mismo_check(self):
        """Dos cabeceras distintas detectadas por la misma plantilla son dos
        hallazgos, no uno."""
        a = compute_fingerprint(check_id="c", target="https://h/", extra="csp")
        b = compute_fingerprint(check_id="c", target="https://h/", extra="hsts")
        assert a != b

    def test_la_severidad_no_entra_en_el_fingerprint(self):
        """Si entrase, recalificar un hallazgo lo convertiría en otro distinto
        y se perdería su historial de triaje."""
        comun = dict(source="x", check_id="c", title="t", target="https://h/")
        bajo = Finding(severity=Severity.LOW, **comun)
        alto = Finding(severity=Severity.CRITICAL, **comun)
        assert bajo.fingerprint == alto.fingerprint


class TestSeveridad:
    def test_vocabulario_de_cada_herramienta(self):
        assert from_tool("WARNING") is Severity.MEDIUM      # semgrep
        assert from_tool("ERROR") is Severity.HIGH          # semgrep
        assert from_tool("Critical") is Severity.CRITICAL
        assert from_tool("3") is Severity.HIGH              # nikto/wapiti
        assert from_tool(None) is Severity.INFO

    def test_una_puntuacion_numerica_usa_los_rangos_de_cvss(self):
        assert from_tool(9.8) is Severity.CRITICAL
        assert from_tool(5.3) is Severity.MEDIUM
        assert from_tool(2.0) is Severity.LOW

    def test_el_vector_cvss_se_puntua(self):
        severidad, puntuacion = from_cvss_vector(
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        )
        assert puntuacion == 9.8
        assert severidad is Severity.CRITICAL

    def test_un_vector_ilegible_no_revienta(self):
        assert from_cvss_vector("esto no es un vector") is None

    def test_la_etiqueta_de_la_herramienta_manda_sobre_el_cvss(self):
        """Muchas plantillas de nuclei traen un CVSS genérico junto a una
        severidad `info`. Ascenderlas automáticamente inundaría el triaje."""
        f = Finding(
            source="nuclei", check_id="t", title="x", target="http://h/",
            severity=Severity.INFO,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        )
        assert f.severity is Severity.INFO    # la etiqueta gana
        assert f.cvss_score == 9.8            # pero la puntuación se conserva
