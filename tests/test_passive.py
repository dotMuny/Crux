"""Comprobaciones propias. Son funciones puras, así que se prueban sin red."""

from __future__ import annotations

import pytest

from crux.core.severity import Severity
from crux.modules import passive
from crux.modules.probe import ProbeResult


def respuesta(**campos) -> ProbeResult:
    """ProbeResult mínimo y sano, que cada test estropea a su manera."""
    base = dict(
        url="https://app.intra/", final_url="https://app.intra/", status=200,
        headers={
            "content-security-policy": "default-src 'self'",
            "strict-transport-security": "max-age=31536000",
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "referrer-policy": "no-referrer",
            "permissions-policy": "geolocation=()",
            "cross-origin-opener-policy": "same-origin",
        },
        raw_request="GET / HTTP/1.1\r\n\r\n", raw_response="HTTP/1.1 200 OK\r\n\r\n",
    )
    base.update(campos)
    return ProbeResult(**base)


class TestCabeceras:
    def test_una_respuesta_completa_no_genera_hallazgo(self):
        assert list(passive.check_security_headers(respuesta())) == []

    def test_se_agrupan_en_un_solo_hallazgo(self):
        """Siete hallazgos para la misma causa y la misma corrección solo
        inflan la cola de triaje."""
        hallazgos = list(passive.check_security_headers(respuesta(headers={})))
        assert len(hallazgos) == 1
        assert "cabeceras de seguridad ausentes" in hallazgos[0].title

    def test_faltar_las_dos_principales_sube_la_severidad(self):
        solo_menores = respuesta(headers={
            "content-security-policy": "default-src 'self'",
            "x-content-type-options": "nosniff",
        })
        graves = respuesta(headers={"x-frame-options": "DENY"})
        assert next(iter(passive.check_security_headers(solo_menores))).severity is Severity.LOW
        assert next(iter(passive.check_security_headers(graves))).severity is Severity.MEDIUM

    def test_hsts_no_se_exige_sobre_http(self):
        """Sobre HTTP el problema es el transporte, no la cabecera que falta."""
        r = respuesta(url="http://app.intra/", final_url="http://app.intra/", headers={})
        hallazgo = next(iter(passive.check_security_headers(r)))
        assert "strict-transport-security" not in hallazgo.extra["missing"]


class TestCookies:
    def test_una_cookie_de_sesion_pesa_mas_que_una_de_preferencias(self):
        sesion = respuesta(cookies=[{"name": "JSESSIONID", "secure": False,
                                     "httponly": False, "samesite": None}])
        tema = respuesta(cookies=[{"name": "tema", "secure": False,
                                   "httponly": False, "samesite": None}])
        assert next(iter(passive.check_cookies(sesion))).severity is Severity.MEDIUM
        assert next(iter(passive.check_cookies(tema))).severity is Severity.LOW

    def test_un_hallazgo_por_cookie(self):
        """La corrección es por cookie, así que el hallazgo también."""
        r = respuesta(cookies=[
            {"name": "a", "secure": False, "httponly": False, "samesite": None},
            {"name": "b", "secure": False, "httponly": False, "samesite": None},
        ])
        hallazgos = list(passive.check_cookies(r))
        assert len(hallazgos) == 2
        assert len({h.fingerprint for h in hallazgos}) == 2

    def test_secure_no_se_exige_sobre_http(self):
        r = respuesta(url="http://a/", final_url="http://a/",
                      cookies=[{"name": "x", "secure": False, "httponly": True,
                                "samesite": "Lax"}])
        assert list(passive.check_cookies(r)) == []

    def test_samesite_none_sin_secure_se_detecta(self):
        r = respuesta(cookies=[{"name": "x", "secure": False, "httponly": True,
                                "samesite": "None"}])
        hallazgo = next(iter(passive.check_cookies(r)))
        assert any("SameSite=None sin Secure" in p for p in hallazgo.extra["problems"])


class TestCors:
    def test_reflejar_origen_con_credenciales_es_alto(self):
        r = respuesta(cors={"reflects_origin": True, "allow_credentials": True,
                            "probe_origin": "https://x.invalid", "vary_origin": False})
        hallazgo = next(iter(passive.check_cors(r)))
        assert hallazgo.severity is Severity.HIGH
        assert "Vary: Origin" in hallazgo.description

    def test_reflejar_sin_credenciales_es_medio(self):
        r = respuesta(cors={"reflects_origin": True, "allow_credentials": False,
                            "probe_origin": "https://x.invalid", "vary_origin": True})
        assert next(iter(passive.check_cors(r))).severity is Severity.MEDIUM

    def test_sin_sondeo_no_se_inventa_nada(self):
        assert list(passive.check_cors(respuesta(cors={}))) == []
        assert list(passive.check_cors(respuesta(cors={"error": "timeout"}))) == []


class TestAgrupacion:
    def test_las_comprobaciones_de_sitio_no_se_repiten_por_ruta(self):
        """El fallo que motivó separar comprobaciones por-ruta y por-sitio:
        cinco URLs del mismo origen producían cinco veces el mismo hallazgo."""
        rutas = ["/", "/a", "/b", "/c", "/d"]
        resultados = [
            respuesta(url=f"https://app.intra{p}", final_url=f"https://app.intra{p}",
                      headers={})
            for p in rutas
        ]
        hallazgos = passive.run_all(resultados)
        cabeceras = [f for f in hallazgos if f.check_id == "missing-security-headers"]
        assert len(cabeceras) == 1
        assert cabeceras[0].target == "https://app.intra"
        assert cabeceras[0].extra["paths_checked"] == len(rutas)

    def test_las_comprobaciones_de_ruta_si_se_repiten(self):
        resultados = [
            respuesta(url=f"https://app.intra{p}", final_url=f"https://app.intra{p}",
                      title="Index of /x")
            for p in ("/x/", "/y/")
        ]
        listados = [f for f in passive.run_all(resultados)
                    if f.check_id == "directory-listing"]
        assert len(listados) == 2

    def test_todos_los_fingerprints_son_distintos(self):
        resultados = [
            respuesta(url="http://app.intra/", final_url="http://app.intra/",
                      headers={"server": "Apache/2.4.49"},
                      cookies=[{"name": "SESSIONID", "secure": False,
                                "httponly": False, "samesite": None}],
                      cors={"reflects_origin": True, "allow_credentials": True,
                            "probe_origin": "https://x.invalid", "vary_origin": False}),
        ]
        hallazgos = passive.run_all(resultados)
        assert len(hallazgos) == len({f.fingerprint for f in hallazgos})


class TestContenidoSensible:
    """Esta comprobación existe por un fallo real: /debug/env devolvió el DSN
    de la base, la clave de sesión y la contraseña de SMTP con un 200, y el
    escaneo no marcó nada."""

    DEBUG_ENV = (
        '{"DEBUG": true, "DB_DSN": "postgresql://intra:Verano2026@db.intra:5432/rrhh",'
        '"SECRET_KEY": "3f9a1c7e22b4", "SMTP_PASSWORD": "Correo.2026"}'
    )

    def test_detecta_credenciales_en_un_endpoint_de_depuracion(self):
        r = respuesta(body_preview=self.DEBUG_ENV)
        hallazgo = next(iter(passive.check_sensitive_content(r)))
        assert hallazgo.severity is Severity.HIGH
        campos = {s["campo"] for s in hallazgo.extra["secretos"]}
        assert "SECRET_KEY" in campos and "SMTP_PASSWORD" in campos

    def test_el_titular_no_reproduce_el_secreto(self):
        """El informe circula por correo y se adjunta a tickets: el valor
        completo vive en la evidencia, no en la descripción."""
        r = respuesta(body_preview=self.DEBUG_ENV)
        hallazgo = next(iter(passive.check_sensitive_content(r)))
        assert "Correo.2026" not in hallazgo.description
        assert "Verano2026" not in hallazgo.description
        assert "Co*" in hallazgo.description

    @pytest.mark.parametrize("cuerpo", [
        '{"DB_PASSWORD": "changeme"}',
        '{"API_KEY": "<your-key-here>"}',
        '{"SECRET": "null"}',
        '{"TOKEN": "${ENV_VAR}"}',
        "<html><title>Portal</title><p>Bienvenido al portal</p></html>",
    ])
    def test_los_marcadores_de_posicion_no_son_hallazgo(self, cuerpo):
        r = respuesta(body_preview=cuerpo)
        assert list(passive.check_sensitive_content(r)) == []

    def test_clave_de_aws_y_clave_privada(self):
        for cuerpo in ("AWS_ACCESS_KEY=AKIA1234567890ABCDEF",
                       "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKC"):
            r = respuesta(body_preview=cuerpo)
            assert list(passive.check_sensitive_content(r)), cuerpo

    def test_una_respuesta_de_error_no_se_analiza(self):
        """Un 500 con una traza no es una exposición: es un error, y lo cubre
        otra comprobación."""
        r = respuesta(status=500, body_preview=self.DEBUG_ENV)
        assert list(passive.check_sensitive_content(r)) == []


class TestEquivalenciaEntreHerramientas:
    def test_nuclei_y_el_modulo_propio_colapsan(self):
        """La promesa del fingerprint: dos herramientas detectando lo mismo son
        un hallazgo. Antes no se cumplía porque el origen entraba en el hash."""
        from crux.core.findings import Finding

        nuestro = Finding(source="passive", check_id="missing-security-headers",
                          title="6 ausentes", target="http://h:8999")
        suyo = Finding(source="nuclei", check_id="http-missing-security-headers",
                       title="csp", target="http://h:8999/",
                       fingerprint_extra="content-security-policy")
        assert nuestro.fingerprint == suyo.fingerprint

    def test_las_variantes_agrupadas_de_nuclei_colapsan_entre_si(self):
        """nuclei emite una por cabecera ausente; son diez filas para un solo
        problema con una sola corrección."""
        from crux.core.findings import Finding

        variantes = [
            Finding(source="nuclei", check_id="http-missing-security-headers",
                    title=h, target="http://h:8999/", fingerprint_extra=h)
            for h in ("content-security-policy", "x-frame-options", "referrer-policy")
        ]
        assert len({f.fingerprint for f in variantes}) == 1

    def test_las_cookies_no_se_funden_entre_si(self):
        """La equivalencia vale, pero dos cookies distintas son dos hallazgos:
        se arreglan por separado."""
        from crux.core.findings import Finding

        a = Finding(source="passive", check_id="cookie-missing-flags",
                    title="a", target="http://h/", fingerprint_extra="SESSIONID")
        b = Finding(source="passive", check_id="cookie-missing-flags",
                    title="b", target="http://h/", fingerprint_extra="CSRFTOKEN")
        assert a.fingerprint != b.fingerprint


class TestAbsorcion:
    """Cuando la herramienta de menor rango no puede aportar el discriminante,
    su hallazgo se absorbe. Nació de dos duplicados de cookie que sobrevivieron
    al deduplicado por fingerprint."""

    def _cookie_nuestra(self):
        from crux.core.findings import Finding
        return Finding(source="passive", check_id="cookie-missing-flags",
                       title="SESSIONID", target="http://h:8999/",
                       fingerprint_extra="SESSIONID", severity=Severity.MEDIUM)

    def _cookies_de_nuclei(self):
        from crux.core.findings import Finding
        return [
            Finding(source="nuclei", check_id=cid, title=cid,
                    target="http://h:8999/", severity=Severity.INFO)
            for cid in ("cookies-without-secure", "cookies-without-httponly",
                        "missing-cookie-samesite-strict")
        ]

    def test_el_hallazgo_mejor_explicado_absorbe_al_otro(self):
        from crux.core.scan import _absorb
        resultado, _ = _absorb([self._cookie_nuestra(), *self._cookies_de_nuclei()])
        assert [f.source for f in resultado] == ["passive"]

    def test_sin_el_nuestro_el_de_la_herramienta_se_conserva(self):
        """Absorber nunca debe esconder un hallazgo que nadie más reporta."""
        from crux.core.scan import _absorb
        resultado, _ = _absorb(self._cookies_de_nuclei())
        assert len(resultado) == 3

    def test_no_absorbe_entre_origenes_distintos(self):
        from crux.core.findings import Finding
        from crux.core.scan import _absorb
        nuestro = self._cookie_nuestra()
        suyo = Finding(source="nuclei", check_id="cookies-without-secure",
                       title="x", target="http://otro-host:8999/")
        assert len(_absorb([nuestro, suyo])[0]) == 2

    def test_lo_que_no_tiene_equivalencia_no_se_toca(self):
        """Un hallazgo sin identidad canónica declarada pasa intacto."""
        from crux.core.findings import Finding
        from crux.core.scan import _absorb
        suelto = Finding(source="nuclei", check_id="git-config", title="git",
                         target="http://h:8999/.git/config")
        resultado, _ = _absorb([self._cookie_nuestra(), suelto])
        assert len(resultado) == 2
        assert {f.check_id for f in resultado} == {"cookie-missing-flags", "git-config"}


class TestObjetivoAbsoluto:
    def test_nuclei_sin_esquema_se_completa(self):
        """nuclei reporta unas veces la URL completa y otras host:puerto a
        secas; sin esquema el fingerprint nunca casa con otra herramienta."""
        from crux.adapters.nuclei import _absolute
        assert _absolute("127.0.0.1:8999", {"host": "http://127.0.0.1:8999"}) == \
            "http://127.0.0.1:8999"
        assert _absolute("app.intra:443", {}) == "https://app.intra:443"
        assert _absolute("http://ya/absoluta", {}) == "http://ya/absoluta"

    @pytest.mark.necesita_objetivo
    def test_lo_absorbido_no_llega_a_la_base(self, tmp_path):
        """El CLI mostraba 11 hallazgos y la base guardaba 12: _persist seguía
        usando el conjunto previo a la absorción. La web UI lee de la base, así
        que habría enseñado uno más que el informe."""
        import asyncio
        from sqlalchemy import func, select

        from crux.core.models import FindingRecord
        from crux.core.scan import run_web_scan
        from crux.core.store import session_scope

        db = tmp_path / "t.db"
        resultado = asyncio.run(
            # Sin adaptadores externos: este test comprueba la persistencia,
            # no la detección, y no debe tardar seis minutos.
            run_web_scan(["http://127.0.0.1:8999/"], profile="passive",
                         project_name="t", db=db, only=[], con_crawler=False)
        )
        with session_scope(db) as session:
            filas = session.scalar(select(func.count(FindingRecord.id)))
        assert filas == len(resultado.findings), (
            "la base y lo reportado deben coincidir"
        )
