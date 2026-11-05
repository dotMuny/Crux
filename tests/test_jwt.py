"""Análisis de JWT: lo que se deduce del token y lo que hay que probar."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest

from crux.core.severity import Severity
from crux.modules import jwt as jwt_mod


def b64(dato: bytes) -> str:
    return base64.urlsafe_b64encode(dato).decode().rstrip("=")


def hacer_token(cabecera: dict, payload: dict, secreto: bytes | None = b"secret") -> str:
    h, p = b64(json.dumps(cabecera).encode()), b64(json.dumps(payload).encode())
    if secreto is None:
        return f"{h}.{p}."
    firma = b64(hmac.new(secreto, f"{h}.{p}".encode(), hashlib.sha256).digest())
    return f"{h}.{p}.{firma}"


class TestParseo:
    def test_un_token_valido_se_descompone(self):
        crudo = hacer_token({"alg": "HS256"}, {"sub": "ana", "exp": 1})
        token = jwt_mod.parsear(crudo)
        assert token is not None
        assert token.alg == "hs256" and token.payload["sub"] == "ana"

    @pytest.mark.parametrize("basura", [
        "", "no.es.jwt", "solodospartes.x", "a.b.c.d",
        b64(b"no es json") + "." + b64(b"{}") + ".x",
    ])
    def test_la_basura_no_revienta(self, basura):
        assert jwt_mod.parsear(basura) is None

    def test_se_encuentran_tokens_dentro_de_texto(self):
        crudo = hacer_token({"alg": "HS256"}, {"sub": "x"})
        hallados = jwt_mod.extraer([("body", f"localStorage.t = '{crudo}';")])
        assert len(hallados) == 1 and hallados[0].crudo == crudo

    def test_el_mismo_token_no_se_duplica(self):
        crudo = hacer_token({"alg": "HS256"}, {"sub": "x"})
        assert len(jwt_mod.extraer([("a", crudo), ("b", crudo)])) == 1


class TestComprobacionesEstaticas:
    def test_un_token_sin_firma_es_critico(self):
        token = jwt_mod.parsear(hacer_token({"alg": "none"}, {"sub": "x"}, None))
        hallazgos = jwt_mod.analizar(token, "http://h/")
        critico = [f for f in hallazgos if f.check_id == "jwt-alg-none-emitido"]
        assert critico and critico[0].severity is Severity.CRITICAL

    def test_se_detecta_el_secreto_de_tutorial(self):
        token = jwt_mod.parsear(hacer_token({"alg": "HS256"}, {"sub": "x"}, b"secret"))
        assert jwt_mod.romper_secreto(token) == "secret"

    def test_un_secreto_fuerte_no_se_rompe(self):
        token = jwt_mod.parsear(
            hacer_token({"alg": "HS256"}, {"sub": "x"}, b"8f3a9c1e7b2d4056a1f8e3c9d7b5a2f4")
        )
        assert jwt_mod.romper_secreto(token) is None

    def test_falta_de_caducidad(self):
        token = jwt_mod.parsear(hacer_token({"alg": "HS256"}, {"sub": "x"}))
        assert any(f.check_id == "jwt-sin-caducidad" for f in jwt_mod.analizar(token, "http://h/"))

    def test_una_caducidad_razonable_no_se_marca(self):
        token = jwt_mod.parsear(
            hacer_token({"alg": "HS256"}, {"sub": "x", "iat": 0, "exp": 3600})
        )
        ids = {f.check_id for f in jwt_mod.analizar(token, "http://h/")}
        assert "jwt-sin-caducidad" not in ids and "jwt-vida-excesiva" not in ids

    def test_una_vida_de_meses_si_se_marca(self):
        token = jwt_mod.parsear(
            hacer_token({"alg": "HS256"}, {"sub": "x", "iat": 0, "exp": 86400 * 365})
        )
        assert any(f.check_id == "jwt-vida-excesiva" for f in jwt_mod.analizar(token, "http://h/"))

    def test_la_contrasena_en_el_payload(self):
        """El payload va en base64, no cifrado: cualquiera que vea el token lo lee."""
        token = jwt_mod.parsear(
            hacer_token({"alg": "HS256"}, {"sub": "x", "password": "Verano2026"})
        )
        hallazgo = next(f for f in jwt_mod.analizar(token, "http://h/")
                        if f.check_id == "jwt-claims-sensibles")
        assert hallazgo.severity is Severity.HIGH
        # El valor del secreto no debe reproducirse en la descripción.
        assert "Verano2026" not in hallazgo.description


class TestForjado:
    def test_el_token_forjado_no_lleva_firma(self):
        token = jwt_mod.parsear(hacer_token({"alg": "HS256"}, {"sub": "luis", "rol": "user"}))
        forjado = jwt_mod.forjar_alg_none(token, rol="admin")
        assert forjado.endswith(".")
        cabecera, payload, _ = forjado.split(".")
        assert json.loads(jwt_mod._b64d(cabecera))["alg"] == "none"
        assert json.loads(jwt_mod._b64d(payload))["rol"] == "admin"
