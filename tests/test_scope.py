"""El alcance: que no se pueda tocar nada fuera de la red interna."""

from __future__ import annotations

import pytest

from crux.core.scope import Scope, ScopeError, ScopeViolation, is_internal


class TestRedesInternas:
    @pytest.mark.parametrize("ip", [
        "10.0.0.1", "172.16.5.9", "192.168.1.1", "127.0.0.1", "169.254.1.1",
        "::1", "fd00::1", "fe80::1",
    ])
    def test_se_consideran_internas(self, ip):
        assert is_internal(ip)

    @pytest.mark.parametrize("ip", [
        "8.8.8.8", "1.1.1.1", "172.32.0.1", "2001:4860:4860::8888",
    ])
    def test_se_consideran_publicas(self, ip):
        assert not is_internal(ip)

    def test_el_espacio_compartido_de_rfc6598_solo_si_se_pide(self):
        """100.64/10 no es privado ni público del todo, y la semántica de
        `ipaddress.is_private` ha cambiado entre versiones de Python. Por eso
        la lista es explícita y este caso es opt-in."""
        assert not is_internal("100.64.0.1")
        assert is_internal("100.64.0.1", allow_shared=True)


class TestConstruccion:
    def test_un_objetivo_publico_se_rechaza(self):
        with pytest.raises(ScopeError, match="IP pública"):
            Scope.build(["https://example.com"])

    def test_se_acepta_con_allow_public_explicito(self):
        scope = Scope.build(["https://example.com"], allow_public=True)
        assert scope.allow_public and scope.entries

    def test_el_rechazo_queda_registrado_para_auditoria(self):
        scope = Scope.build(
            ["http://127.0.0.1:8999/", "https://example.com"]
        )
        rechazados = scope.describe()["rejected"]
        assert any("example.com" in r["target"] for r in rechazados)

    def test_un_cidr_se_admite_entero(self):
        scope = Scope.build(["192.168.50.0/24"])
        assert scope.allows_ip("192.168.50.200")

    def test_otra_red_privada_no_declarada_queda_fuera(self):
        """Estar en RFC1918 no basta: autorizar 192.168.50.0/24 no autoriza a
        tocar la subred de al lado, que puede ser de otro equipo."""
        scope = Scope.build(["192.168.50.0/24"])
        assert not scope.allows_ip("192.168.51.1")

    def test_allow_internal_relaja_el_alcance_si_se_pide(self):
        scope = Scope.build(["192.168.50.0/24"], allow_internal=True)
        assert scope.allows_ip("192.168.51.1")
        assert not scope.allows_ip("8.8.8.8")


class TestControlDeAcceso:
    @pytest.fixture
    def scope(self):
        return Scope.build(["http://127.0.0.1:8999/"])

    def test_bloquea_el_interactsh_publico_de_nuclei(self, scope):
        """oast.pro es el servidor OAST que nuclei usa por defecto."""
        assert not scope.allows_url("https://oast.pro/abcdef")

    def test_un_host_no_congelado_no_se_permite(self, scope):
        """Aunque resolviese a una IP interna: si no estaba en el alcance al
        arrancar, no se toca. Esto cierra el DNS rebinding."""
        assert not scope.allows_host("maquina-nueva.intra.corp")

    def test_require_lanza_al_salirse(self, scope):
        with pytest.raises(ScopeViolation):
            scope.require("8.8.8.8")

    def test_el_dns_queda_congelado(self, scope):
        assert scope.resolve("127.0.0.1") or scope.allows_ip("127.0.0.1")
        assert scope.resolve("otro.host") == ()
