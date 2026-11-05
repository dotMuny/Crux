"""Aislamiento de red: contención real, no comprobación.

Los tests que de verdad demuestran algo necesitan privilegios para crear el
namespace. Donde no los haya se marcan como omitidos en lugar de dar un verde
que no significa nada.
"""

from __future__ import annotations

import subprocess

import pytest

from crux.core.sandbox import (
    IP_EQUIPO, SUBRED, SandboxDeRed, SandboxNoDisponible, comprobar_disponible,
)
from crux.core.scope import Scope

HAY_PRIVILEGIOS, MOTIVO = comprobar_disponible()
requiere_privilegios = pytest.mark.skipif(
    not HAY_PRIVILEGIOS, reason=f"sin privilegios para aislar la red: {MOTIVO}"
)


class TestSinPrivilegios:
    """Lo que se puede comprobar sin montar nada."""

    def test_los_destinos_salen_del_alcance(self):
        scope = Scope.build(["10.20.4.0/24", "http://127.0.0.1:8999/"])
        caja = SandboxDeRed(nombre="x", scope=scope)
        destinos = caja._destinos_permitidos()
        assert "10.20.4.0/24" in destinos
        assert any(d.startswith("127.0.0.1") for d in destinos)

    def test_una_red_no_declarada_no_entra(self):
        scope = Scope.build(["10.20.4.0/24"])
        caja = SandboxDeRed(nombre="x", scope=scope)
        assert not any("192.168" in d for d in caja._destinos_permitidos())

    def test_avisa_de_objetivos_en_loopback(self):
        """Dentro del namespace, 127.0.0.1 es otro loopback. Decirlo antes
        evita que un resultado vacío se lea como que la app no responde."""
        scope = Scope.build(["http://127.0.0.1:8999/"])
        caja = SandboxDeRed(nombre="x", scope=scope)
        assert caja.objetivos_en_loopback() == ["http://127.0.0.1:8999/"]

    def test_un_objetivo_encaminable_no_avisa(self):
        scope = Scope.build(["10.20.4.0/24"])
        assert SandboxDeRed(nombre="x", scope=scope).objetivos_en_loopback() == []

    def test_no_se_puede_envolver_sin_montar(self):
        scope = Scope.build(["10.20.4.0/24"])
        with pytest.raises(SandboxNoDisponible):
            SandboxDeRed(nombre="x", scope=scope).envolver(["true"])


@requiere_privilegios
class TestAislamientoReal:
    """Monta el namespace y comprueba qué se alcanza y qué no."""

    @pytest.fixture
    def caja(self):
        # El extremo del cable en el equipo es el objetivo permitido, y sirve
        # de control positivo: si no se alcanza, el aislamiento está de más.
        scope = Scope.build([f"http://{IP_EQUIPO}:8998/"])
        with SandboxDeRed(nombre="cxtest", scope=scope) as sandbox:
            yield sandbox

    def _tcp(self, caja, destino, puerto, timeout=8):
        orden = caja.envolver([
            "timeout", "5", "bash", "-c", f"exec 3<>/dev/tcp/{destino}/{puerto}"
        ])
        return subprocess.run(orden, capture_output=True, timeout=timeout).returncode == 0

    def test_internet_no_tiene_ruta(self, caja):
        assert not self._tcp(caja, "1.1.1.1", 443)

    def test_el_dns_publico_no_tiene_ruta(self, caja):
        assert not self._tcp(caja, "8.8.8.8", 53)

    def test_una_red_interna_no_declarada_tampoco(self, caja):
        """La decisión de alcance estricto deja de ser política y pasa a ser
        una propiedad de la red: no hay ruta."""
        assert not self._tcp(caja, "192.168.1.1", 80)

    def test_la_resolucion_queda_congelada(self, caja):
        """Sin servidor de nombres dentro: solo resuelve lo que se escribió en
        el hosts del namespace. El rebinding deja de ser posible."""
        r = subprocess.run(caja.envolver(["getent", "hosts", "github.com"]),
                           capture_output=True, text=True, timeout=10)
        assert r.returncode != 0 or not r.stdout.strip()

    def test_localhost_resuelve_dentro(self, caja):
        # `getent hosts` devuelve primero la entrada IPv6; `ahosts` las da
        # todas, que es lo que hay que comprobar.
        r = subprocess.run(caja.envolver(["getent", "ahosts", "localhost"]),
                           capture_output=True, text=True, timeout=10)
        assert "127.0.0.1" in r.stdout and "::1" in r.stdout

    def test_la_herramienta_no_corre_como_root(self, caja):
        """El namespace se crea con privilegios, pero lo que se ejecuta dentro
        los suelta: una herramienta auditada no necesita ser root."""
        r = subprocess.run(caja.envolver(["id", "-u"]), capture_output=True,
                           text=True, timeout=10)
        assert r.stdout.strip() != "0"

    def test_se_limpia_al_salir(self):
        scope = Scope.build([f"http://{IP_EQUIPO}:8998/"])
        with SandboxDeRed(nombre="cxlimpieza", scope=scope):
            pass
        existentes = subprocess.run(["ip", "netns", "list"], capture_output=True,
                                    text=True, timeout=10).stdout
        assert "cxlimpieza" not in existentes
