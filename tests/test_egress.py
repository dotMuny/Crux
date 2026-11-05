"""La prueba del requisito central: que nada se sale del alcance.

Hay tres niveles de evidencia aquí, de más débil a más fuerte:

1. Que la política esté declarada (barato, pero solo comprueba intención).
2. Que el entorno del subproceso no lleve credenciales ni proxies.
3. Que las herramientas funcionen **dentro de un namespace de red sin ruta por
   defecto**. Ese último es el que de verdad demuestra la propiedad: si algo
   necesitaba internet, ahí falla.

El tercero requiere poder crear namespaces de usuario; donde no se pueda, se
marca como omitido en lugar de dar un falso verde.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest

from crux.adapters import all_adapters
from crux.adapters.nuclei import NucleiAdapter
from crux.core.egress import (
    EgressPolicyError,
    clean_env,
    leaked_credential_vars,
)

# Herramientas que salen a internet por su cuenta si no se las ata.
PHONES_HOME = {"nuclei", "wapiti", "nikto", "semgrep", "trivy", "osv-scanner"}


def test_entorno_no_propaga_credenciales(monkeypatch):
    """Un subproceso comprometido no debe encontrar nada que exfiltrar."""
    for name, value in {
        "GITHUB_TOKEN": "ghp_falso",
        "AWS_SECRET_ACCESS_KEY": "secreto",
        "NPM_TOKEN": "npm_falso",
        "SSH_AUTH_SOCK": "/tmp/agente",
        "KUBECONFIG": "/home/x/.kube/config",
        "MI_API_KEY": "abc123",
    }.items():
        monkeypatch.setenv(name, value)

    env = clean_env()
    assert leaked_credential_vars(env) == [], (
        f"variables sensibles propagadas al subproceso: {leaked_credential_vars(env)}"
    )


def test_entorno_no_hereda_proxies(monkeypatch):
    """Un proxy heredado sería una ruta de salida que no controlamos."""
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy"):
        monkeypatch.setenv(name, "http://proxy.corporativo:8080")

    env = clean_env()
    assert not {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy"} & set(env)
    assert env["NO_PROXY"] == "*"


def test_telemetria_desactivada_por_entorno():
    env = clean_env()
    assert env["DO_NOT_TRACK"] == "1"
    assert env["SEMGREP_SEND_METRICS"] == "off"
    assert env["PDCP_API_KEY"] == ""


@pytest.mark.parametrize("name", sorted(PHONES_HOME))
def test_herramientas_que_llaman_a_casa_tienen_politica(name):
    """Si añadimos un adaptador de una herramienta con telemetría, debe traer
    su política declarada o este test falla."""
    adapters = all_adapters()
    if name not in adapters:
        pytest.skip(f"el adaptador de {name} todavía no existe")
    policy = adapters[name].egress
    assert policy.required or policy.forbidden, (
        f"{name} sale a internet por defecto y no declara política de egress"
    )


def test_nuclei_exige_desactivar_interactsh():
    """El detalle menos obvio de todo el proyecto: nuclei usa el Interactsh
    PÚBLICO (oast.pro y compañía) por defecto para las pruebas OAST."""
    policy = NucleiAdapter.egress
    assert "-ni" in policy.required
    assert "-duc" in policy.required
    for flag in ("-uc", "-uncover", "-turl", "-cloud-upload", "-iserver"):
        assert flag in policy.forbidden, f"{flag} debería estar prohibido"


def test_la_politica_bloquea_antes_de_ejecutar():
    """Un argv que viola la política no llega nunca a ejecutarse."""
    with pytest.raises(EgressPolicyError) as excinfo:
        NucleiAdapter.egress.check("nuclei", ["nuclei", "-u", "http://10.0.0.1", "-uncover"])
    mensaje = str(excinfo.value)
    assert "-uncover" in mensaje
    assert "-ni" in mensaje  # también avisa de los que faltan


def _puede_crear_netns() -> bool:
    if os.geteuid() == 0:
        return True
    try:
        salida = subprocess.run(
            ["unshare", "-rn", "true"], capture_output=True, timeout=10, check=False
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return salida.returncode == 0


@pytest.mark.skipif(not _puede_crear_netns(),
                    reason="no se pueden crear namespaces de red de usuario aquí")
@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei no instalado")
def test_nuclei_arranca_sin_ruta_por_defecto():
    """nuclei debe arrancar y cargar plantillas sin salida a internet.

    Dentro de `unshare -rn` solo existe loopback y no hay ruta por defecto. Si
    nuclei necesitase la red para arrancar —comprobar versión, bajar plantillas—
    aquí fallaría. Con -duc y -ni no la necesita.
    """
    from crux.core import paths

    templates = paths.nuclei_templates_dir()
    if not templates.is_dir():
        pytest.skip("no hay plantillas instaladas; ejecuta install/bootstrap.sh")

    resultado = subprocess.run(
        ["unshare", "-rn", "nuclei", "-duc", "-ni", "-nc", "-jsonl",
         "-t", str(templates), "-tl", "-tags", "tech"],
        capture_output=True, timeout=180, env=clean_env(), check=False,
    )
    salida = (resultado.stdout + resultado.stderr).decode("utf-8", "replace")
    assert resultado.returncode == 0, f"nuclei falló sin red:\n{salida[-1500:]}"
    assert "oast" not in salida.lower(), "nuclei mencionó un servidor OAST remoto"


@pytest.mark.skipif(not _puede_crear_netns(),
                    reason="no se pueden crear namespaces de red de usuario aquí")
def test_el_probador_no_alcanza_internet_sin_ruta():
    """Dentro del namespace, una petición a una IP pública debe fallar.

    Es el control negativo del test anterior: confirma que el aislamiento es
    real y que el verde de arriba significa algo.
    """
    codigo = (
        "import httpx,sys\n"
        "try:\n"
        "    httpx.get('http://1.1.1.1', timeout=4, trust_env=False)\n"
        "    sys.exit('ALCANZÓ internet: el aislamiento no funciona')\n"
        "except httpx.HTTPError:\n"
        "    print('sin salida, como debe ser')\n"
    )
    resultado = subprocess.run(
        ["unshare", "-rn", sys.executable, "-I", "-c", codigo],
        capture_output=True, timeout=60, env=clean_env(), check=False,
    )
    assert resultado.returncode == 0, (
        resultado.stdout.decode() + resultado.stderr.decode()
    )
