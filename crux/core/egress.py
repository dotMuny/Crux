"""Control de egress: que ninguna herramienta hable con nadie que no sea el objetivo.

Tres mecanismos, todos aplicados por el `runner` antes de ejecutar nada:

1. **Flags obligatorios y prohibidos por herramienta.** Varias herramientas salen
   a internet *por defecto*, lo cual es la parte menos obvia de todo esto:
   `nuclei` usa el servidor Interactsh **público** (`oast.pro`, `oast.live`…) para
   las pruebas OAST y comprueba actualizaciones al arrancar; `wapiti` envía un
   informe automático cuando un módulo falla; `nikto` consulta actualizaciones.
   Si falta un flag obligatorio, el runner no ejecuta: falla.

2. **Entorno saneado por allowlist.** Se construye el entorno del subproceso
   desde cero con las variables imprescindibles, en lugar de heredar el del
   usuario y quitar cosas. Así ni las variables de proxy ni las credenciales
   (`AWS_*`, `GITHUB_TOKEN`, `SSH_AUTH_SOCK`…) llegan al subproceso: si una
   herramienta comprometida quisiera exfiltrar algo, no tiene qué.

3. **Argumentos de Chromium** que apagan toda la red de fondo del navegador.
"""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, field
from typing import Final, Iterable, Mapping, Sequence


class EgressPolicyError(RuntimeError):
    """El argv propuesto viola la política de egress. Nunca se llega a ejecutar."""


@dataclass(frozen=True, slots=True)
class EgressPolicy:
    """Qué flags exige y qué flags prohíbe una herramienta concreta."""

    required: tuple[str, ...] = ()
    forbidden: tuple[str, ...] = ()
    # Motivo legible de cada prohibición, para el mensaje de error y la auditoría.
    reasons: Mapping[str, str] = field(default_factory=dict)

    def check(self, tool: str, argv: Sequence[str]) -> None:
        """Valida un argv. Lanza `EgressPolicyError` con todos los problemas."""
        tokens = set(argv)
        problems: list[str] = []

        for flag in self.required:
            if flag not in tokens:
                why = self.reasons.get(flag, "obligatorio por la política de egress")
                problems.append(f"falta {flag} ({why})")

        for flag in self.forbidden:
            if flag in tokens:
                why = self.reasons.get(flag, "prohibido por la política de egress")
                problems.append(f"presente {flag} ({why})")

        if problems:
            raise EgressPolicyError(
                f"{tool}: política de egress violada -> " + "; ".join(problems)
                + f"\n  argv: {shlex.join(argv)}"
            )


# Variables de entorno que sí se pasan a los subprocesos. Todo lo demás se queda
# fuera, credenciales incluidas.
ENV_ALLOWLIST: Final[tuple[str, ...]] = (
    "PATH",
    "HOME",
    "LANG",
    "LC_ALL",
    "TMPDIR",
    "USER",
    "SHELL",
    "GOCACHE",      # go lo necesita aunque solo lea
    "JAVA_HOME",    # algunas herramientas de SCA invocan la JVM
)

# Variables que se fijan en todos los subprocesos para apagar telemetría y proxies.
ENV_OVERRIDES: Final[dict[str, str]] = {
    "NO_COLOR": "1",
    "DO_NOT_TRACK": "1",
    "CI": "1",                       # muchas herramientas callan la telemetría en CI
    "SEMGREP_SEND_METRICS": "off",
    "SEMGREP_ENABLE_VERSION_CHECK": "0",
    "PDCP_API_KEY": "",              # ProjectDiscovery Cloud: sin clave, no sube nada
    "DISABLE_TELEMETRY": "1",
    "SCARF_ANALYTICS": "false",
    "CHECKPOINT_DISABLE": "1",
    # Si algo intentase usar un proxy heredado, NO_PROXY universal lo neutraliza.
    "NO_PROXY": "*",
    "no_proxy": "*",
}

# Argumentos de Chromium que apagan la red que el navegador hace por su cuenta
# (component updater, Safe Browsing, sincronización, informes de dominio).
CHROMIUM_ARGS: Final[tuple[str, ...]] = (
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-background-networking",
    "--disable-component-update",
    "--disable-sync",
    "--disable-domain-reliability",
    "--disable-client-side-phishing-detection",
    "--safebrowsing-disable-auto-update",
    "--disable-breakpad",
    "--metrics-recording-only",
    "--disable-features=OptimizationHints,Translate,MediaRouter,InterestFeedContentSuggestions",
)


def clean_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    """Entorno mínimo para un subproceso, construido por allowlist.

    No hereda el entorno del usuario: lo reconstruye. Es más estricto que quitar
    variables conocidas, porque también deja fuera las que todavía no conocemos.
    """
    env = {name: os.environ[name] for name in ENV_ALLOWLIST if name in os.environ}
    env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    env.update(ENV_OVERRIDES)
    if extra:
        env.update(extra)
    return env


def leaked_credential_vars(env: Mapping[str, str]) -> list[str]:
    """Nombres de variables del entorno dado que parecen llevar credenciales.

    Se usa en los tests para comprobar que `clean_env` no las deja pasar.
    """
    markers = ("TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "APIKEY",
               "CREDENTIAL", "PRIVATE_KEY", "SESSION")
    prefixes = ("AWS_", "AZURE_", "GCP_", "GOOGLE_", "GH_", "GITHUB_", "GITLAB_",
                "DOCKER_", "NPM_", "PYPI_", "SSH_", "KUBE")
    found = []
    for name, value in env.items():
        upper = name.upper()
        if any(m in upper for m in markers) and value:
            found.append(name)
        elif upper.startswith(prefixes) and value:
            found.append(name)
    return sorted(set(found))


def chromium_args(extra: Iterable[str] = ()) -> list[str]:
    return [*CHROMIUM_ARGS, *extra]
