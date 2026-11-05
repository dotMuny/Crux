"""Perfiles de escaneo: cuánto se permite tocar el objetivo.

Un escaneo contra una app interna en producción no se parece a uno contra un
entorno de pruebas. El perfil fija una sola vez el ritmo, la concurrencia y qué
clases de prueba están permitidas, y cada adaptador lo traduce a sus flags.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass

from .severity import Severity


class Profile(enum.StrEnum):
    PASSIVE = "passive"
    SAFE_ACTIVE = "safe-active"
    AGGRESSIVE = "aggressive"


@dataclass(frozen=True, slots=True)
class Policy:
    """Los límites concretos de un perfil."""

    profile: Profile
    # Ritmo y paralelismo
    max_rps: float
    concurrency: int
    request_timeout: float
    task_timeout: int                     # segundos por tarea; 0 = sin límite
    # Qué se permite
    allow_active_probes: bool             # enviar payloads de prueba
    allow_injection: bool                 # sqlmap, fuzzing de inyección
    allow_bruteforce: bool                # descubrimiento de contenido por fuerza bruta
    allow_destructive_methods: bool       # PUT/DELETE en pruebas
    # Crawling
    crawl_max_pages: int
    crawl_max_depth: int
    # Filtro de severidad mínima a reportar
    min_severity: Severity = Severity.INFO

    @property
    def nuclei_severities(self) -> str:
        """Severidades que se piden a nuclei, según el perfil."""
        if self.profile is Profile.PASSIVE:
            return "info,low,medium,high,critical"
        return "info,low,medium,high,critical"

    @property
    def nuclei_rate_limit(self) -> int:
        return max(1, int(self.max_rps))


_PROFILES: dict[Profile, Policy] = {
    # Solo observación: nada que modifique estado ni genere carga apreciable.
    # Es el perfil con el que se toca producción.
    Profile.PASSIVE: Policy(
        profile=Profile.PASSIVE,
        max_rps=5,
        concurrency=4,
        request_timeout=10.0,
        task_timeout=900,
        allow_active_probes=False,
        allow_injection=False,
        allow_bruteforce=False,
        allow_destructive_methods=False,
        crawl_max_pages=150,
        crawl_max_depth=3,
    ),
    # El predeterminado: detección activa sin fuerza bruta ni inyección profunda.
    Profile.SAFE_ACTIVE: Policy(
        profile=Profile.SAFE_ACTIVE,
        max_rps=20,
        concurrency=10,
        request_timeout=15.0,
        task_timeout=1200,
        allow_active_probes=True,
        allow_injection=False,
        allow_bruteforce=True,
        allow_destructive_methods=False,
        crawl_max_pages=600,
        crawl_max_depth=5,
    ),
    # Todo permitido. Para entornos de pruebas o ventanas acordadas.
    Profile.AGGRESSIVE: Policy(
        profile=Profile.AGGRESSIVE,
        max_rps=80,
        concurrency=25,
        request_timeout=25.0,
        task_timeout=0,
        allow_active_probes=True,
        allow_injection=True,
        allow_bruteforce=True,
        allow_destructive_methods=True,
        crawl_max_pages=3000,
        crawl_max_depth=8,
    ),
}


def get_policy(profile: Profile | str) -> Policy:
    key = Profile(profile) if not isinstance(profile, Profile) else profile
    return _PROFILES[key]
