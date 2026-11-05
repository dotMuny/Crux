"""Rutas locales, siguiendo el estándar XDG. Un fichero por analista, sin servidor."""

from __future__ import annotations

import os
from pathlib import Path


def _xdg(var: str, fallback: str) -> Path:
    value = os.environ.get(var)
    return Path(value) if value else Path.home() / fallback


def data_dir() -> Path:
    return _xdg("XDG_DATA_HOME", ".local/share") / "crux"


def config_dir() -> Path:
    return _xdg("XDG_CONFIG_HOME", ".config") / "crux"


def cache_dir() -> Path:
    return _xdg("XDG_CACHE_HOME", ".cache") / "crux"


def db_path() -> Path:
    return data_dir() / "crux.db"


def runs_dir() -> Path:
    """Salidas crudas de cada herramienta, por escaneo."""
    return data_dir() / "runs"


def reports_dir() -> Path:
    return data_dir() / "reports"


def nuclei_templates_dir() -> Path:
    """Directorio local de plantillas. Se fija de forma explícita para que nunca
    se dependa de la autoactualización de nuclei."""
    return data_dir() / "nuclei-templates"


def vulndb_dir() -> Path:
    """Bases de vulnerabilidades descargadas en el bootstrap (trivy, osv)."""
    return data_dir() / "vulndb"


def ensure_dirs() -> None:
    for path in (data_dir(), config_dir(), cache_dir(), runs_dir(), reports_dir()):
        path.mkdir(parents=True, exist_ok=True)
