"""Adaptadores de herramienta. Importarlos aquí es lo que los registra."""

from . import gitleaks, nuclei, semgrep, trivy, wapiti  # noqa: F401
from .base import Adapter, ScanContext, all_adapters, get_adapter, register

__all__ = ["Adapter", "ScanContext", "all_adapters", "get_adapter", "register"]
