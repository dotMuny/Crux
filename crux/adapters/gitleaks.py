"""Adaptador de gitleaks: secretos en el código y en el historial.

A diferencia del análisis estático, aquí **no** se excluyen los directorios de
pruebas. Un secreto en un fichero de test es un secreto igual: la credencial
existe, funciona, y quien lea el repositorio la encuentra. La distinción entre
código que se despliega y código que no vale para patrones de inyección, no
para una contraseña.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from ..core.egress import EgressPolicy
from ..core.findings import Evidence, EvidenceKind, Finding
from ..core.runner import ToolRun
from ..core.severity import Confidence, Severity
from .base import Adapter, ScanContext, register

_GITLEAKS_EGRESS = EgressPolicy(
    required=("--report-format", "--no-banner"),
    forbidden=("--baseline-path-remote", "--enable-rule-remote"),
    reasons={
        "--report-format": "el formato JSON es el que parseamos",
        "--no-banner": "el banner ensucia la salida",
    },
)

# Qué tan grave es según lo que se filtró. gitleaks no gradúa: lo hacemos aquí,
# porque una clave de AWS activa no es lo mismo que una cadena de prueba.
GRAVEDAD_POR_REGLA = {
    "aws-access-token": Severity.CRITICAL,
    "aws-secret-key": Severity.CRITICAL,
    "private-key": Severity.CRITICAL,
    "gcp-service-account": Severity.CRITICAL,
    "stripe-access-token": Severity.CRITICAL,
    "github-pat": Severity.CRITICAL,
    "gitlab-pat": Severity.CRITICAL,
    "slack-bot-token": Severity.HIGH,
    "slack-webhook-url": Severity.HIGH,
    "jwt": Severity.MEDIUM,
    "generic-api-key": Severity.HIGH,
}


@register
class GitleaksAdapter(Adapter):
    name = "gitleaks"
    binary = "gitleaks"
    kind = "code"
    egress = _GITLEAKS_EGRESS
    version_argv = ("version",)
    # Devuelve 1 cuando encuentra secretos.
    ok_exit_codes = (0, 1)

    def build_argv(self, ctx: ScanContext) -> list[str] | None:
        raiz = ctx.ruta
        if raiz is None or not raiz.exists():
            return None
        informe = ctx.artifact("gitleaks.json")
        argv = [
            "gitleaks", "detect",
            "--source", str(raiz),
            "--report-format", "json",
            "--report-path", str(informe),
            "--no-banner",
            "--exit-code", "0",     # el informe es la fuente, no el código de salida
            "--redact=0",           # el valor hace falta para la evidencia; se oculta al mostrarlo
        ]
        if not (raiz / ".git").is_dir():
            # Sin repositorio no hay historial que recorrer; sin esto gitleaks
            # falla en vez de analizar los ficheros tal cual están.
            argv.append("--no-git")
        return argv

    def parse(self, run: ToolRun, ctx: ScanContext) -> Iterable[Finding]:
        informe = ctx.artifact("gitleaks.json")
        datos, aviso = self.leer_json(informe, vacio=[])
        if aviso is not None:
            yield aviso

        raiz = ctx.ruta
        for hallazgo in datos or []:
            yield self._a_finding(hallazgo, raiz)

    def _a_finding(self, h: dict, raiz: Path | None) -> Finding:
        regla = h.get("RuleID", "desconocida")
        ruta = h.get("File", "")
        if raiz is not None:
            try:
                ruta = str(Path(ruta).relative_to(raiz))
            except ValueError:
                pass
        linea = h.get("StartLine", 0)
        secreto = h.get("Secret", "") or ""
        commit = h.get("Commit", "") or ""

        return Finding(
            source=self.name,
            check_id=regla,
            title=f"Secreto en el código: {h.get('Description', regla)}",
            description=(
                f"Se encontró un valor que coincide con «{regla}» en {ruta}:{linea}. "
                f"Valor parcial: {_ocultar(secreto)}. "
                + (f"Procede del commit {commit[:10]}, así que sigue en el historial "
                   "aunque se borre del fichero actual."
                   if commit else
                   "Está en el árbol de trabajo.")
            ),
            remediation=(
                "Rota la credencial: hay que darla por comprometida. Después sácala "
                "del código a una variable de entorno o a un gestor de secretos, y "
                "si está en el historial de git, reescríbelo — borrarla del último "
                "commit no la quita de los anteriores."
            ),
            target=f"{ruta}:{linea}",
            severity=GRAVEDAD_POR_REGLA.get(regla, Severity.HIGH),
            confidence=Confidence.FIRM,
            cwe=["CWE-798"],
            owasp=["A07:2021"],
            evidence=[Evidence(
                kind=EvidenceKind.CODE,
                snippet=(h.get("Match") or "").strip()[:300],
                path=f"{ruta}:{linea}",
                meta={"regla": regla, "commit": commit, "autor": h.get("Author", "")},
            )],
            fingerprint_extra=f"{ruta}:{linea}",
            extra={"entropia": h.get("Entropy"), "commit": commit},
        )


def _ocultar(valor: str) -> str:
    """Lo justo para reconocerlo sin reproducirlo. El valor íntegro va en la
    evidencia, no en el titular que acaba en un ticket."""
    if len(valor) <= 8:
        return "*" * len(valor)
    # La máscara tiene largo fijo: un secreto largo —una clave privada, por
    # ejemplo— generaba una tira de asteriscos que desbordaba el informe a lo
    # ancho. Se añade la longitud real, que es la información que aporta.
    return f"{valor[:3]}{'*' * 8}{valor[-3:]} ({len(valor)} caracteres)"
