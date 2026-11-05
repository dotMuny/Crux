"""Adaptador de semgrep: análisis estático del código fuente.

Dos cosas que no son opcionales:

- `--metrics=off`. Semgrep envía estadísticas de uso por defecto, que incluyen
  identificadores del proyecto analizado.
- `--config` apuntando a un árbol de reglas **local**. Un `--config=auto` o
  `p/default` descarga reglas del registry remoto en cada ejecución: además de
  ser tráfico saliente, significa que dos escaneos del mismo código pueden dar
  resultados distintos sin que nada haya cambiado.

Las reglas se clonan una vez en el bootstrap, fijadas a un commit, y a partir
de ahí el análisis es reproducible.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from ..core import paths
from ..core.egress import EgressPolicy
from ..core.findings import Evidence, EvidenceKind, Finding
from ..core.runner import ToolRun
from ..core.severity import Confidence, Severity, from_tool
from .base import Adapter, ScanContext, register

_SEMGREP_EGRESS = EgressPolicy(
    required=("--metrics=off", "--json", "--quiet"),
    forbidden=("--config=auto", "--config=p/default", "--config=p/ci",
               "--config=r/all", "--enable-version-check", "--publish",
               "--app-url", "--supply-chain", "--pro"),
    reasons={
        "--metrics=off": "semgrep envía estadísticas de uso que incluyen datos del proyecto",
        "--json": "la salida JSON es la que parseamos",
        "--quiet": "sin barra de progreso en la salida que parseamos",
        "--config=auto": "descarga reglas del registry en cada ejecución",
        "--config=p/default": "descarga reglas del registry en cada ejecución",
        "--publish": "subiría los hallazgos a la nube de semgrep",
        "--pro": "el motor pro exige contactar con su servicio de licencias",
    },
)

# Los identificadores de regla de semgrep son rutas largas; de ellas se saca el
# CWE cuando la propia regla lo declara en sus metadatos.
SEVERIDAD_SEMGREP = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM,
                     "INFO": Severity.LOW, "INVENTORY": Severity.INFO,
                     "EXPERIMENT": Severity.INFO}

# Lenguajes que analizamos, según lo que usa la organización.
LENGUAJES = ("python", "javascript", "typescript", "java", "php", "csharp")

# Directorios que semgrep omite por su cuenta, comprobado empíricamente con
# esta versión. Para análisis estático la exclusión es razonable —ese código no
# se despliega—, pero callarlo no lo es: un informe que dice «sin hallazgos»
# sobre código que nadie miró es peor que no informar.
OMITIDOS_POR_DEFECTO = (".venv", "build", "dist", "node_modules", "test",
                        "tests", "vendor")


@register
class SemgrepAdapter(Adapter):
    name = "semgrep"
    binary = "semgrep"
    kind = "code"
    egress = _SEMGREP_EGRESS
    version_argv = ("--version",)
    # semgrep devuelve 1 cuando encuentra hallazgos.
    ok_exit_codes = (0, 1)

    def reglas(self) -> Path | None:
        """Árbol de reglas local. Sin él no se ejecuta."""
        local = paths.data_dir() / "semgrep-rules"
        return local if local.is_dir() else None

    def build_argv(self, ctx: ScanContext) -> list[str] | None:
        raiz = ctx.ruta
        if raiz is None or not raiz.exists():
            return None
        reglas = self.reglas()
        if reglas is None:
            raise RuntimeError(
                "no hay reglas de semgrep instaladas. Ejecuta install/bootstrap.sh, "
                "que las clona fijadas a un commit. No se usa --config=auto porque "
                "descarga del registry remoto en cada ejecución."
            )

        # Solo los subdirectorios de los lenguajes que la organización usa:
        # el árbol completo son más de dos mil reglas, muchas para lenguajes
        # que aquí no aparecen.
        configs: list[str] = []
        for lenguaje in LENGUAJES:
            carpeta = reglas / lenguaje
            if carpeta.is_dir():
                configs += ["--config", str(carpeta)]

        return [
            "semgrep", "scan",
            "--metrics=off",            # sin telemetría
            "--json",
            "--quiet",
            "--no-git-ignore",          # el fixture y muchos repos internos no son git
            "--timeout", "30",
            "--max-target-bytes", "2000000",
            *configs,
            str(raiz),
        ]

    def parse(self, run: ToolRun, ctx: ScanContext) -> Iterable[Finding]:
        salida = run.text().strip()
        datos, aviso = self.leer_json(salida, vacio={})
        if aviso is not None:
            yield aviso
        datos = datos or {}

        raiz = ctx.ruta
        for resultado in datos.get("results", []):
            yield self._a_finding(resultado, raiz)

        aviso = self._aviso_de_cobertura(datos, raiz)
        if aviso is not None:
            yield aviso

    def _aviso_de_cobertura(self, datos: dict, raiz: Path | None) -> Finding | None:
        """Deja constancia de qué quedó sin analizar.

        No es un hallazgo de seguridad, es un hallazgo sobre el propio escaneo:
        quien lea el informe tiene que poder distinguir «aquí no hay nada» de
        «aquí no se miró».
        """
        if raiz is None:
            return None
        analizados = len(datos.get("paths", {}).get("scanned", []))
        presentes = sorted({
            d.name for d in raiz.rglob("*")
            if d.is_dir() and d.name in OMITIDOS_POR_DEFECTO
        })
        if not presentes:
            return None

        return Finding(
            source=self.name,
            check_id="cobertura-parcial",
            title=f"{len(presentes)} directorio(s) quedaron fuera del análisis estático",
            description=(
                f"semgrep analizó {analizados} fichero(s) y omitió por configuración "
                f"propia: {', '.join(presentes)}. Para código de pruebas o "
                "dependencias de terceros la omisión es razonable —no se despliega—, "
                "pero conviene saberlo: la ausencia de hallazgos ahí no significa "
                "que no los haya."
            ),
            remediation=(
                "Si alguno de esos directorios contiene código que sí se despliega, "
                "analízalo apuntando directamente a él."
            ),
            target=str(raiz),
            severity=Severity.INFO,
            confidence=Confidence.CERTAIN,
            extra={"omitidos": presentes, "ficheros_analizados": analizados},
        )

    def _a_finding(self, resultado: dict, raiz: Path | None) -> Finding:
        extra = resultado.get("extra") or {}
        meta = extra.get("metadata") or {}
        ruta = resultado.get("path", "")
        if raiz is not None:
            try:
                ruta = str(Path(ruta).relative_to(raiz))
            except ValueError:
                pass
        linea = (resultado.get("start") or {}).get("line", 0)
        regla = resultado.get("check_id", "desconocida")
        # El identificador de semgrep lleva toda la ruta de la regla; para el
        # título basta su último tramo, que es el nombre legible.
        nombre_corto = regla.rsplit(".", 1)[-1]

        cwe = meta.get("cwe") or []
        if isinstance(cwe, str):
            cwe = [cwe]
        owasp = meta.get("owasp") or []
        if isinstance(owasp, str):
            owasp = [owasp]

        return Finding(
            source=self.name,
            check_id=nombre_corto,
            title=(meta.get("shortDescription") or nombre_corto.replace("-", " ")).strip(),
            description=(extra.get("message") or "").strip(),
            remediation=(meta.get("fix") or meta.get("fix_regex", {}).get("replacement")
                         or "Revisa el fragmento señalado y aplica la corrección "
                            "que indique la referencia de la regla.").strip()
            if isinstance(meta.get("fix"), str) or meta.get("fix") is None else "",
            # Para el código, el objetivo es fichero:línea, no una URL.
            target=f"{ruta}:{linea}",
            severity=SEVERIDAD_SEMGREP.get(
                str(extra.get("severity", "")).upper(),
                from_tool(extra.get("severity")),
            ),
            # El análisis estático señala un patrón, no demuestra explotabilidad.
            confidence=Confidence.FIRM if meta.get("confidence") != "LOW"
            else Confidence.TENTATIVE,
            cwe=[c.split(":")[0].strip() if ":" in c else c for c in cwe][:3],
            owasp=[o.split(":")[0].strip() if ":" in o else o for o in owasp][:3],
            references=[r for r in (meta.get("references") or [])][:4],
            tags=[t for t in (meta.get("technology") or []) if isinstance(t, str)],
            evidence=[Evidence(
                kind=EvidenceKind.CODE,
                snippet=(extra.get("lines") or "").strip() or None,
                path=f"{ruta}:{linea}",
                meta={"regla": regla, "lenguaje": meta.get("technology")},
            )],
            # Dos hallazgos de la misma regla en líneas distintas son dos
            # hallazgos: se arreglan por separado.
            fingerprint_extra=str(linea),
            extra={"regla_completa": regla, "categoria": meta.get("category")},
        )
