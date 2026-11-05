"""Adaptador de trivy: dependencias con vulnerabilidad conocida.

Se eligió trivy sobre osv-scanner porque está en el repositorio firmado de
Kali —la preferencia que fija docs/decisiones.md §4— y porque su base de datos
se descarga entera y se consulta en local. osv-scanner habría exigido
`go install` y bases aparte para lo mismo.

En ejecución no toca la red: `--skip-db-update` impide que compruebe si hay
base nueva y `--offline-scan` evita que consulte servicios externos para
resolver dependencias. La base se descarga en el bootstrap.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

from ..core import paths
from ..core.egress import EgressPolicy
from ..core.findings import Evidence, EvidenceKind, Finding
from ..core.runner import ToolRun
from ..core.severity import Confidence, Severity, from_cvss_vector, from_tool
from .base import Adapter, ScanContext, register

_TRIVY_EGRESS = EgressPolicy(
    required=("--skip-db-update", "--offline-scan", "--format", "--quiet"),
    forbidden=("--download-db-only", "--download-java-db-only", "--server",
               "--token", "--reset"),
    reasons={
        "--skip-db-update": "sin esto trivy comprueba y descarga base nueva en cada ejecución",
        "--offline-scan": "sin esto consulta servicios externos para resolver dependencias",
        "--format": "la salida JSON es la que parseamos",
        "--quiet": "sin barra de progreso en la salida",
        "--server": "delegar en un servidor remoto es tráfico saliente",
        "--download-db-only": "descargar la base es tarea del bootstrap, no del escaneo",
    },
)


@register
class TrivyAdapter(Adapter):
    name = "trivy"
    binary = "trivy"
    kind = "code"
    egress = _TRIVY_EGRESS
    version_argv = ("--version",)
    ok_exit_codes = (0,)

    def base_de_datos(self) -> Path | None:
        db = paths.vulndb_dir()
        return db if (db / "db").is_dir() else None

    def build_argv(self, ctx: ScanContext) -> list[str] | None:
        raiz = ctx.ruta
        if raiz is None or not raiz.exists():
            return None
        if self.base_de_datos() is None:
            raise RuntimeError(
                f"no hay base de vulnerabilidades en {paths.vulndb_dir()}. "
                "Ejecuta install/bootstrap.sh con red disponible: en tiempo de "
                "escaneo la base no se descarga, por política."
            )
        salida = ctx.artifact("trivy.json")
        return [
            "trivy", "fs",
            "--cache-dir", str(paths.vulndb_dir()),
            "--scanners", "vuln",
            "--skip-db-update",      # no comprueba si hay base nueva
            "--offline-scan",        # no consulta servicios externos
            "--format", "json",
            "--quiet",
            "--output", str(salida),
            "--severity", "UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL",
            str(raiz),
        ]

    def parse(self, run: ToolRun, ctx: ScanContext) -> Iterable[Finding]:
        salida = ctx.artifact("trivy.json")
        datos, aviso = self.leer_json(salida, vacio={})
        if aviso is not None:
            yield aviso
        datos = datos or {}

        raiz = ctx.ruta
        for resultado in datos.get("Results") or []:
            manifiesto = resultado.get("Target", "")
            if raiz is not None:
                try:
                    manifiesto = str(Path(manifiesto).relative_to(raiz))
                except ValueError:
                    pass
            # Se agrupa por paquete, no por CVE. Una versión antigua de
            # jackson-databind arrastra setenta CVE: setenta filas para una
            # sola acción —actualizar— dejan el informe ilegible y esconden
            # los demás hallazgos. El paquete es la unidad de corrección.
            por_paquete: dict[tuple[str, str], list[dict]] = {}
            for vuln in resultado.get("Vulnerabilities") or []:
                clave = (vuln.get("PkgName", ""), vuln.get("InstalledVersion", ""))
                por_paquete.setdefault(clave, []).append(vuln)

            for (paquete, version), vulns in por_paquete.items():
                yield self._a_finding(paquete, version, vulns, manifiesto,
                                      resultado.get("Type", ""))

        aviso = self._aviso_de_cobertura(ctx.ruta, datos)
        if aviso is not None:
            yield aviso

    def _a_finding(self, paquete: str, instalada: str, vulns: list[dict],
                   manifiesto: str, ecosistema: str) -> Finding:
        # El peor CVE del grupo marca la severidad y el vector: es el que
        # determina la urgencia de actualizar.
        peor = max(vulns, key=lambda v: int(from_tool(v.get("Severity"))))
        severidad = from_tool(peor.get("Severity"))

        vector, puntuacion = None, None
        for fuente in (peor.get("CVSS") or {}).values():
            vector = fuente.get("V3Vector") or vector
            puntuacion = fuente.get("V3Score") or puntuacion
            if vector:
                break
        if vector and puntuacion is None:
            calculado = from_cvss_vector(vector)
            puntuacion = calculado[1] if calculado else None

        cves = sorted({v.get("VulnerabilityID", "") for v in vulns if v.get("VulnerabilityID")})
        # La versión corregida útil es la más alta que arregle el peor CVE.
        correcciones = sorted({v.get("FixedVersion", "") for v in vulns if v.get("FixedVersion")})
        cwes = sorted({c for v in vulns for c in (v.get("CweIDs") or [])})

        return Finding(
            source=self.name,
            check_id=f"dependencia-vulnerable:{paquete}",
            title=(f"{paquete} {instalada} acumula {len(cves)} vulnerabilidad(es) conocida(s)"
                   if len(cves) > 1 else
                   f"{paquete} {instalada} tiene {cves[0] if cves else 'una vulnerabilidad'}"),
            description=(
                (peor.get("Title") or peor.get("Description") or "").strip()[:400]
                + f"\n\nLa más grave es {peor.get('VulnerabilityID', '?')} "
                  f"({severidad.label}). "
                + (f"En total: {', '.join(cves[:12])}"
                   + (f" y {len(cves) - 12} más." if len(cves) > 12 else ".")
                   if len(cves) > 1 else "")
                + (f"\nDeclarada en {manifiesto}." if manifiesto else "")
            ),
            remediation=(
                f"Actualiza {paquete} a {correcciones[-1]} o posterior."
                if correcciones else
                f"No hay versión corregida publicada para {paquete}. Valora "
                "sustituir la dependencia o aislar su uso."
            ),
            target=f"{manifiesto}:{paquete}",
            severity=severidad,
            # La coincidencia es por versión declarada: que la dependencia esté
            # presente no prueba que el código llegue a la ruta vulnerable.
            confidence=Confidence.FIRM,
            cvss_vector=vector,
            cvss_score=puntuacion,
            cwe=cwes[:3],
            references=[r for r in (peor.get("References") or [])][:3],
            tags=[ecosistema] if ecosistema else [],
            evidence=[Evidence(
                kind=EvidenceKind.CODE,
                snippet=f"{paquete} {instalada}"
                        + (f"  →  {correcciones[-1]}" if correcciones else
                           "  →  sin versión corregida")
                        + "\n\n" + "\n".join(
                            f"  {v.get('VulnerabilityID', '?'):<18} "
                            f"{str(v.get('Severity', '')).lower():<9} "
                            f"{(v.get('Title') or '')[:70]}"
                            for v in sorted(vulns,
                                            key=lambda x: -int(from_tool(x.get("Severity"))))[:15]
                        ),
                path=manifiesto,
                meta={"cves": cves, "ecosistema": ecosistema},
            )],
            fingerprint_extra=f"{paquete}@{instalada}",
            extra={"paquete": paquete, "instalada": instalada,
                   "corregida": correcciones[-1] if correcciones else "",
                   "ecosistema": ecosistema, "cves": cves, "total_cves": len(cves)},
        )

    def _aviso_de_cobertura(self, raiz: Path | None, datos: dict) -> Finding | None:
        """Manifiestos sin fichero de bloqueo: ahí trivy no puede mirar.

        Comprobado con esta versión: `package.json`, `composer.json` y los
        `.csproj` por sí solos no producen hallazgos — hace falta el lockfile
        que fija las versiones reales del árbol de dependencias. Sin decirlo,
        un informe limpio sobre un proyecto npm parecería una buena noticia
        cuando en realidad nadie ha mirado.
        """
        if raiz is None:
            return None

        PAREJAS = {
            "package.json": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"),
            "composer.json": ("composer.lock",),
            "Gemfile": ("Gemfile.lock",),
            "pyproject.toml": ("poetry.lock", "uv.lock", "requirements.txt"),
        }
        huerfanos: list[str] = []
        for manifiesto, bloqueos in PAREJAS.items():
            for encontrado in raiz.rglob(manifiesto):
                if not any((encontrado.parent / b).exists() for b in bloqueos):
                    huerfanos.append(str(encontrado.relative_to(raiz)))
        for csproj in raiz.rglob("*.csproj"):
            if not (csproj.parent / "packages.lock.json").exists():
                huerfanos.append(str(csproj.relative_to(raiz)))

        if not huerfanos:
            return None
        return Finding(
            source=self.name,
            check_id="sin-fichero-de-bloqueo",
            title=f"{len(huerfanos)} manifiesto(s) sin fichero de bloqueo",
            description=(
                "Estos manifiestos declaran dependencias pero no hay lockfile que "
                "fije las versiones instaladas, así que el análisis no ha podido "
                f"mirarlas: {', '.join(huerfanos[:8])}"
                + (f" y {len(huerfanos) - 8} más." if len(huerfanos) > 8 else ".")
                + " La ausencia de hallazgos en esos ecosistemas no significa que "
                "no los haya."
            ),
            remediation=(
                "Versiona el fichero de bloqueo junto al manifiesto. Además de "
                "permitir el análisis, es lo que hace reproducible la instalación."
            ),
            target=str(raiz),
            severity=Severity.MEDIUM,
            confidence=Confidence.CERTAIN,
            cwe=["CWE-1104"],
            extra={"manifiestos": huerfanos},
        )
