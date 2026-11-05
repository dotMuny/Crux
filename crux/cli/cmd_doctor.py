"""`crux doctor`: qué hay, qué falta y si la política de egress está sana.

Es lo primero que se ejecuta en una instalación nueva, y lo que se mira cuando un
escaneo se comporta raro. Sale con código distinto de cero si falta algo que
impide escanear, para poder encadenarlo en un script de instalación.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..adapters import all_adapters
from ..core import paths
from ..core.egress import clean_env, leaked_credential_vars

# Herramientas que Crux usa, con para qué sirve cada una y si es imprescindible.
TOOLS: tuple[tuple[str, str, bool], ...] = (
    ("nuclei", "motor de detección principal", True),
    ("nmap", "barrido de puertos y servicios", True),
    ("whatweb", "huella de tecnologías", False),
    ("ffuf", "descubrimiento de contenido", False),
    ("gobuster", "descubrimiento de contenido (alternativa)", False),
    ("nikto", "comprobaciones clásicas de servidor web", False),
    ("wapiti", "DAST activo", False),
    ("sqlmap", "inyección SQL (solo perfil agresivo)", False),
    ("sslscan", "estado de TLS", False),
    ("testssl.sh", "estado de TLS exhaustivo", False),
    ("wafw00f", "detección de WAF", False),
    ("dalfox", "XSS en contexto", False),
    ("semgrep", "análisis estático del código", True),
    ("gitleaks", "secretos en el código", True),
    ("syft", "SBOM CycloneDX", False),
    ("trivy", "dependencias vulnerables, sin red", True),
    ("chromedriver", "crawler con navegador", True),
)

# Herramientas que salen a internet por defecto y por tanto NO deben usarse sin
# una política de egress declarada. `doctor` verifica que la tenemos puesta.
PHONES_HOME = {"nuclei", "wapiti", "nikto", "semgrep", "trivy"}


@dataclass(slots=True)
class Check:
    ok: bool
    label: str
    detail: str = ""

    @property
    def mark(self) -> str:
        return "[green]✓[/green]" if self.ok else "[red]✗[/red]"


def _tool_rows(console: Console) -> tuple[Table, list[str]]:
    table = Table("", "herramienta", "para qué", "versión", box=None, pad_edge=False)
    missing_required: list[str] = []
    for binary, purpose, required in TOOLS:
        path = shutil.which(binary)
        if path:
            from ..core.runner import tool_version, version_flags

            version = tool_version(binary, (binary, *version_flags(binary))) or "?"
            table.add_row("[green]✓[/green]", binary, purpose, _trim(version))
        else:
            mark = "[red]✗[/red]" if required else "[yellow]–[/yellow]"
            note = "imprescindible" if required else "opcional"
            table.add_row(mark, binary, purpose, f"[dim]no instalada ({note})[/dim]")
            if required:
                missing_required.append(binary)
    return table, missing_required


def _data_checks() -> list[Check]:
    """Datos locales sin los que un escaneo no puede ser offline."""
    checks: list[Check] = []

    templates = paths.nuclei_templates_dir()
    fallback = Path.home() / ".local" / "nuclei-templates"
    chosen = templates if templates.is_dir() else fallback
    count = sum(1 for _ in chosen.rglob("*.yaml")) if chosen.is_dir() else 0
    checks.append(
        Check(
            count > 0,
            "plantillas de nuclei",
            f"{count} plantillas en {chosen}" if count
            else f"ninguna. Ejecuta: nuclei -ut -ud {templates}",
        )
    )

    seclists = Path("/usr/share/seclists")
    checks.append(
        Check(seclists.is_dir(), "wordlists (SecLists)",
              str(seclists) if seclists.is_dir() else "falta: apt install seclists")
    )

    browser = next(
        (p for p in ("/usr/bin/chromium", "/usr/bin/chromium-browser", "/usr/bin/google-chrome")
         if Path(p).exists()),
        None,
    )
    checks.append(
        Check(browser is not None, "navegador para el crawler",
              browser or "falta Chromium: apt install chromium")
    )

    vulndb = paths.vulndb_dir()
    has_db = (vulndb / "db").is_dir()
    checks.append(
        Check(has_db, "base de vulnerabilidades de trivy",
              str(vulndb) if has_db
              else f"falta. Ejecuta: trivy --cache-dir {vulndb} image --download-db-only")
    )

    reglas = paths.data_dir() / "semgrep-rules"
    n_reglas = sum(1 for _ in reglas.rglob("*.yaml")) if reglas.is_dir() else 0
    checks.append(
        Check(n_reglas > 0, "reglas de semgrep",
              f"{n_reglas} reglas en {reglas}" if n_reglas
              else "faltan. Las clona install/bootstrap.sh fijadas a un commit")
    )
    return checks


def _egress_checks() -> list[Check]:
    """Autocomprobación de la propia política de egress.

    No mira la red: comprueba que las salvaguardas están puestas. Que de verdad
    no haya tráfico saliente lo demuestra `tests/test_egress.py`, que ejecuta las
    herramientas en un namespace de red sin ruta por defecto.
    """
    checks: list[Check] = []

    env = clean_env()
    leaked = leaked_credential_vars(env)
    checks.append(
        Check(not leaked, "entorno de subprocesos sin credenciales",
              "ninguna variable sensible se propaga" if not leaked
              else f"¡se filtran! {', '.join(leaked)}")
    )
    proxies = [v for v in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY") if v in env]
    checks.append(
        Check(not proxies, "sin proxies heredados",
              f"NO_PROXY={env.get('NO_PROXY')}" if not proxies
              else f"heredados: {proxies}")
    )

    # Cada adaptador de una herramienta que llama a casa debe declarar política.
    adapters = all_adapters()
    undeclared = [
        name for name, cls in adapters.items()
        if name in PHONES_HOME and not cls.egress.required and not cls.egress.forbidden
    ]
    covered = sorted(set(adapters) & PHONES_HOME)
    checks.append(
        Check(
            not undeclared,
            "política de egress declarada",
            f"declarada en: {', '.join(covered) or 'ninguno todavía'}" if not undeclared
            else f"sin política: {', '.join(undeclared)}",
        )
    )
    return checks


def _verify_manifest(console: Console) -> bool:
    """Comprueba los SHA256 de `install/manifest.toml` contra el disco."""
    manifest_path = Path(__file__).resolve().parents[2] / "install" / "manifest.toml"
    if not manifest_path.exists():
        console.print(
            f"[yellow]–[/yellow] no hay manifiesto en {manifest_path}; "
            "nada que verificar todavía"
        )
        return True

    data = tomllib.loads(manifest_path.read_text(encoding="utf-8"))
    table = Table("", "artefacto", "esperado", "obtenido", box=None)
    all_ok = True
    for name, entry in (data.get("artifact") or {}).items():
        path = Path(entry["path"]).expanduser()
        expected = entry.get("sha256", "")
        if not path.exists():
            table.add_row("[red]✗[/red]", name, expected[:16], "[red]no existe[/red]")
            all_ok = False
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        ok = actual == expected
        all_ok &= ok
        table.add_row(
            "[green]✓[/green]" if ok else "[red]✗[/red]",
            name, expected[:16], actual[:16] if not ok else "[green]coincide[/green]",
        )
    console.print(table)
    return all_ok


@click.command("doctor")
@click.option("--verify-supply-chain", is_flag=True,
              help="Recalcula los SHA256 de install/manifest.toml y los compara.")
def doctor(verify_supply_chain: bool) -> None:
    """Comprueba el entorno: herramientas, datos locales y política de egress."""
    console = Console()
    console.print(
        Panel.fit(
            f"[bold]crux doctor[/bold]\n"
            f"python {sys.version.split()[0]}  ·  datos en {paths.data_dir()}",
            border_style="cyan",
        )
    )

    tools_table, missing_required = _tool_rows(console)
    console.print("\n[bold]Herramientas[/bold]")
    console.print(tools_table)

    console.print("\n[bold]Datos locales[/bold]")
    data_checks = _data_checks()
    for check in data_checks:
        console.print(f"{check.mark} {check.label}: [dim]{check.detail}[/dim]")

    console.print("\n[bold]Egress[/bold]")
    egress_checks = _egress_checks()
    for check in egress_checks:
        console.print(f"{check.mark} {check.label}: [dim]{check.detail}[/dim]")

    supply_ok = True
    if verify_supply_chain:
        console.print("\n[bold]Cadena de suministro[/bold]")
        supply_ok = _verify_manifest(console)

    blockers: list[str] = []
    if missing_required:
        blockers.append(f"herramientas imprescindibles ausentes: {', '.join(missing_required)}")
    blockers += [c.label for c in data_checks[:1] if not c.ok]      # plantillas de nuclei
    blockers += [c.label for c in egress_checks if not c.ok]
    if not supply_ok:
        blockers.append("el manifiesto no cuadra")

    console.print()
    if blockers:
        console.print(
            Panel.fit(
                "[bold red]No se puede escanear todavía[/bold red]\n"
                + "\n".join(f"· {b}" for b in blockers),
                border_style="red",
            )
        )
        raise SystemExit(1)
    console.print(Panel.fit("[bold green]Listo para escanear[/bold green]",
                            border_style="green"))


def _trim(text: str, width: int = 44) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[: width - 1] + "…"
