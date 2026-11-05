#!/usr/bin/env bash
#
# Instalación de Crux. Es el ÚNICO momento en que se usa internet.
#
# A partir de aquí la herramienta funciona sin salida: las plantillas de nuclei,
# las reglas de semgrep y la base de vulnerabilidades quedan en local, y en
# tiempo de escaneo está prohibido descargarlas (ver docs/decisiones.md).
#
# Orden de preferencia para cada herramienta, según la decisión 4:
#   1. Repositorio firmado de la distribución
#   2. Módulos de Go, cuyo checksum DB es un log de transparencia
#   3. PyPI con versión clavada
set -euo pipefail

AZUL=$'\033[36m'; VERDE=$'\033[32m'; AMBAR=$'\033[33m'; FIN=$'\033[0m'
paso()  { printf '%s==>%s %s\n' "$AZUL" "$FIN" "$1"; }
bien()  { printf '%s  ✓%s %s\n' "$VERDE" "$FIN" "$1"; }
aviso() { printf '%s  –%s %s\n' "$AMBAR" "$FIN" "$1"; }

DATOS="${XDG_DATA_HOME:-$HOME/.local/share}/crux"
RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Versiones clavadas. Cambiarlas es una decisión, no un efecto secundario.
SEMGREP_VERSION="1.182.1"
SEMGREP_RULES_COMMIT="16b9e6d45f10649f6a531ec4838ed9924372c3bc"

mkdir -p "$DATOS"

# ── 1. Herramientas del repositorio firmado ─────────────────────────────────
paso "Herramientas de la distribución (firmadas por su clave GPG)"
APT_NECESARIAS=(nuclei nmap whatweb ffuf gobuster nikto wapiti sqlmap sslscan
                wafw00f chromium chromium-driver seclists gitleaks syft trivy)
FALTAN=()
for p in "${APT_NECESARIAS[@]}"; do
  dpkg -s "$p" >/dev/null 2>&1 || FALTAN+=("$p")
done
if [ ${#FALTAN[@]} -gt 0 ]; then
  echo "    instalando: ${FALTAN[*]}"
  sudo apt-get install -y "${FALTAN[@]}"
fi
bien "${#APT_NECESARIAS[@]} paquetes presentes"

# ── 2. semgrep, con versión clavada ─────────────────────────────────────────
paso "semgrep $SEMGREP_VERSION"
if command -v semgrep >/dev/null && semgrep --version 2>/dev/null | grep -q "^$SEMGREP_VERSION$"; then
  bien "ya instalado en la versión esperada"
else
  pipx install --force "semgrep==$SEMGREP_VERSION"
  bien "instalado"
fi

# ── 3. Datos locales ────────────────────────────────────────────────────────
paso "Plantillas de nuclei"
# OJO: aquí NO se pasa -duc. Ese flag desactiva la comprobación de
# actualizaciones del binario Y de las plantillas, así que con él la descarga
# no hace nada y el directorio queda vacío sin dar error.
nuclei -ut -ud "$DATOS/nuclei-templates"
bien "$(find "$DATOS/nuclei-templates" -name '*.yaml' 2>/dev/null | wc -l) plantillas"

paso "Reglas de semgrep (fijadas a un commit)"
if [ -d "$DATOS/semgrep-rules/.git" ]; then
  git -C "$DATOS/semgrep-rules" fetch --quiet --depth 1 origin "$SEMGREP_RULES_COMMIT" 2>/dev/null || true
  git -C "$DATOS/semgrep-rules" checkout --quiet "$SEMGREP_RULES_COMMIT" 2>/dev/null || true
else
  git clone --quiet https://github.com/semgrep/semgrep-rules.git "$DATOS/semgrep-rules"
  git -C "$DATOS/semgrep-rules" checkout --quiet "$SEMGREP_RULES_COMMIT"
fi
ACTUAL="$(git -C "$DATOS/semgrep-rules" rev-parse HEAD)"
if [ "$ACTUAL" != "$SEMGREP_RULES_COMMIT" ]; then
  aviso "el árbol de reglas está en $ACTUAL, no en el commit fijado"
else
  bien "$(find "$DATOS/semgrep-rules" -name '*.yaml' | wc -l) reglas en $SEMGREP_RULES_COMMIT"
fi

paso "Base de vulnerabilidades de trivy"
trivy --cache-dir "$DATOS/vulndb" image --download-db-only
bien "descargada en $DATOS/vulndb"

# ── 4. Navegador de Playwright: no hace falta ───────────────────────────────
# El crawler usa Selenium con el chromium-driver del sistema. No se descargan
# navegadores: ver docs/decisiones.md §6.

# ── 5. Paquete Python ───────────────────────────────────────────────────────
paso "Paquete crux"
if [ ! -d "$RAIZ/.venv" ]; then
  # --system-site-packages reutiliza lo que Kali ya trae —FastAPI, SQLAlchemy,
  # Playwright, WeasyPrint— en vez de descargarlo otra vez.
  python3 -m venv --system-site-packages "$RAIZ/.venv"
fi
"$RAIZ/.venv/bin/python" -m pip install --quiet -e "$RAIZ"
bien "instalado en $RAIZ/.venv"

# ── 6. Interfaz web ─────────────────────────────────────────────────────────
paso "Interfaz web"
if [ -d "$RAIZ/crux/web/dist" ]; then
  bien "ya compilada (el dist se distribuye versionado: npm no toca este equipo)"
else
  aviso "no hay dist compilado. Si éste es el equipo de build:"
  echo "       cd $RAIZ/frontend && corepack pnpm install && corepack pnpm build"
fi

# ── 7. La orden en el PATH ──────────────────────────────────────────────────
# El lanzador que genera pip vive dentro del entorno virtual, así que sin esto
# la orden sólo existe para quien lo active: en una terminal normal, `crux web`
# responde «command not found». Un enlace en ~/.local/bin —donde Debian espera
# los binarios del usuario— la deja disponible sin tocar el sistema ni pedir
# sudo. No se escribe en /usr/local/bin a propósito: eso sí es del sistema.
paso "La orden crux"
BIN="$HOME/.local/bin"
mkdir -p "$BIN"
if [ -e "$BIN/crux" ] &&
   [ "$(readlink -f "$BIN/crux")" != "$(readlink -f "$RAIZ/.venv/bin/crux")" ]; then
  aviso "$BIN/crux ya existe y apunta a otro sitio: se deja como está"
  aviso "usa $RAIZ/.venv/bin/crux, o rehaz el enlace a mano si es lo que quieres"
else
  ln -sfn "$RAIZ/.venv/bin/crux" "$BIN/crux"
  bien "enlazada en $BIN/crux"
fi
case ":$PATH:" in
  *":$BIN:"*) ;;
  # Debian añade ~/.local/bin desde ~/.profile sólo si el directorio ya existía
  # al iniciar sesión. Si lo acabamos de crear, no estará hasta volver a entrar.
  *) aviso "$BIN no está en tu PATH: abre una sesión nueva, o añádelo a tu shell" ;;
esac

# ── 8. Comprobación final ───────────────────────────────────────────────────
paso "Comprobando la instalación"
"$RAIZ/.venv/bin/crux" doctor
