#!/usr/bin/env bash
#
# Construye un paquete de instalación autocontenido.
#
# Se ejecuta UNA vez, en la máquina de build y con red. Produce un tarball que
# se copia al Kali de cada analista —por repositorio interno o por USB— y se
# instala sin salida a internet.
#
# Lo que va dentro, y por qué:
#   · el código y el dist ya compilado, para que npm no toque el equipo destino
#   · las ruedas de Python, descargadas una vez
#   · las plantillas de nuclei, las reglas de semgrep y la base de trivy
#   · un manifiesto con el SHA256 de cada pieza, que `crux doctor
#     --verify-supply-chain` recalcula en destino
set -euo pipefail

AZUL=$'\033[36m'; VERDE=$'\033[32m'; AMBAR=$'\033[33m'; FIN=$'\033[0m'
paso()  { printf '%s==>%s %s\n' "$AZUL" "$FIN" "$1"; }
bien()  { printf '%s  ✓%s %s\n' "$VERDE" "$FIN" "$1"; }
aviso() { printf '%s  –%s %s\n' "$AMBAR" "$FIN" "$1"; }

RAIZ="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATOS="${XDG_DATA_HOME:-$HOME/.local/share}/crux"
SALIDA="${1:-$RAIZ/dist}"
VERSION="$(git -C "$RAIZ" describe --tags --always 2>/dev/null || date +%Y%m%d)"
NOMBRE="crux-$VERSION"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$SALIDA" "$TMP/$NOMBRE"
paso "Preparando $NOMBRE"

# ── Código ──────────────────────────────────────────────────────────────────
paso "Código y artefactos"
git -C "$RAIZ" archive --format=tar HEAD | tar -x -C "$TMP/$NOMBRE"
if [ -d "$RAIZ/crux/web/dist" ]; then
  mkdir -p "$TMP/$NOMBRE/crux/web"
  cp -r "$RAIZ/crux/web/dist" "$TMP/$NOMBRE/crux/web/"
  bien "interfaz compilada incluida ($(du -sh "$RAIZ/crux/web/dist" | cut -f1))"
else
  aviso "sin dist compilado: el destino se quedará sin interfaz web"
fi

# ── Ruedas de Python ────────────────────────────────────────────────────────
paso "Ruedas de Python"
# Se descargan aquí, una vez, para que el destino no necesite PyPI. Las que
# Kali ya trae de serie no hacen falta: el venv se crea con
# --system-site-packages.
mkdir -p "$TMP/$NOMBRE/wheelhouse"
"$RAIZ/.venv/bin/python" -m pip download --quiet --dest "$TMP/$NOMBRE/wheelhouse" \
  "$RAIZ" 2>/dev/null || aviso "algunas ruedas de ejecución no se pudieron descargar"
# setuptools y wheel por si el sistema de destino no los trae.
"$RAIZ/.venv/bin/python" -m pip download --quiet --dest "$TMP/$NOMBRE/wheelhouse" \
  "setuptools>=77" wheel 2>/dev/null || true
bien "$(find "$TMP/$NOMBRE/wheelhouse" -name '*.whl' -o -name '*.tar.gz' | wc -l) paquetes"

# ── Datos ───────────────────────────────────────────────────────────────────
paso "Datos locales"
mkdir -p "$TMP/$NOMBRE/datos"
for pieza in nuclei-templates semgrep-rules vulndb; do
  if [ -d "$DATOS/$pieza" ]; then
    # El .git de las reglas no aporta nada en destino y pesa.
    tar -C "$DATOS" --exclude='.git' -czf "$TMP/$NOMBRE/datos/$pieza.tar.gz" "$pieza"
    bien "$pieza ($(du -h "$TMP/$NOMBRE/datos/$pieza.tar.gz" | cut -f1))"
  else
    aviso "falta $pieza: ejecuta install/bootstrap.sh antes de empaquetar"
  fi
done

# ── Manifiesto ──────────────────────────────────────────────────────────────
paso "Manifiesto con SHA256"
{
  echo "# Manifiesto de $NOMBRE"
  echo "# Generado el $(date -Iseconds) en $(hostname)"
  echo "#"
  echo "# \`crux doctor --verify-supply-chain\` recalcula estos hashes en destino."
  echo "# Si alguno no cuadra, el paquete se ha alterado entre la máquina de"
  echo "# build y el equipo del analista."
  echo
  echo "[meta]"
  echo "version = \"$VERSION\""
  echo "commit = \"$(git -C "$RAIZ" rev-parse HEAD 2>/dev/null || echo desconocido)\""
  echo "generado = \"$(date -Iseconds)\""
  echo
  while IFS= read -r f; do
    rel="${f#$TMP/$NOMBRE/}"
    clave="$(echo "$rel" | tr './-' '___')"
    echo "[artifact.$clave]"
    echo "path = \"$rel\""
    echo "sha256 = \"$(sha256sum "$f" | cut -d' ' -f1)\""
    echo "bytes = $(stat -c%s "$f")"
    echo
  done < <(find "$TMP/$NOMBRE/datos" "$TMP/$NOMBRE/wheelhouse" -type f 2>/dev/null | sort)
} > "$TMP/$NOMBRE/install/manifest.toml"
bien "$(grep -c '^\[artifact\.' "$TMP/$NOMBRE/install/manifest.toml") artefactos con hash"

# ── Instalador de destino ───────────────────────────────────────────────────
cat > "$TMP/$NOMBRE/instalar.sh" <<'DESTINO'
#!/usr/bin/env bash
# Instalación en destino. No usa internet.
set -euo pipefail
AQUI="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DATOS="${XDG_DATA_HOME:-$HOME/.local/share}/crux"
mkdir -p "$DATOS"

echo "==> Datos locales"
for t in "$AQUI"/datos/*.tar.gz; do
  [ -e "$t" ] || continue
  # --no-same-owner: los ficheros son del usuario que instala, no de quien
  # empaquetó. Sin esto, tar intenta restaurar un uid que en el equipo de
  # destino puede no existir y la extracción falla entera.
  tar --no-same-owner -xzf "$t" -C "$DATOS"
  echo "  ✓ $(basename "$t" .tar.gz)"
done

echo "==> Paquete Python (sin red: sólo desde el wheelhouse)"
python3 -m venv --system-site-packages "$AQUI/.venv"
# --no-build-isolation: sin esto pip monta un entorno aparte para construir y
# le exige setuptools, que no está en el wheelhouse. El venv se creó con
# --system-site-packages, así que ve el setuptools del sistema y no hace falta
# empaquetar herramientas de construcción.
"$AQUI/.venv/bin/python" -m pip install --quiet --no-index --no-build-isolation \
  --find-links "$AQUI/wheelhouse" -e "$AQUI"

echo "==> Comprobando"
"$AQUI/.venv/bin/crux" doctor --verify-supply-chain
echo
echo "Listo. Añade a tu PATH:  $AQUI/.venv/bin"
DESTINO
chmod +x "$TMP/$NOMBRE/instalar.sh"

# ── Empaquetado ─────────────────────────────────────────────────────────────
paso "Empaquetando"
tar -C "$TMP" -czf "$SALIDA/$NOMBRE.tar.gz" "$NOMBRE"
sha256sum "$SALIDA/$NOMBRE.tar.gz" > "$SALIDA/$NOMBRE.tar.gz.sha256"
bien "$SALIDA/$NOMBRE.tar.gz ($(du -h "$SALIDA/$NOMBRE.tar.gz" | cut -f1))"
bien "$SALIDA/$NOMBRE.tar.gz.sha256"
echo
echo "En el equipo de destino:"
echo "  tar -xzf $NOMBRE.tar.gz && cd $NOMBRE && ./instalar.sh"
