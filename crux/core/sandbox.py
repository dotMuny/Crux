"""Aislamiento de red real: el egress cero deja de ser detección y pasa a ser contención.

Hasta aquí, que una herramienta no saliera del alcance se conseguía quitándole
los flags de telemetría, saneando su entorno y comprobándolo después. Eso
detecta y disuade, pero no impide: una herramienta que decidiera abrir un
socket a donde le diese la gana, podría.

Este módulo pone la red por debajo. Crea un namespace de red con una única
salida —un cable virtual hacia el equipo— y una regla de cortafuegos que sólo
deja pasar hacia las direcciones del alcance. Lo demás no es que esté
desaconsejado: no tiene ruta.

Además escribe el DNS congelado como `/etc/hosts` del namespace, de modo que
los nombres del alcance resuelven a lo que resolvieron al empezar y ningún
otro nombre resuelve a nada. El rebinding deja de ser algo que vigilar.

Necesita privilegios para crear el veth y la regla. Sin ellos no se degrada en
silencio: se dice y se sigue sin sandbox, que es el comportamiento de siempre.
"""

from __future__ import annotations

import ipaddress
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Sequence

from .scope import Scope

# Subred del cable virtual. /30 porque sólo hacen falta dos direcciones, y en
# un rango que no choca con las habituales de una intranet.
SUBRED = ipaddress.ip_network("10.199.77.0/30")
IP_EQUIPO = "10.199.77.1"
IP_SANDBOX = "10.199.77.2"
TABLA_NFT = "crux_sandbox"


class SandboxNoDisponible(RuntimeError):
    """No se puede crear el aislamiento. Nunca se degrada en silencio."""


def _ejecutar(argv: Sequence[str], *, root: bool = True, check: bool = True):
    orden = (["sudo", "-n", *argv] if root and os.geteuid() != 0 else list(argv))
    return subprocess.run(orden, capture_output=True, text=True, check=check, timeout=20)


def comprobar_disponible() -> tuple[bool, str]:
    """¿Se puede crear el aislamiento aquí? Devuelve también el motivo."""
    for binario in ("ip", "nft"):
        if shutil.which(binario) is None and not os.path.exists(f"/usr/sbin/{binario}"):
            return False, f"falta {binario}"
    if os.geteuid() != 0:
        try:
            _ejecutar(["true"], root=True)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError):
            return False, ("hace falta root para crear el cable virtual y la regla "
                           "de cortafuegos; configura sudo sin contraseña o ejecuta "
                           "el escaneo como root")
    return True, "disponible"


@dataclass(slots=True)
class SandboxDeRed:
    """Namespace de red que sólo alcanza las direcciones del alcance."""

    nombre: str
    scope: Scope
    _creado: bool = field(default=False, repr=False)
    permitidas: list[str] = field(default_factory=list)

    # -- ciclo de vida ------------------------------------------------------
    def __enter__(self) -> SandboxDeRed:
        self.crear()
        return self

    def __exit__(self, *_: object) -> None:
        self.destruir()

    def crear(self) -> None:
        disponible, motivo = comprobar_disponible()
        if not disponible:
            raise SandboxNoDisponible(motivo)

        self.permitidas = self._destinos_permitidos()
        if not self.permitidas:
            raise SandboxNoDisponible(
                "el alcance no resolvió a ninguna dirección: no hay nada que permitir"
            )

        # Se limpia antes de crear: un escaneo anterior interrumpido deja
        # restos, y dos namespaces con el mismo nombre no pueden coexistir.
        self.destruir(silencioso=True)
        try:
            self._crear_namespace()
            self._crear_cable()
            self._escribir_hosts()
            self._crear_reglas()
            self._creado = True
        except subprocess.CalledProcessError as exc:
            self.destruir(silencioso=True)
            raise SandboxNoDisponible(
                f"no se pudo montar el aislamiento: {exc.stderr.strip() or exc}"
            ) from exc

    def destruir(self, *, silencioso: bool = False) -> None:
        for argv in (
            ["nft", "delete", "table", "inet", TABLA_NFT],
            ["ip", "netns", "delete", self.nombre],
            ["ip", "link", "delete", self._veth_equipo],
        ):
            try:
                _ejecutar(argv, check=False)
            except Exception:
                if not silencioso:
                    raise
        self._creado = False

    # -- construcción -------------------------------------------------------
    @property
    def _veth_equipo(self) -> str:
        # El nombre de interfaz tiene un límite de 15 caracteres.
        return f"ax-{self.nombre[:11]}"

    def _destinos_permitidos(self) -> list[str]:
        """Direcciones y redes que el sandbox podrá alcanzar."""
        destinos: list[str] = []
        for entrada in self.scope.entries:
            if entrada.network is not None:
                destinos.append(str(entrada.network))
            for direccion in entrada.addresses:
                destinos.append(f"{direccion}/32" if direccion.version == 4
                                else f"{direccion}/128")
        for direcciones in self.scope._frozen_dns.values():
            for direccion in direcciones:
                destinos.append(f"{direccion}/32" if direccion.version == 4
                                else f"{direccion}/128")
        return sorted(set(destinos))

    def _crear_namespace(self) -> None:
        _ejecutar(["ip", "netns", "add", self.nombre])
        _ejecutar(["ip", "netns", "exec", self.nombre, "ip", "link", "set", "lo", "up"])

    def _crear_cable(self) -> None:
        veth = self._veth_equipo
        _ejecutar(["ip", "link", "add", veth, "type", "veth", "peer", "name", "ax-in"])
        _ejecutar(["ip", "link", "set", "ax-in", "netns", self.nombre])
        _ejecutar(["ip", "addr", "add", f"{IP_EQUIPO}/30", "dev", veth])
        _ejecutar(["ip", "link", "set", veth, "up"])
        _ejecutar(["ip", "netns", "exec", self.nombre,
                   "ip", "addr", "add", f"{IP_SANDBOX}/30", "dev", "ax-in"])
        _ejecutar(["ip", "netns", "exec", self.nombre, "ip", "link", "set", "ax-in", "up"])
        _ejecutar(["ip", "netns", "exec", self.nombre,
                   "ip", "route", "add", "default", "via", IP_EQUIPO])

    def _escribir_hosts(self) -> None:
        """El DNS congelado, como /etc/hosts del namespace.

        `ip netns exec` monta /etc/netns/<nombre>/ sobre /etc, así que esto
        sustituye la resolución del sistema dentro del sandbox: los nombres del
        alcance resuelven a lo que resolvieron al empezar, y ningún otro nombre
        resuelve a nada. El DNS rebinding deja de ser posible, no sólo de estar
        vigilado.
        """
        lineas = ["127.0.0.1\tlocalhost", "::1\tlocalhost"]
        for nombre, direcciones in self.scope._frozen_dns.items():
            # Un objetivo dado como IP literal se congela contra sí mismo; no
            # es un nombre y escribirlo en hosts no aporta nada.
            try:
                ipaddress.ip_address(nombre)
            except ValueError:
                pass
            else:
                continue
            for direccion in direcciones:
                lineas.append(f"{direccion}\t{nombre}")

        carpeta = f"/etc/netns/{self.nombre}"
        _ejecutar(["mkdir", "-p", carpeta])
        contenido = "\n".join(lineas) + "\n"
        subprocess.run(
            (["sudo", "-n"] if os.geteuid() != 0 else []) + ["tee", f"{carpeta}/hosts"],
            input=contenido, capture_output=True, text=True, check=True, timeout=10,
        )
        # Sin servidor de nombres: dentro del sandbox no hay a quién preguntar,
        # que es justo lo que se quiere.
        subprocess.run(
            (["sudo", "-n"] if os.geteuid() != 0 else []) + ["tee", f"{carpeta}/resolv.conf"],
            input="# Crux: resolución congelada en hosts; sin servidor de nombres.\n",
            capture_output=True, text=True, check=True, timeout=10,
        )

    def _crear_reglas(self) -> None:
        """Cortafuegos: sólo se reenvía hacia el alcance; lo demás se descarta."""
        _ejecutar(["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"])

        permitidas_v4 = [d for d in self.permitidas if ":" not in d]
        conjunto = ", ".join(permitidas_v4) or "127.0.0.1/32"
        reglas = f"""
table inet {TABLA_NFT} {{
  set permitidas {{
    type ipv4_addr
    flags interval
    elements = {{ {conjunto} }}
  }}
  chain forward {{
    type filter hook forward priority -10; policy accept;
    iifname "{self._veth_equipo}" ip daddr @permitidas accept
    iifname "{self._veth_equipo}" ct state established,related accept
    iifname "{self._veth_equipo}" drop
  }}
  chain postrouting {{
    type nat hook postrouting priority 100; policy accept;
    ip saddr {SUBRED} ip daddr @permitidas masquerade
  }}
}}
"""
        subprocess.run(
            (["sudo", "-n"] if os.geteuid() != 0 else []) + ["nft", "-f", "-"],
            input=reglas, capture_output=True, text=True, check=True, timeout=20,
        )

    # -- uso ----------------------------------------------------------------
    def envolver(self, argv: Sequence[str]) -> list[str]:
        """Antepone lo necesario para ejecutar dentro del namespace."""
        if not self._creado:
            raise SandboxNoDisponible("el sandbox no está montado")
        prefijo = ["ip", "netns", "exec", self.nombre]
        if os.geteuid() != 0:
            # `ip netns exec` necesita privilegios; se devuelven de inmediato
            # al usuario original para que la herramienta no corra como root.
            prefijo = ["sudo", "-n", *prefijo, "setpriv",
                       f"--reuid={os.getuid()}", f"--regid={os.getgid()}",
                       "--clear-groups"]
        return [*prefijo, *argv]

    def objetivos_en_loopback(self) -> list[str]:
        """Objetivos que el sandbox no puede alcanzar, por diseño.

        Dentro de un namespace de red, 127.0.0.1 es el loopback del propio
        namespace, no el del equipo. Un objetivo en localhost es por tanto
        inalcanzable desde dentro. No es un fallo del aislamiento: es lo que
        significa aislar. Conviene decirlo antes de que alguien interprete un
        escaneo vacío como que la aplicación no responde.
        """
        import ipaddress as _ip

        problematicos = []
        for entrada in self.scope.entries:
            for direccion in entrada.addresses:
                if direccion.is_loopback:
                    problematicos.append(entrada.raw)
                    break
        return sorted(set(problematicos))

    def describe(self) -> dict[str, object]:
        return {
            "namespace": self.nombre,
            "montado": self._creado,
            "destinos_permitidos": self.permitidas,
            "dns_congelado": {
                h: [str(d) for d in ds] for h, ds in self.scope._frozen_dns.items()
            },
        }
