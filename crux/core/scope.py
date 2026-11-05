"""Alcance del escaneo: confinado a redes internas y congelado al arrancar.

Dos propiedades que este módulo garantiza y que el resto del sistema da por hechas:

1. **Solo redes internas.** Un objetivo que resuelva a una IP pública se rechaza,
   salvo que el operador pase `--allow-public` de forma explícita, y en ese caso
   queda registrado en el log de auditoría.
2. **DNS congelado.** Los nombres se resuelven una sola vez, al construir el
   alcance, y a partir de ahí toda comprobación usa esa foto. Esto cierra dos
   agujeros: el DNS rebinding durante el escaneo, y que una herramienta siga un
   redirect hacia un host que resuelve a internet.

Las redes permitidas se enumeran de forma explícita en lugar de delegar en
`ipaddress.is_private`, cuya semántica ha cambiado entre versiones de Python
(p. ej. el espacio compartido 100.64.0.0/10). Para una herramienta de seguridad,
la lista auditable vale más que la comodidad.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from typing import Final, Iterable
from urllib.parse import urlsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


def _nets(*cidrs: str) -> tuple[IPNetwork, ...]:
    return tuple(ipaddress.ip_network(c) for c in cidrs)


# Redes consideradas internas. RFC1918, loopback, link-local y ULA de IPv6.
INTERNAL_NETWORKS: Final[tuple[IPNetwork, ...]] = _nets(
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
)

# Espacio compartido de RFC6598 (CGNAT). No es privado ni público del todo; hay
# organizaciones que lo usan en su red interna, así que se permite solo si se pide.
SHARED_NETWORKS: Final[tuple[IPNetwork, ...]] = _nets("100.64.0.0/10")


class ScopeError(ValueError):
    """El objetivo no se puede incluir en el alcance."""


class ScopeViolation(RuntimeError):
    """Se intentó tocar algo que está fuera del alcance congelado."""


def is_internal(ip: IPAddress | str, *, allow_shared: bool = False) -> bool:
    """¿Esta IP pertenece a una red interna?"""
    addr = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
    networks = INTERNAL_NETWORKS + (SHARED_NETWORKS if allow_shared else ())
    return any(addr in net for net in networks)


@dataclass(frozen=True, slots=True)
class ScopeEntry:
    """Un objetivo del alcance, ya resuelto."""

    raw: str
    kind: str                       # "url" | "host" | "network"
    host: str | None = None
    port: int | None = None
    scheme: str | None = None
    base_path: str = "/"
    addresses: tuple[IPAddress, ...] = ()
    network: IPNetwork | None = None

    @property
    def is_public(self) -> bool:
        """True si alguna de sus direcciones cae fuera de las redes internas."""
        if self.network is not None:
            return not any(
                self.network.subnet_of(net)  # type: ignore[arg-type]
                for net in INTERNAL_NETWORKS
                if net.version == self.network.version
            )
        return any(not is_internal(a) for a in self.addresses)

    def describe(self) -> dict[str, object]:
        """Forma serializable, para congelar en `Scan.scope` y auditar luego."""
        return {
            "raw": self.raw,
            "kind": self.kind,
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
            "base_path": self.base_path,
            "addresses": [str(a) for a in self.addresses],
            "network": str(self.network) if self.network else None,
        }


def _resolve(host: str) -> tuple[IPAddress, ...]:
    """Resuelve un nombre a todas sus direcciones. Una sola vez, al congelar."""
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ScopeError(f"no se puede resolver {host!r}: {exc.strerror or exc}") from exc
    seen: dict[str, IPAddress] = {}
    for info in infos:
        addr = info[4][0]
        if addr not in seen:
            seen[addr] = ipaddress.ip_address(addr)
    return tuple(seen.values())


def parse_entry(raw: str) -> ScopeEntry:
    """Interpreta un objetivo: URL, host, host:puerto o CIDR. Resuelve el DNS."""
    raw = raw.strip()
    if not raw:
        raise ScopeError("objetivo vacío")

    # CIDR o IP suelta: no hay nada que resolver.
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        pass
    else:
        if network.num_addresses > 1 or "/" in raw:
            return ScopeEntry(raw=raw, kind="network", network=network)
        addr = next(iter(network.hosts()), None) or network.network_address
        return ScopeEntry(raw=raw, kind="host", host=str(addr), addresses=(addr,))

    if "://" in raw:
        split = urlsplit(raw)
        if split.scheme not in ("http", "https"):
            raise ScopeError(f"esquema no soportado: {split.scheme!r}")
        if not split.hostname:
            raise ScopeError(f"URL sin host: {raw!r}")
        host = split.hostname
        port = split.port or (443 if split.scheme == "https" else 80)
        return ScopeEntry(
            raw=raw,
            kind="url",
            host=host,
            port=port,
            scheme=split.scheme,
            base_path=split.path or "/",
            addresses=_resolve(host),
        )

    # host o host:puerto
    host, _, port_text = raw.rpartition(":")
    if host and port_text.isdigit():
        return ScopeEntry(
            raw=raw, kind="host", host=host, port=int(port_text), addresses=_resolve(host)
        )
    return ScopeEntry(raw=raw, kind="host", host=raw, addresses=_resolve(raw))


@dataclass(slots=True)
class Scope:
    """El alcance congelado de un escaneo.

    Construir un `Scope` tiene efectos: resuelve DNS y rechaza lo que no cumpla.
    A partir de ahí es una foto inmutable que todo el sistema consulta.
    """

    entries: list[ScopeEntry] = field(default_factory=list)
    allow_public: bool = False
    allow_shared: bool = False
    # Relaja el alcance a "cualquier red privada" en lugar de "solo lo
    # declarado". No es lo predeterminado: ver `allows_ip`.
    allow_internal: bool = False
    # Nombres extra permitidos aunque no sean objetivo directo (p. ej. un CDN
    # interno o un IdP de la intranet del que cuelga la app).
    extra_hosts: list[str] = field(default_factory=list)
    # Proveedores de identidad: hosts a los que hay que ir para ENTRAR en la
    # aplicación —un Keycloak, un ADFS—, y nada más. Se resuelven y se congelan
    # como el resto, y el aislamiento de red les da ruta, pero no son
    # auditables: `allows_host` dice que no aunque compartan IP con un objetivo.
    # Un Keycloak corporativo da servicio a cien aplicaciones; auditar una no
    # autoriza a escanearlo a él.
    proveedores_identidad: list[str] = field(default_factory=list)
    _frozen_dns: dict[str, tuple[IPAddress, ...]] = field(default_factory=dict, repr=False)
    _allowed_ips: set[IPAddress] = field(default_factory=set, repr=False)
    _allowed_networks: list[IPNetwork] = field(default_factory=list, repr=False)
    rejected: list[tuple[str, str]] = field(default_factory=list)

    @classmethod
    def build(
        cls,
        targets: Iterable[str],
        *,
        allow_public: bool = False,
        allow_shared: bool = False,
        allow_internal: bool = False,
        extra_hosts: Iterable[str] = (),
        proveedores_identidad: Iterable[str] = (),
    ) -> Scope:
        """Resuelve y valida los objetivos. Lanza `ScopeError` si ninguno sirve."""
        scope = cls(allow_public=allow_public, allow_shared=allow_shared,
                    allow_internal=allow_internal, extra_hosts=list(extra_hosts))
        for raw in targets:
            try:
                entry = parse_entry(raw)
            except ScopeError as exc:
                scope.rejected.append((raw, str(exc)))
                continue
            if entry.is_public and not allow_public:
                scope.rejected.append(
                    (raw, "resuelve a una IP pública; usa --allow-public si es intencionado")
                )
                continue
            scope._admit(entry)

        for host in scope.extra_hosts:
            try:
                addresses = _resolve(host)
            except ScopeError as exc:
                scope.rejected.append((host, str(exc)))
                continue
            scope._frozen_dns[host.lower()] = addresses
            scope._allowed_ips.update(addresses)

        for crudo in proveedores_identidad:
            scope._admitir_proveedor(crudo)

        if not scope.entries:
            detail = "; ".join(f"{raw}: {why}" for raw, why in scope.rejected)
            raise ScopeError(f"ningún objetivo válido en el alcance ({detail})")
        return scope

    def _admitir_proveedor(self, crudo: str) -> None:
        """Congela un proveedor de identidad, con las mismas reglas que un objetivo.

        Acepta una URL o un nombre. Un proveedor que resuelva a una IP pública
        se rechaza salvo con `allow_public`, igual que un objetivo: que sea
        «solo para entrar» no cambia que el tráfico saldría de la red interna.
        """
        host = (urlsplit(crudo).hostname if "://" in crudo else crudo).strip().lower()
        if not host or host in self.proveedores_identidad:
            return
        try:
            direcciones = _resolve(host)
        except ScopeError as exc:
            self.rejected.append((crudo, f"proveedor de identidad: {exc}"))
            return
        if not self.allow_public and not all(
                is_internal(d, allow_shared=self.allow_shared) for d in direcciones):
            self.rejected.append(
                (crudo, "el proveedor de identidad resuelve a una IP pública; "
                        "usa --allow-public si es intencionado"))
            return
        self._frozen_dns[host] = direcciones
        self.proveedores_identidad.append(host)

    def _admit(self, entry: ScopeEntry) -> None:
        self.entries.append(entry)
        if entry.host:
            self._frozen_dns.setdefault(entry.host.lower(), entry.addresses)
        self._allowed_ips.update(entry.addresses)
        if entry.network is not None:
            self._allowed_networks.append(entry.network)

    # -- Consultas que hace el resto del sistema --------------------------------

    def resolve(self, host: str) -> tuple[IPAddress, ...]:
        """Resolución **solo** desde la foto congelada. Nunca vuelve a consultar DNS."""
        return self._frozen_dns.get(host.lower(), ())

    def allows_host(self, host: str) -> bool:
        """¿Se puede auditar este host? Un nombre no congelado no se permite."""
        host = host.strip().lower()
        if not host or host in self.proveedores_identidad:
            return False
        try:
            addr = ipaddress.ip_address(host)
        except ValueError:
            addresses = self.resolve(host)
            return bool(addresses) and all(self.allows_ip(a) for a in addresses)
        return self.allows_ip(addr)

    def allows_ip(self, ip: IPAddress | str) -> bool:
        """Solo lo declarado. Ser una IP interna no basta.

        Es deliberadamente estricto: una autorización para auditar
        192.168.50.0/24 no autoriza a tocar 192.168.51.1, aunque también sea
        una red privada — puede ser la subred de otro equipo. Lo que una
        aplicación necesite fuera de sus propios objetivos (un IdP interno, un
        CDN de la intranet) se declara con `extra_hosts`, de forma explícita y
        auditable.

        `allow_internal` relaja esto a "cualquier red privada" para quien
        prefiera esa interpretación, pero no es lo predeterminado.
        """
        addr = ipaddress.ip_address(ip) if isinstance(ip, str) else ip
        if addr in self._allowed_ips:
            return True
        if any(addr in net for net in self._allowed_networks):
            return True
        if self.allow_internal:
            return is_internal(addr, allow_shared=self.allow_shared)
        return False

    def allows_url(self, url: str) -> bool:
        """Usado por el interceptor de Playwright para abortar peticiones fuera de alcance."""
        try:
            host = urlsplit(url).hostname
        except ValueError:
            return False
        return bool(host) and self.allows_host(host)

    def es_proveedor(self, url_o_host: str) -> bool:
        host = urlsplit(url_o_host).hostname if "://" in url_o_host else url_o_host
        return bool(host) and host.lower() in self.proveedores_identidad

    def permite_para_entrar(self, url: str) -> bool:
        """¿Puede el navegador del login ir aquí? Lo auditable y los proveedores."""
        return self.allows_url(url) or self.es_proveedor(url)

    def require(self, host: str) -> None:
        if not self.allows_host(host):
            raise ScopeViolation(f"{host!r} está fuera del alcance congelado de este escaneo")

    @property
    def urls(self) -> list[str]:
        return [e.raw for e in self.entries if e.kind == "url"]

    @property
    def hosts(self) -> list[str]:
        return [e.host for e in self.entries if e.host]

    def describe(self) -> dict[str, object]:
        """Foto serializable para `Scan.scope`: lo que se auditará después."""
        return {
            "entries": [e.describe() for e in self.entries],
            "allow_public": self.allow_public,
            "allow_shared": self.allow_shared,
            "allow_internal": self.allow_internal,
            "extra_hosts": self.extra_hosts,
            "proveedores_identidad": self.proveedores_identidad,
            "frozen_dns": {h: [str(a) for a in ips] for h, ips in self._frozen_dns.items()},
            "rejected": [{"target": raw, "reason": why} for raw, why in self.rejected],
        }
