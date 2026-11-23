"""Modelo de laboratorio: nodos, puertos y enlaces, validado con Pydantic.

Todo valor que termina en un comando (nombres de nodo e interfaz, IP,
gateway) pasa por estas validaciones antes de llegar a Mininet.
"""

from enum import Enum
from ipaddress import IPv4Address, IPv4Interface, IPv4Network
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

NOMBRE_RE = r'^[a-z][a-z0-9]{0,7}$'
ID_RE = r'^[A-Za-z0-9_-]{1,32}$'
DNS_RE = r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$'
IFNAMSIZ = 15

MAX_NODOS = 32
MAX_ENLACES = 64


class TipoNodo(str, Enum):
    pc = 'pc'
    switch = 'switch'
    router = 'router'
    servidor = 'servidor'


# Puertos válidos por tipo de nodo. El nombre Linux es "<nombre>-eth<puerto>".
PUERTOS = {
    TipoNodo.pc: range(0, 1),
    TipoNodo.switch: range(1, 17),
    TipoNodo.router: range(0, 8),
    TipoNodo.servidor: range(0, 1),
}
HOSTS = (TipoNodo.pc, TipoNodo.servidor)
VLAN_ID = dict(ge=1, le=4094)


class Estricto(BaseModel):
    model_config = ConfigDict(extra='forbid')


def _con_prefijo(v):
    if isinstance(v, str) and '/' not in v:
        raise ValueError('falta el prefijo de red, por ejemplo 10.0.0.1/24')
    return v


class Subinterfaz(Estricto):
    """Subinterfaz 802.1Q de un router (router-on-a-stick): <intf>.<vlan>."""
    vlan: int = Field(**VLAN_ID)
    ip: IPv4Interface

    _prefijo = field_validator('ip', mode='before')(classmethod(lambda cls, v: _con_prefijo(v)))


class ReglaACL(Estricto):
    """Regla de una ACL de entrada. Se evalúan en orden; al final hay un "deny any" implícito."""
    accion: Literal['permitir', 'denegar']
    protocolo: Literal['ip', 'icmp', 'tcp', 'udp'] = 'ip'
    origen: Optional[IPv4Network] = None       # None = any
    destino: Optional[IPv4Network] = None
    puerto: Optional[int] = Field(default=None, ge=1, le=65535)   # destino, solo tcp/udp


class Interfaz(Estricto):
    puerto: int = Field(ge=0, le=16)
    ip: Optional[IPv4Interface] = None
    # Switch: puerto de acceso en una VLAN o troncal 802.1Q con las VLAN permitidas.
    vlan: Optional[int] = Field(default=None, **VLAN_ID)
    troncal: Optional[list[int]] = Field(default=None, max_length=32)
    # Router: subinterfaces, papel en NAT y ACL de entrada.
    subinterfaces: list[Subinterfaz] = Field(default_factory=list, max_length=16)
    nat: Optional[Literal['interior', 'exterior']] = None
    acl_entrada: list[ReglaACL] = Field(default_factory=list, max_length=32)

    _prefijo = field_validator('ip', mode='before')(classmethod(lambda cls, v: _con_prefijo(v)))


class Ruta(Estricto):
    destino: IPv4Network
    via: IPv4Address


class PoolDHCP(Estricto):
    desde: IPv4Address
    hasta: IPv4Address
    gateway: Optional[IPv4Address] = None
    dns: Optional[IPv4Address] = None


class RegistroDNS(Estricto):
    nombre: str = Field(pattern=DNS_RE, max_length=253)
    ip: IPv4Address


class Servicios(Estricto):
    dhcp: Optional[PoolDHCP] = None
    dns: list[RegistroDNS] = Field(default_factory=list, max_length=64)
    http: bool = False


class Nodo(Estricto):
    id: str = Field(pattern=ID_RE)
    tipo: TipoNodo
    nombre: str = Field(pattern=NOMBRE_RE)
    x: float = 0.0
    y: float = 0.0
    interfaces: list[Interfaz] = Field(default_factory=list, max_length=17)
    gateway: Optional[IPv4Address] = None
    # PC/servidor
    dhcp: bool = False                       # pide IP por DHCP (solo PC)
    dns: Optional[IPv4Address] = None        # servidor DNS (resolv.conf propio del nodo)
    servicios: Optional[Servicios] = None    # solo servidor
    # Router
    rutas: list[Ruta] = Field(default_factory=list, max_length=32)
    frr: bool = False                        # FRRouting con vtysh en el namespace del router
    ospf: bool = False                       # OSPF área 0 en todas sus redes (requiere frr)

    def interfaz(self, puerto):
        for intf in self.interfaces:
            if intf.puerto == puerto:
                return intf
        return None


class Extremo(Estricto):
    nodo: str = Field(pattern=ID_RE)
    puerto: int = Field(ge=0, le=16)


class Enlace(Estricto):
    id: str = Field(pattern=ID_RE)
    a: Extremo
    b: Extremo


class Lab(Estricto):
    version: Literal[1] = 1
    nodos: list[Nodo] = Field(default_factory=list, max_length=MAX_NODOS)
    enlaces: list[Enlace] = Field(default_factory=list, max_length=MAX_ENLACES)

    @model_validator(mode='after')
    def _coherente(self):
        errores = errores_lab(self)
        if errores:
            raise ValueError('; '.join(errores))
        return self

    def nodo(self, nodo_id):
        for nodo in self.nodos:
            if nodo.id == nodo_id:
                return nodo
        return None


def nombre_intf(nodo, puerto):
    return '%s-eth%d' % (nodo.nombre, puerto)


def nombre_subintf(nodo, puerto, vlan):
    return '%s.%d' % (nombre_intf(nodo, puerto), vlan)


def ips_nodo(nodo):
    """(nombre de interfaz, IPv4Interface) de todas las direcciones del nodo, subinterfaces incluidas."""
    r = []
    for intf in nodo.interfaces:
        if intf.ip is not None:
            r.append((nombre_intf(nodo, intf.puerto), intf.ip))
        for sub in intf.subinterfaces:
            r.append((nombre_subintf(nodo, intf.puerto, sub.vlan), sub.ip))
    return r


def errores_lab(lab):
    """Devuelve la lista de errores de coherencia del laboratorio (vacía si es válido)."""
    errores = []
    por_id = {}
    nombres = set()
    for nodo in lab.nodos:
        if nodo.id in por_id:
            errores.append('id de nodo repetido: %s' % nodo.id)
        por_id[nodo.id] = nodo
        if nodo.nombre in nombres:
            errores.append('nombre repetido: %s' % nodo.nombre)
        nombres.add(nodo.nombre)
        errores.extend(_errores_nodo(nodo))

    ids_enlace = set()
    usados = set()
    # Unión-búsqueda sobre los enlaces switch-switch: sin STP, un ciclo es una tormenta.
    padre = {}

    def raiz(x):
        while padre.setdefault(x, x) != x:
            x = padre[x]
        return x

    for enlace in lab.enlaces:
        if enlace.id in ids_enlace:
            errores.append('id de enlace repetido: %s' % enlace.id)
        ids_enlace.add(enlace.id)
        nodos = []
        for ext in (enlace.a, enlace.b):
            nodo = por_id.get(ext.nodo)
            if nodo is None:
                errores.append('el enlace %s usa un nodo inexistente: %s' % (enlace.id, ext.nodo))
                continue
            nodos.append(nodo)
            if ext.puerto not in PUERTOS[nodo.tipo]:
                errores.append('%s no tiene el puerto %d' % (nodo.nombre, ext.puerto))
            clave = (ext.nodo, ext.puerto)
            if clave in usados:
                errores.append('el puerto %s está conectado dos veces' % nombre_intf(nodo, ext.puerto))
            usados.add(clave)
        if enlace.a.nodo == enlace.b.nodo:
            errores.append('el enlace %s conecta un nodo consigo mismo' % enlace.id)
            continue
        if len(nodos) == 2 and all(n.tipo == TipoNodo.switch for n in nodos):
            ra, rb = raiz(nodos[0].id), raiz(nodos[1].id)
            if ra == rb:
                errores.append('el enlace %s forma un bucle entre switches (no hay STP en esta versión)'
                               % enlace.id)
            padre[ra] = rb
    return errores


def _errores_nodo(nodo):
    errores = []
    puertos = set()
    nombre = nodo.nombre
    for intf in nodo.interfaces:
        nintf = nombre_intf(nodo, intf.puerto)
        if intf.puerto not in PUERTOS[nodo.tipo]:
            errores.append('%s no tiene el puerto %d' % (nombre, intf.puerto))
        if intf.puerto in puertos:
            errores.append('%s: puerto %d configurado dos veces' % (nombre, intf.puerto))
        puertos.add(intf.puerto)
        errores.extend(_errores_vlan_puerto(nodo, intf, nintf))
        errores.extend(_errores_router_puerto(nodo, intf, nintf))
        if intf.ip is not None and nodo.tipo == TipoNodo.switch:
            errores.append('%s es un switch: sus puertos no llevan IP' % nombre)
    redes = []
    for nintf, ip in ips_nodo(nodo):
        if nodo.tipo == TipoNodo.switch:
            continue
        red = ip.network
        if red.prefixlen < 31 and ip.ip in (red.network_address, red.broadcast_address):
            errores.append('%s: %s es la dirección de red o de broadcast de %s' % (nintf, ip.ip, red))
        if ip.ip.is_loopback or ip.ip.is_multicast or ip.ip.is_unspecified or ip.ip.is_link_local:
            errores.append('%s: %s no es una dirección de host válida' % (nintf, ip.ip))
        redes.append((nintf, red))
    for n, (i1, r1) in enumerate(redes):
        for i2, r2 in redes[n + 1:]:
            if r1.overlaps(r2):
                errores.append('%s: %s y %s están en redes superpuestas (%s, %s)'
                               % (nombre, i1, i2, r1, r2))
    errores.extend(_errores_host(nodo))
    errores.extend(_errores_router(nodo))
    errores.extend(_errores_servidor(nodo))
    return errores


def _errores_vlan_puerto(nodo, intf, nintf):
    errores = []
    if intf.vlan is None and intf.troncal is None:
        return errores
    if nodo.tipo != TipoNodo.switch:
        return ['%s: VLAN de acceso y troncales se configuran en puertos de switch' % nintf]
    if intf.vlan is not None and intf.troncal is not None:
        errores.append('%s: un puerto es de acceso (VLAN) o troncal, no las dos cosas' % nintf)
    if intf.troncal is not None:
        if any(not 1 <= v <= 4094 for v in intf.troncal):
            errores.append('%s: las VLAN van de 1 a 4094' % nintf)
        if len(set(intf.troncal)) != len(intf.troncal):
            errores.append('%s: VLAN repetida en la troncal' % nintf)
    return errores


def _errores_router_puerto(nodo, intf, nintf):
    errores = []
    if nodo.tipo != TipoNodo.router:
        if intf.subinterfaces:
            errores.append('%s: solo los routers tienen subinterfaces' % nintf)
        if intf.nat is not None or intf.acl_entrada:
            errores.append('%s: NAT y ACL se configuran en interfaces de router' % nintf)
        return errores
    vlans = [s.vlan for s in intf.subinterfaces]
    if len(set(vlans)) != len(vlans):
        errores.append('%s: subinterfaz repetida' % nintf)
    for sub in intf.subinterfaces:
        if len(nombre_subintf(nodo, intf.puerto, sub.vlan)) > IFNAMSIZ:
            errores.append('%s.%d: el nombre supera 15 caracteres; acortá el nombre del router'
                           % (nintf, sub.vlan))
    if intf.nat is not None and intf.ip is None and not intf.subinterfaces:
        errores.append('%s: una interfaz NAT necesita IP' % nintf)
    for n, regla in enumerate(intf.acl_entrada, start=1):
        if regla.puerto is not None and regla.protocolo not in ('tcp', 'udp'):
            errores.append('%s: regla %d de la ACL: el puerto solo vale para tcp o udp' % (nintf, n))
    return errores


def _errores_host(nodo):
    errores = []
    nombre = nodo.nombre
    if nodo.gateway is not None:
        if nodo.tipo not in HOSTS:
            errores.append('%s: solo las PC y los servidores llevan gateway' % nombre)
        else:
            ips = [i.ip for i in nodo.interfaces if i.ip is not None]
            if not ips:
                errores.append('%s: tiene gateway pero no tiene IP' % nombre)
            elif not any(nodo.gateway in ip.network for ip in ips):
                errores.append('%s: el gateway %s no está en la red de la PC' % (nombre, nodo.gateway))
            elif any(nodo.gateway == ip.ip for ip in ips):
                errores.append('%s: el gateway no puede ser la propia IP' % nombre)
    if nodo.dns is not None and nodo.tipo not in HOSTS:
        errores.append('%s: el servidor DNS se configura en PC y servidores' % nombre)
    if nodo.dhcp:
        if nodo.tipo != TipoNodo.pc:
            errores.append('%s: solo las PC piden IP por DHCP' % nombre)
        elif any(i.ip is not None for i in nodo.interfaces) or nodo.gateway is not None:
            errores.append('%s: con DHCP la IP y el gateway los entrega el servidor; dejalos vacíos'
                           % nombre)
    return errores


def _errores_router(nodo):
    errores = []
    nombre = nodo.nombre
    if nodo.tipo != TipoNodo.router:
        if nodo.rutas or nodo.frr or nodo.ospf:
            errores.append('%s: rutas, FRR y OSPF son de routers' % nombre)
        return errores
    if nodo.ospf and not nodo.frr:
        errores.append('%s: OSPF necesita FRR activado' % nombre)
    redes = [ip.network for _, ip in ips_nodo(nodo)]
    for ruta in nodo.rutas:
        if not any(ruta.via in red for red in redes):
            errores.append('%s: la ruta a %s usa %s, que no está en ninguna red conectada'
                           % (nombre, ruta.destino, ruta.via))
    nat = {i.nat for i in nodo.interfaces if i.nat}
    if nat and nat != {'interior', 'exterior'}:
        errores.append('%s: NAT necesita al menos una interfaz interior y una exterior' % nombre)
    return errores


def _errores_servidor(nodo):
    errores = []
    nombre = nodo.nombre
    if nodo.servicios is None:
        return errores
    if nodo.tipo != TipoNodo.servidor:
        return ['%s: los servicios (DHCP, DNS, HTTP) van en un servidor' % nombre]
    ips = [i.ip for i in nodo.interfaces if i.ip is not None]
    if not ips:
        return ['%s: el servidor necesita una IP fija para ofrecer servicios' % nombre]
    red = ips[0].network
    pool = nodo.servicios.dhcp
    if pool is not None:
        if pool.desde not in red or pool.hasta not in red:
            errores.append('%s: el rango DHCP tiene que estar en la red del servidor (%s)' % (nombre, red))
        elif pool.desde > pool.hasta:
            errores.append('%s: el rango DHCP empieza después de donde termina' % nombre)
        elif pool.desde <= ips[0].ip <= pool.hasta:
            errores.append('%s: la IP del servidor está dentro del rango DHCP' % nombre)
        elif pool.desde in (red.network_address, red.broadcast_address) or \
                pool.hasta in (red.network_address, red.broadcast_address):
            errores.append('%s: el rango DHCP incluye la dirección de red o de broadcast' % nombre)
        if pool.gateway is not None and pool.gateway not in red:
            errores.append('%s: el gateway que entrega el DHCP no está en %s' % (nombre, red))
    nombres = [r.nombre for r in nodo.servicios.dns]
    if len(set(nombres)) != len(nombres):
        errores.append('%s: nombre DNS repetido' % nombre)
    return errores
