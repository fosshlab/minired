"""Traducción de un Lab validado a un plan de red concreto para Mininet.

El plan es puro (no importa Mininet) para poder probarlo sin root. El runtime
lo recorre para crear nodos, enlaces e interfaces con nombres deterministas.
"""

from dataclasses import dataclass, field

from .topologia import TipoNodo, nombre_intf


@dataclass(frozen=True)
class ExtremoPlan:
    enlace: str          # id del enlace
    extremo: str         # 'a' o 'b'
    nodo: str            # id del nodo
    nombre_nodo: str
    tipo: TipoNodo
    intf: str            # nombre Linux de la interfaz
    ip: str | None       # "10.0.0.1/24" o None


@dataclass
class PlanRed:
    lab: object
    # enlace_id -> (ExtremoPlan a, ExtremoPlan b)
    enlaces: dict = field(default_factory=dict)
    # nombre de interfaz -> ExtremoPlan
    por_intf: dict = field(default_factory=dict)
    # id de switch -> dpid de 16 dígitos hexadecimales
    dpids: dict = field(default_factory=dict)

    def extremo_opuesto(self, enlace_id, extremo):
        a, b = self.enlaces[enlace_id]
        return b if extremo == 'a' else a

    def mapa_publico(self):
        """Mapa enlace -> interfaces para la interfaz web."""
        return {eid: {'a': a.intf, 'b': b.intf} for eid, (a, b) in self.enlaces.items()}


def planificar(lab):
    plan = PlanRed(lab=lab)
    switches = [n for n in lab.nodos if n.tipo == TipoNodo.switch]
    for i, sw in enumerate(switches, start=1):
        # dpid explícito: así el nombre del switch no necesita terminar en número.
        plan.dpids[sw.id] = '%016x' % i
    for enlace in lab.enlaces:
        extremos = []
        for lado, ext in (('a', enlace.a), ('b', enlace.b)):
            nodo = lab.nodo(ext.nodo)
            intf = nodo.interfaz(ext.puerto)
            ep = ExtremoPlan(
                enlace=enlace.id, extremo=lado, nodo=nodo.id, nombre_nodo=nodo.nombre,
                tipo=nodo.tipo, intf=nombre_intf(nodo, ext.puerto),
                ip=str(intf.ip) if intf is not None and intf.ip is not None else None)
            extremos.append(ep)
            plan.por_intf[ep.intf] = ep
        plan.enlaces[enlace.id] = tuple(extremos)
    return plan
