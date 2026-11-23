import os


from minired.captura.correlador import Observacion
from minired.captura.decodificar import decodificar
from minired.captura.pcap import leer_archivo
from minired.modelo.a_mininet import planificar
from minired.modelo.topologia import Lab

DATOS = os.path.join(os.path.dirname(__file__), 'datos')


def lab_3pc(nombres=('xa1', 'xa2', 'xa3'), switch='xs1'):
    """3 PC + 1 switch, igual a la captura grabada en la VM (tests/datos/lan_3pc_ping)."""
    nodos = [{'id': 'sw', 'tipo': 'switch', 'nombre': switch, 'x': 0, 'y': 0}]
    enlaces = []
    for i, nombre in enumerate(nombres, start=1):
        nodos.append({'id': 'pc%d' % i, 'tipo': 'pc', 'nombre': nombre, 'x': 100 * i, 'y': 100,
                      'interfaces': [{'puerto': 0, 'ip': '10.0.0.%d/24' % i}]})
        enlaces.append({'id': 'e%d' % i, 'a': {'nodo': 'pc%d' % i, 'puerto': 0},
                        'b': {'nodo': 'sw', 'puerto': i}})
    return Lab.model_validate({'version': 1, 'nodos': nodos, 'enlaces': enlaces})


def observaciones_de(directorio, plan):
    """Lee un pcap por interfaz (nombre <intf>.pcap) y arma observaciones como lo hace la sesión."""
    obs = []
    seq = 0
    for intf, ep in sorted(plan.por_intf.items()):
        ruta = os.path.join(directorio, intf + '.pcap')
        if not os.path.exists(ruta):
            continue
        opuesto = plan.extremo_opuesto(ep.enlace, ep.extremo)
        for reg in leer_archivo(ruta):
            seq += 1
            obs.append(Observacion(seq, reg.ts_ns, ep.enlace, ep.extremo, ep.nodo, opuesto.nodo,
                                   intf, reg.datos, reg.largo_original, intf + '.pcap', reg.n,
                                   decodificar(reg.datos)))
    return obs


