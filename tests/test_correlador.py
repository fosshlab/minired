import os

from minired.captura.decodificar import decodificar
from minired.captura.pcap import leer_archivo
from minired.captura.correlador import ALTA, SIN_CORRELACIONAR, Correlador, Observacion
from minired.modelo.a_mininet import planificar
from minired.modelo.topologia import Lab

from utiles import lab_3pc, observaciones_de

D = os.path.join(os.path.dirname(__file__), 'datos', 'lan_3pc_ping')


def tipos(lab):
    return {n.id: n.tipo for n in lab.nodos}


def correlacionar(lab, obs):
    c = Correlador(tipos(lab))
    for o in reversed(obs):       # orden de llegada arbitrario
        c.agregar(o)
    return c.confirmar_todo()


def por_paquete(conf):
    paquetes = {}
    for o in conf:
        paquetes.setdefault(o.paquete, []).append(o)
    return paquetes


def test_ping_lan_captura_real():
    lab = lab_3pc()
    plan = planificar(lab)
    conf = correlacionar(lab, observaciones_de(D, plan))
    assert len(conf) == 9
    assert all(o.confianza == ALTA for o in conf)
    paquetes = list(por_paquete(conf).values())
    assert len(paquetes) == 4          # ARP request, ARP reply, ICMP request, ICMP reply

    arp_req, arp_rep, icmp_req, icmp_rep = paquetes
    # ARP request: entra al switch por e1 y se inunda por e2 y e3 (dos ramas del mismo padre)
    raiz = arp_req[0]
    assert raiz.resumen['arp']['op'] == 1
    assert (raiz.enlace, raiz.emisor, raiz.profundidad) == ('e1', 'pc1', 0)
    ramas = sorted((o.enlace, o.nodo) for o in arp_req[1:])
    assert ramas == [('e2', 'pc2'), ('e3', 'pc3')]
    assert all(o.padre == raiz.id and o.profundidad == 1 for o in arp_req[1:])

    # ARP reply y el eco ICMP: unicast, solo por el camino correcto
    assert [(o.enlace, o.nodo) for o in arp_rep] == [('e2', 'sw'), ('e1', 'pc1')]
    assert [(o.enlace, o.nodo) for o in icmp_req] == [('e1', 'sw'), ('e2', 'pc2')]
    assert icmp_req[0].resumen['icmp']['tipo'] == 8
    assert icmp_req[1].padre == icmp_req[0].id
    assert [(o.enlace, o.nodo) for o in icmp_rep] == [('e2', 'sw'), ('e1', 'pc1')]
    assert not any(o.enlace == 'e3' for o in icmp_req + icmp_rep)


def test_sin_entrada_al_switch_queda_suelta():
    lab = lab_3pc()
    plan = planificar(lab)
    obs = [o for o in observaciones_de(D, plan) if o.intf != 'xs1-eth1']   # se "perdió" la entrada
    conf = correlacionar(lab, obs)
    sueltas = [o for o in conf if o.confianza == SIN_CORRELACIONAR]
    # el ARP inundado hacia pc2 y pc3 y el eco hacia pc2 no se inventan: quedan sueltos
    assert sorted((o.nodo, o.resumen['protocolo']) for o in sueltas) == [
        ('pc2', 'arp'), ('pc2', 'icmp'), ('pc3', 'arp')]
    assert all(o.padre is None for o in sueltas)
    assert len({o.paquete for o in sueltas}) == 3


def test_fuera_de_ventana_no_correlaciona():
    lab = lab_3pc()
    plan = planificar(lab)
    obs = observaciones_de(D, plan)
    for o in obs:
        if o.intf == 'xa3-eth0':
            o.ts_ns += 10_000_000_000
    conf = correlacionar(lab, obs)
    o3 = next(o for o in conf if o.intf == 'xa3-eth0')
    assert o3.confianza == SIN_CORRELACIONAR


def test_retardo_de_confirmacion():
    lab = lab_3pc()
    obs = sorted(observaciones_de(D, planificar(lab)), key=lambda o: o.ts_ns)
    c = Correlador(tipos(lab), retardo_ns=300_000_000)
    for o in obs:
        c.agregar(o)
    t0 = obs[0].ts_ns
    assert c.confirmar(t0 + 100_000_000) == []
    assert len(c.confirmar(t0 + 400_000_000)) == len(obs)


def lab_router():
    return Lab.model_validate({'version': 1, 'nodos': [
        {'id': 'h1', 'tipo': 'pc', 'nombre': 'pc1', 'interfaces': [{'puerto': 0, 'ip': '10.0.1.1/24'}],
         'gateway': '10.0.1.254'},
        {'id': 'r', 'tipo': 'router', 'nombre': 'r1', 'interfaces': [
            {'puerto': 0, 'ip': '10.0.1.254/24'}, {'puerto': 1, 'ip': '10.0.2.254/24'}]},
        {'id': 'h2', 'tipo': 'pc', 'nombre': 'pc2', 'interfaces': [{'puerto': 0, 'ip': '10.0.2.1/24'}],
         'gateway': '10.0.2.254'}],
        'enlaces': [{'id': 'e1', 'a': {'nodo': 'h1', 'puerto': 0}, 'b': {'nodo': 'r', 'puerto': 0}},
                    {'id': 'e2', 'a': {'nodo': 'r', 'puerto': 1}, 'b': {'nodo': 'h2', 'puerto': 0}}]})


def test_router_reenvio_con_ttl():
    lab = lab_router()
    d = leer_archivo(os.path.join(D, 'xa2-eth0.pcap'))[1].datos
    fwd = bytearray(d)
    fwd[0:12] = b'\xbb' * 12
    fwd[22] = 63
    entrada = Observacion(1, 1000, 'e1', 'b', 'r', 'h1', 'r1-eth0', d, len(d), 'x', 1, decodificar(d))
    salida = Observacion(2, 2000, 'e2', 'b', 'h2', 'r', 'pc2-eth0', bytes(fwd), len(fwd), 'y', 1,
                         decodificar(bytes(fwd)))
    c = Correlador(tipos(lab))
    c.agregar(salida)
    c.agregar(entrada)
    conf = c.confirmar_todo()
    assert conf[1].padre == 'o1' and conf[1].confianza == 'media'
    assert conf[1].paquete == conf[0].paquete
    # mismo TTL (no decrementado): no es un reenvío, el router lo origina
    salida2 = Observacion(3, 3000, 'e2', 'b', 'h2', 'r', 'pc2-eth0', d, len(d), 'y', 2, decodificar(d))
    c.agregar(salida2)
    o = c.confirmar_todo()[0]
    assert o.padre is None and o.confianza == ALTA and o.paquete != conf[0].paquete


# --- etapa 3: troncales, router-on-a-stick y NAT (tramas sintéticas) ---------

import tramas as T  # noqa: E402
from minired.captura.correlador import BAJA, MEDIA  # noqa: E402
from minired.modelo.topologia import TipoNodo  # noqa: E402

MS = 1_000_000


def _obs(seq, ms, enlace, nodo, emisor, datos):
    return Observacion(seq, ms * MS, enlace, 'b', nodo, emisor, '%s-x' % nodo, datos, len(datos),
                       'x.pcap', seq, decodificar(datos))


def test_troncal_y_router_on_a_stick():
    """v1 (VLAN 10) → sa → vr (troncal, etiqueta 10) → sa (etiqueta 20) → v3 (VLAN 20)."""
    tipos_ = {'v1': TipoNodo.pc, 'v3': TipoNodo.pc, 'sa': TipoNodo.switch, 'r': TipoNodo.router}
    mv1, mr, mv3 = '02:00:00:00:01:00', '02:00:00:00:09:00', '02:00:00:00:03:00'
    ida = T.ipv4('10.10.0.1', '10.20.0.1', 1, T.icmp_eco(), ttl=64)
    ruteado = T.ipv4('10.10.0.1', '10.20.0.1', 1, T.icmp_eco(), ttl=63)
    obs = [
        _obs(1, 0, 'e1', 'sa', 'v1', T.eth(mr, mv1, 0x0800, ida)),
        _obs(2, 1, 'e4', 'r', 'sa', T.eth(mr, mv1, 0x0800, ida, vlan=10)),
        _obs(3, 2, 'e4', 'sa', 'r', T.eth(mv3, mr, 0x0800, ruteado, vlan=20)),
        _obs(4, 3, 'e2', 'v3', 'sa', T.eth(mv3, mr, 0x0800, ruteado)),
    ]
    c = Correlador(tipos_)
    for o in reversed(obs):
        c.agregar(o)
    conf = c.confirmar_todo()
    assert len({o.paquete for o in conf}) == 1
    assert [(o.id, o.padre, o.confianza, o.profundidad) for o in conf] == [
        ('o1', None, ALTA, 0), ('o2', 'o1', ALTA, 1), ('o3', 'o2', MEDIA, 2), ('o4', 'o3', ALTA, 3)]


def test_switch_no_reenvia_por_el_puerto_de_entrada():
    tipos_ = {'a': TipoNodo.pc, 'sw': TipoNodo.switch}
    t = T.eth('ff:ff:ff:ff:ff:ff', '02:00:00:00:01:00', 0x0806, b'\0' * 28)
    c = Correlador(tipos_)
    c.agregar(_obs(1, 0, 'e1', 'sw', 'a', t))
    c.agregar(_obs(2, 1, 'e1', 'a', 'sw', t))
    assert [o.confianza for o in c.confirmar_todo()] == [ALTA, SIN_CORRELACIONAR]


def test_nat_se_correlaciona_con_confianza_baja():
    tipos_ = {'n1': TipoNodo.pc, 'r': TipoNodo.router, 'web': TipoNodo.servidor}
    ida = T.ipv4('10.40.0.1', '203.0.113.10', 1, T.icmp_eco(ident=7), ttl=64)
    traducido = T.ipv4('203.0.113.1', '203.0.113.10', 1, T.icmp_eco(ident=40001), ttl=63)
    otro = T.ipv4('203.0.113.1', '203.0.113.10', 1, T.icmp_eco(ident=40001, seq=9), ttl=63)
    c = Correlador(tipos_)
    for o in [_obs(1, 0, 'e3', 'r', 'n1', T.eth('02:00:00:00:09:00', '02:00:00:00:01:00', 0x0800, ida)),
              _obs(2, 1, 'e4', 'web', 'r', T.eth('02:00:00:00:0a:00', '02:00:00:00:09:01', 0x0800, traducido)),
              _obs(3, 2, 'e4', 'web', 'r', T.eth('02:00:00:00:0a:00', '02:00:00:00:09:01', 0x0800, otro))]:
        c.agregar(o)
    conf = c.confirmar_todo()
    assert [(o.padre, o.confianza) for o in conf] == [(None, ALTA), ('o1', BAJA), (None, ALTA)]
    assert decodificar(conf[1].datos)['ip']['src'] == '203.0.113.1'
