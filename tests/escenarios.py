"""Laboratorios de la etapa 3 (VLAN, FRR/OSPF, DHCP/DNS/HTTP, NAT/ACL).

Los usan las pruebas del modelo (sin root) y las de integración en la VM.
Los nombres son cortos y propios para no chocar con otras redes de la VM.
"""

from minired.modelo.topologia import Lab


def _lab(nodos, enlaces):
    return Lab.model_validate({'version': 1, 'nodos': nodos, 'enlaces': enlaces})


def _en(id_, a, pa, b, pb):
    return {'id': id_, 'a': {'nodo': a, 'puerto': pa}, 'b': {'nodo': b, 'puerto': pb}}


def _pc(id_, nombre, ip=None, gw=None, **extra):
    d = {'id': id_, 'tipo': 'pc', 'nombre': nombre, **extra}
    if ip:
        d['interfaces'] = [{'puerto': 0, 'ip': ip}]
    if gw:
        d['gateway'] = gw
    return d


def lab_vlan():
    """Dos switches unidos por una troncal (VLAN 10 y 20) y un router-on-a-stick.

    v1 (VLAN 10) y v2 (VLAN 10, en el otro switch) se ven por la troncal.
    v3 (VLAN 20) llega a v1 solo a través del router (inter-VLAN).
    v4 está en la VLAN 20 con una IP de la red de la VLAN 10: no debe llegar a v1 (aislamiento).
    """
    nodos = [
        {'id': 'sa', 'tipo': 'switch', 'nombre': 'vsa', 'interfaces': [
            {'puerto': 1, 'vlan': 10}, {'puerto': 2, 'vlan': 20},
            {'puerto': 3, 'troncal': [10, 20]}, {'puerto': 4, 'troncal': [10, 20]}]},
        {'id': 'sb', 'tipo': 'switch', 'nombre': 'vsb', 'interfaces': [
            {'puerto': 1, 'vlan': 10}, {'puerto': 2, 'vlan': 20},
            {'puerto': 3, 'troncal': [10, 20]}]},
        {'id': 'r', 'tipo': 'router', 'nombre': 'vr', 'interfaces': [
            {'puerto': 0, 'subinterfaces': [{'vlan': 10, 'ip': '10.10.0.254/24'},
                                            {'vlan': 20, 'ip': '10.20.0.254/24'}]}]},
        _pc('v1', 'v1', '10.10.0.1/24', '10.10.0.254'),
        _pc('v2', 'v2', '10.10.0.2/24', '10.10.0.254'),
        _pc('v3', 'v3', '10.20.0.1/24', '10.20.0.254'),
        _pc('v4', 'v4', '10.10.0.4/24'),
    ]
    enlaces = [
        _en('e1', 'v1', 0, 'sa', 1), _en('e2', 'v3', 0, 'sa', 2),
        _en('e3', 'sa', 3, 'sb', 3), _en('e4', 'r', 0, 'sa', 4),
        _en('e5', 'v2', 0, 'sb', 1), _en('e6', 'v4', 0, 'sb', 2),
    ]
    return _lab(nodos, enlaces)


def lab_ospf():
    """f1 — fr1 — fr2 — f2 con FRR y OSPF: las rutas remotas se aprenden, no se cargan a mano."""
    nodos = [
        _pc('f1', 'f1', '10.61.0.1/24', '10.61.0.254'),
        {'id': 'r1', 'tipo': 'router', 'nombre': 'fr1', 'frr': True, 'ospf': True, 'interfaces': [
            {'puerto': 0, 'ip': '10.61.0.254/24'}, {'puerto': 1, 'ip': '10.60.0.1/30'}]},
        {'id': 'r2', 'tipo': 'router', 'nombre': 'fr2', 'frr': True, 'ospf': True, 'interfaces': [
            {'puerto': 0, 'ip': '10.62.0.254/24'}, {'puerto': 1, 'ip': '10.60.0.2/30'}]},
        _pc('f2', 'f2', '10.62.0.1/24', '10.62.0.254'),
    ]
    enlaces = [_en('e1', 'f1', 0, 'r1', 0), _en('e2', 'r1', 1, 'r2', 1), _en('e3', 'r2', 0, 'f2', 0)]
    return _lab(nodos, enlaces)


def lab_servicios():
    """Dos LAN separadas, cada una con su servidor DHCP: cada PC recibe una IP de su propio rango.

    El servidor da1 además resuelve web.lab y sirve HTTP.
    """
    nodos = [
        {'id': 'sa', 'tipo': 'switch', 'nombre': 'dsa'},
        {'id': 'sb', 'tipo': 'switch', 'nombre': 'dsb'},
        {'id': 'srva', 'tipo': 'servidor', 'nombre': 'da1', 'dns': '10.30.0.1',
         'interfaces': [{'puerto': 0, 'ip': '10.30.0.1/24'}],
         'servicios': {'dhcp': {'desde': '10.30.0.100', 'hasta': '10.30.0.150',
                                'gateway': '10.30.0.254', 'dns': '10.30.0.1'},
                       'dns': [{'nombre': 'web.lab', 'ip': '10.30.0.1'}], 'http': True}},
        {'id': 'srvb', 'tipo': 'servidor', 'nombre': 'db1',
         'interfaces': [{'puerto': 0, 'ip': '10.31.0.1/24'}],
         'servicios': {'dhcp': {'desde': '10.31.0.200', 'hasta': '10.31.0.210'}}},
        _pc('ca', 'dc1', dhcp=True),
        _pc('ca2', 'dc2', dhcp=True),
        _pc('cb', 'dc3', dhcp=True),
    ]
    enlaces = [_en('e1', 'srva', 0, 'sa', 1), _en('e2', 'ca', 0, 'sa', 2), _en('e3', 'ca2', 0, 'sa', 3),
               _en('e4', 'srvb', 0, 'sb', 1), _en('e5', 'cb', 0, 'sb', 2)]
    return _lab(nodos, enlaces)


def lab_nat_acl():
    """Red interior 10.40.0.0/24 detrás de un router con NAT (masquerade) hacia 203.0.113.0/24.

    El servidor exterior no tiene ruta de vuelta a 10.40.0.0/24: solo responde gracias al NAT.
    ACL de entrada en la interfaz interior: n2 no puede hacer ping, pero sí usar HTTP.
    """
    nodos = [
        _pc('n1', 'n1', '10.40.0.1/24', '10.40.0.254'),
        _pc('n2', 'n2', '10.40.0.2/24', '10.40.0.254'),
        {'id': 'sw', 'tipo': 'switch', 'nombre': 'ns'},
        {'id': 'r', 'tipo': 'router', 'nombre': 'nr',
         'rutas': [{'destino': '198.51.100.0/24', 'via': '203.0.113.10'}],
         'interfaces': [
             {'puerto': 0, 'ip': '10.40.0.254/24', 'nat': 'interior', 'acl_entrada': [
                 {'accion': 'denegar', 'protocolo': 'icmp', 'origen': '10.40.0.2/32'},
                 {'accion': 'permitir', 'protocolo': 'ip'}]},
             {'puerto': 1, 'ip': '203.0.113.1/24', 'nat': 'exterior'}]},
        {'id': 'web', 'tipo': 'servidor', 'nombre': 'nsrv',
         'interfaces': [{'puerto': 0, 'ip': '203.0.113.10/24'}], 'servicios': {'http': True}},
    ]
    enlaces = [_en('e1', 'n1', 0, 'sw', 1), _en('e2', 'n2', 0, 'sw', 2), _en('e3', 'r', 0, 'sw', 3),
               _en('e4', 'r', 1, 'web', 0)]
    return _lab(nodos, enlaces)
