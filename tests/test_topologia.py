import pytest
from pydantic import ValidationError

from minired.modelo.a_mininet import planificar
from minired.modelo.topologia import Lab

from utiles import lab_3pc


def lab(nodos, enlaces=()):
    return Lab.model_validate({'version': 1, 'nodos': nodos, 'enlaces': list(enlaces)})


def pc(id_, nombre, ip=None, gw=None):
    d = {'id': id_, 'tipo': 'pc', 'nombre': nombre}
    if ip:
        d['interfaces'] = [{'puerto': 0, 'ip': ip}]
    if gw:
        d['gateway'] = gw
    return d


def sw(id_, nombre):
    return {'id': id_, 'tipo': 'switch', 'nombre': nombre}


def en(id_, a, pa, b, pb):
    return {'id': id_, 'a': {'nodo': a, 'puerto': pa}, 'b': {'nodo': b, 'puerto': pb}}


def test_lab_valido_y_plan():
    plan = planificar(lab_3pc(('pc1', 'pc2', 'pc3'), 's1'))
    assert plan.enlaces['e2'][0].intf == 'pc2-eth0'
    assert plan.enlaces['e2'][1].intf == 's1-eth2'
    assert plan.por_intf['s1-eth3'].enlace == 'e3'
    assert plan.extremo_opuesto('e1', 'b').intf == 'pc1-eth0'
    assert plan.dpids == {'sw': '0000000000000001'}
    assert plan.enlaces['e1'][0].ip == '10.0.0.1/24'


@pytest.mark.parametrize('nombre', ['pc1;reboot', 'PC1', '1pc', 'pc-1', 'nombremuylargo', '', 'pc 1',
                                    '$(id)'])
def test_nombres_invalidos(nombre):
    with pytest.raises(ValidationError):
        lab([pc('n1', nombre)])


@pytest.mark.parametrize('ip', ['10.0.0.1/24;id', '10.0.0.1', '10.0.0.0/24', '10.0.0.255/24',
                                '300.0.0.1/24', '127.0.0.1/8', 'fe80::1/64', '10.0.0.1/24 '])
def test_ip_invalidas(ip):
    with pytest.raises(ValidationError):
        lab([pc('n1', 'pc1', ip)])


def test_gateway():
    lab([pc('n1', 'pc1', '10.0.0.1/24', '10.0.0.254')])
    for gw in ['10.0.1.254', '10.0.0.1', '10.0.0.254; id']:
        with pytest.raises(ValidationError):
            lab([pc('n1', 'pc1', '10.0.0.1/24', gw)])
    with pytest.raises(ValidationError):
        lab([pc('n1', 'pc1', None, '10.0.0.254')])


def test_nombres_e_ids_repetidos():
    with pytest.raises(ValidationError, match='nombre repetido'):
        lab([pc('n1', 'pc1'), pc('n2', 'pc1')])
    with pytest.raises(ValidationError, match='id de nodo repetido'):
        lab([pc('n1', 'pc1'), pc('n1', 'pc2')])


def test_puertos():
    with pytest.raises(ValidationError, match='no tiene el puerto'):
        lab([pc('n1', 'pc1'), sw('s', 's1')], [en('e1', 'n1', 1, 's', 1)])
    with pytest.raises(ValidationError, match='no tiene el puerto'):
        lab([pc('n1', 'pc1'), sw('s', 's1')], [en('e1', 'n1', 0, 's', 0)])
    with pytest.raises(ValidationError, match='dos veces'):
        lab([pc('n1', 'pc1'), pc('n2', 'pc2'), sw('s', 's1')],
            [en('e1', 'n1', 0, 's', 1), en('e2', 'n2', 0, 's', 1)])
    with pytest.raises(ValidationError, match='inexistente'):
        lab([pc('n1', 'pc1')], [en('e1', 'n1', 0, 'zz', 1)])
    with pytest.raises(ValidationError, match='consigo mismo'):
        lab([sw('s', 's1')], [en('e1', 's', 1, 's', 2)])


def test_bucle_de_switches():
    sws = [sw('a', 'sa'), sw('b', 'sb'), sw('c', 'sc')]
    lab(sws, [en('e1', 'a', 1, 'b', 1), en('e2', 'b', 2, 'c', 1)])
    with pytest.raises(ValidationError, match='bucle'):
        lab(sws, [en('e1', 'a', 1, 'b', 1), en('e2', 'b', 2, 'c', 1), en('e3', 'c', 2, 'a', 2)])


def test_router_redes_superpuestas_y_switch_sin_ip():
    r = {'id': 'r', 'tipo': 'router', 'nombre': 'r1',
         'interfaces': [{'puerto': 0, 'ip': '10.0.0.1/24'}, {'puerto': 1, 'ip': '10.0.0.2/16'}]}
    with pytest.raises(ValidationError, match='superpuestas'):
        lab([r])
    s = {'id': 's', 'tipo': 'switch', 'nombre': 's1', 'interfaces': [{'puerto': 1, 'ip': '10.0.0.1/24'}]}
    with pytest.raises(ValidationError, match='switch'):
        lab([s])


def test_campos_extra_rechazados():
    with pytest.raises(ValidationError):
        Lab.model_validate({'version': 1, 'nodos': [dict(pc('n1', 'pc1'), cmd='id')]})
